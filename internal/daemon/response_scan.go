package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AnalyzeProjectResponseScanner extracts the Findings (json.RawMessage)
// and Stats (small struct) from a daemon analyze-project response
// envelope without routing the whole 30 MB payload through
// json.Unmarshal. The Unmarshal path scans every byte twice (outer
// {ok,error,data} envelope, then inner {findings,stats}) and on a
// kotlin-corpus warm baseline that's ~150 ms of CPU pure overhead —
// the bytes are already valid JSON, we just need to find where the
// findings array ends and where the stats object begins.
//
// The scanner uses balanced-bracket walking with proper string-escape
// handling, so it's correct for arbitrary findings content (paths
// with quotes, messages with brackets, etc.). On any structural
// surprise it returns an error and the caller falls back to
// json.Unmarshal — never trading correctness for speed.
//
// Wire shape this targets exactly:
//
//	{"ok":true,"data":{"findings":[...],"stats":{...}}}
//
// or error form:
//
//	{"ok":false,"error":"..."}
//
// Anything else (different field order, extra fields, whitespace)
// goes through the json.Unmarshal fallback. The daemon writes the
// fast shape verbatim today; future protocol additions can stay
// fast by extending this scanner or accept the Unmarshal fallback.

// ScanAnalyzeProjectResponse parses line (a single daemon response
// without trailing newline) into out without a full json.Unmarshal.
// Returns ok=true when the fast path succeeded; ok=false (with a
// nil error) means the input didn't match the expected shape and
// the caller should fall back to json.Unmarshal. A non-nil error is
// a daemon-side failure surfaced from the response's "error" field.
func ScanAnalyzeProjectResponse(line []byte, out *AnalyzeProjectResult) (handled bool, daemonErr error) {
	if out == nil {
		return false, nil
	}

	// Strip trailing newline if present; the wire is newline-terminated
	// but ReadBytes('\n') keeps the delimiter. Be defensive in case the
	// caller already trimmed it.
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}

	// Success envelope: {"ok":true,"data":{"findings":...,"stats":...}}
	const okPrefix = `{"ok":true,"data":{"findings":`
	if hasPrefix(line, okPrefix) {
		findingsStart := len(okPrefix)
		findingsEnd, err := jsonValueEnd(line, findingsStart)
		if err != nil {
			return false, nil //nolint:nilerr // intentional fallback: caller retries with json.Unmarshal
		}
		// After findings comes ,"stats":<obj>}}
		const statsKey = `,"stats":`
		if !hasPrefixAt(line, findingsEnd, statsKey) {
			return false, nil
		}
		statsStart := findingsEnd + len(statsKey)
		statsEnd, err := jsonValueEnd(line, statsStart)
		if err != nil {
			return false, nil //nolint:nilerr // intentional fallback
		}
		// Must end with `}}` (closes data + closes envelope).
		if statsEnd+2 != len(line) || line[statsEnd] != '}' || line[statsEnd+1] != '}' {
			return false, nil
		}
		out.Findings = append(out.Findings[:0], line[findingsStart:findingsEnd]...)
		if err := json.Unmarshal(line[statsStart:statsEnd], &out.Stats); err != nil {
			return false, fmt.Errorf("scan response stats: %w", err)
		}
		return true, nil
	}

	// Error envelope: {"ok":false,"error":"..."}
	const errPrefix = `{"ok":false,"error":`
	if hasPrefix(line, errPrefix) {
		msgStart := len(errPrefix)
		msgEnd, err := jsonValueEnd(line, msgStart)
		if err != nil {
			return false, nil //nolint:nilerr // intentional fallback
		}
		if msgEnd+1 != len(line) || line[msgEnd] != '}' {
			return false, nil
		}
		var msg string
		if err := json.Unmarshal(line[msgStart:msgEnd], &msg); err != nil {
			return false, nil //nolint:nilerr // intentional fallback
		}
		return true, errors.New(msg)
	}

	// Unknown shape — caller falls back to json.Unmarshal.
	return false, nil
}

// jsonValueEnd returns the byte index immediately after the JSON
// value that begins at start. Handles objects, arrays, strings,
// numbers, booleans, and null. Errors when the value is malformed
// or runs past the end of the buffer.
//
// The scanner assumes compact JSON (no inter-token whitespace),
// matching how the daemon writes the envelope. Whitespace handling
// would just add no-op branches; the fallback path covers that case.
func jsonValueEnd(data []byte, start int) (int, error) {
	if start >= len(data) {
		return -1, errors.New("scan: empty value")
	}
	b := data[start]
	switch b {
	case '{':
		return scanBalanced(data, start, '{', '}')
	case '[':
		return scanBalanced(data, start, '[', ']')
	case '"':
		return scanString(data, start+1)
	case 't', 'f', 'n':
		return scanLiteral(data, start)
	}
	if b == '-' || (b >= '0' && b <= '9') {
		return scanNumber(data, start), nil
	}
	return -1, fmt.Errorf("scan: unexpected token %q at %d", b, start)
}

// scanLiteral matches the JSON literal `true`, `false`, or `null` and
// returns the byte index immediately after it. Called from
// jsonValueEnd's t/f/n switch arms.
func scanLiteral(data []byte, start int) (int, error) {
	switch data[start] {
	case 't':
		if start+4 <= len(data) && data[start+1] == 'r' && data[start+2] == 'u' && data[start+3] == 'e' {
			return start + 4, nil
		}
	case 'f':
		if start+5 <= len(data) && data[start+1] == 'a' && data[start+2] == 'l' && data[start+3] == 's' && data[start+4] == 'e' {
			return start + 5, nil
		}
	case 'n':
		if start+4 <= len(data) && data[start+1] == 'u' && data[start+2] == 'l' && data[start+3] == 'l' {
			return start + 4, nil
		}
	}
	return -1, fmt.Errorf("scan: bad literal at %d", start)
}

func scanBalanced(data []byte, start int, openByte, closeByte byte) (int, error) {
	depth := 0
	inString := false
	for i := start; i < len(data); i++ {
		b := data[i]
		if inString {
			if b == '\\' {
				// Skip the next byte (the escape's payload). Even for
				// \uXXXX the next byte alone keeps us out of a stray
				// quote — the remaining hex digits never include a
				// raw '"' or '\\'.
				i++
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case openByte:
			depth++
		case closeByte:
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
	}
	return -1, errors.New("scan: unbalanced brace")
}

func scanString(data []byte, start int) (int, error) {
	for i := start; i < len(data); i++ {
		b := data[i]
		if b == '\\' {
			i++
			continue
		}
		if b == '"' {
			return i + 1, nil
		}
	}
	return -1, errors.New("scan: unterminated string")
}

func scanNumber(data []byte, start int) int {
	i := start
	if i < len(data) && data[i] == '-' {
		i++
	}
	for i < len(data) {
		b := data[i]
		if (b >= '0' && b <= '9') || b == '.' || b == 'e' || b == 'E' || b == '+' || b == '-' {
			i++
			continue
		}
		break
	}
	return i
}

func hasPrefix(data []byte, prefix string) bool {
	if len(data) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[i] != prefix[i] {
			return false
		}
	}
	return true
}

func hasPrefixAt(data []byte, off int, prefix string) bool {
	if off+len(prefix) > len(data) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if data[off+i] != prefix[i] {
			return false
		}
	}
	return true
}
