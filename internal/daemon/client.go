package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// DefaultSocketPath returns the conventional socket path for a project
// rooted at root (.krit/daemon.sock under the project root).
func DefaultSocketPath(root string) string {
	return filepath.Join(root, ".krit", "daemon.sock")
}

// Available reports whether a daemon appears reachable at socketPath. It
// performs a short-timeout dial; absence is not an error from the caller's
// perspective, just "fall back to in-process".
func Available(socketPath string) bool {
	if socketPath == "" {
		return false
	}
	if _, err := os.Stat(socketPath); err != nil {
		return false
	}
	conn, err := (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Call sends a single Request to the daemon at socketPath and decodes the
// Data field of the Response into out (which may be nil). It returns the
// daemon's error string as a Go error when OK=false.
func Call(socketPath, verb string, args any, out any) error {
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return fmt.Errorf("daemon: dial %s: %w", socketPath, err)
	}
	defer conn.Close()

	var raw json.RawMessage
	if args != nil {
		buf, err := json.Marshal(args)
		if err != nil {
			return fmt.Errorf("daemon: marshal args: %w", err)
		}
		raw = buf
	}
	req := Request{Verb: verb, Args: raw}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("daemon: marshal request: %w", err)
	}
	body = append(body, '\n')
	if _, err := conn.Write(body); err != nil {
		return fmt.Errorf("daemon: write: %w", err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("daemon: read: %w", err)
	}
	// Fast path for analyze-project's giant 30 MB envelope: a hand-
	// rolled byte scanner extracts Findings (json.RawMessage) and
	// Stats (small struct) without paying the ~150 ms two-pass
	// json.Unmarshal that the generic path costs on warm baselines.
	// Falls back transparently to json.Unmarshal when the envelope
	// shape doesn't match (different field order, whitespace, etc.).
	if apr, ok := out.(*AnalyzeProjectResult); ok {
		handled, daemonErr := ScanAnalyzeProjectResponse(line, apr)
		if handled {
			return daemonErr
		}
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return fmt.Errorf("daemon: decode response: %w", err)
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	if out == nil {
		return nil
	}
	if len(resp.Data) == 0 {
		return nil
	}
	return json.Unmarshal(resp.Data, out)
}
