package sshclient

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveHostNameDoesNotBreakSubsequentDirectives reproduces a downstream
// bug where setting HostName to an IP literal (or any value that does not
// match the enclosing Host pattern) inside a Host block silently dropped
// every directive that appeared after HostName. The pattern check for the
// remaining directives was being re-evaluated against the rewritten host,
// which by definition no longer matched the alias on the Host line.
func TestResolveHostNameDoesNotBreakSubsequentDirectives(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "ssh_config")
	keyPath := filepath.Join(dir, "id_test")
	cfg := "Host machineproxy-e2e\n" +
		"    HostName ::1\n" +
		"    Port 2222\n" +
		"    User someuser\n" +
		"    IdentityFile " + keyPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	missingSystemPath := filepath.Join(dir, "no-such-system-config")
	lookup := &Lookup{
		Host:             "machineproxy-e2e",
		UserConfigFile:   cfgPath,
		SystemConfigFile: missingSystemPath,
	}
	opts, err := lookup.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if opts.Hostname == nil || *opts.Hostname != "::1" {
		t.Errorf("Hostname: got %v, want \"::1\"", deref(opts.Hostname))
	}
	if opts.Port == nil || *opts.Port != 2222 {
		t.Errorf("Port: got %v, want 2222", derefInt(opts.Port))
	}
	if opts.User == nil || *opts.User != "someuser" {
		t.Errorf("User: got %v, want \"someuser\"", deref(opts.User))
	}
	if len(opts.IdentityFile) == 0 {
		t.Errorf("IdentityFile: got empty, want %q", keyPath)
	} else {
		found := false
		for _, f := range opts.IdentityFile {
			if f == keyPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("IdentityFile: got %v, want to contain %q", opts.IdentityFile, keyPath)
		}
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func derefInt(i *int) int {
	if i == nil {
		return -1
	}
	return *i
}
