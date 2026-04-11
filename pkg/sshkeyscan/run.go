package sshkeyscan

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Run executes the ssh-keyscan action based on cfg and returns a process
// exit code.
func Run(cfg *Config) int {
	if cfg.Version {
		fmt.Printf("ssh-keyscan (sshconf) %s\n", version.Version)
		return 0
	}

	if len(cfg.Hosts) == 0 && cfg.HostFile == "" {
		fmt.Fprintf(os.Stderr, "usage: ssh-keyscan [-46cDHv] [-f file] [-O option] [-p port] [-T timeout] [-t type] [host | addrlist namelist]\n")
		return 1
	}

	keyTypes := cfg.KeyTypes
	if len(keyTypes) == 0 {
		keyTypes = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}
	}

	if cfg.HostFile != "" {
		var r *os.File
		if cfg.HostFile == "-" {
			r = os.Stdin
		} else {
			var err error
			r, err = os.Open(cfg.HostFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh-keyscan: %v\n", err)
				return 1
			}
			defer r.Close()
		}
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				cfg.Hosts = append(cfg.Hosts, line)
			}
		}
	}

	if len(cfg.Hosts) == 0 {
		return 0
	}

	timeout := time.Duration(cfg.Timeout) * time.Second

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, host := range cfg.Hosts {
		for _, keyType := range keyTypes {
			wg.Add(1)
			go func(host, keyType string) {
				defer wg.Done()
				key, err := ScanHostKey(host, cfg.Port, keyType, timeout)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if cfg.Verbose {
						fmt.Fprintf(os.Stderr, "# %s:%d %s: %v\n", host, cfg.Port, keyType, err)
					}
					return
				}
				if cfg.HashHosts {
					fmt.Printf("%s %s\n", knownhosts.HashHostname(host), key)
				} else {
					if cfg.Port != 22 {
						fmt.Printf("[%s]:%d %s\n", host, cfg.Port, key)
					} else {
						fmt.Printf("%s %s\n", host, key)
					}
				}
			}(host, keyType)
		}
	}

	wg.Wait()

	return 0
}
