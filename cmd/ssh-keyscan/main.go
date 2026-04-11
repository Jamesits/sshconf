package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jamesits/sshconf/pkg/version"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := parseArgs(os.Args[1:])

	if args.version {
		fmt.Printf("ssh-keyscan (sshconf) %s\n", version.Version)
		return 0
	}

	if len(args.hosts) == 0 && args.hostFile == "" {
		fmt.Fprintf(os.Stderr, "usage: ssh-keyscan [-46cDHv] [-f file] [-O option] [-p port] [-T timeout] [-t type] [host | addrlist namelist]\n")
		return 1
	}

	// Determine key types to scan for
	keyTypes := args.keyTypes
	if len(keyTypes) == 0 {
		keyTypes = []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"}
	}

	// Collect hosts from -f file
	if args.hostFile != "" {
		var r *os.File
		if args.hostFile == "-" {
			r = os.Stdin
		} else {
			var err error
			r, err = os.Open(args.hostFile)
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
				args.hosts = append(args.hosts, line)
			}
		}
	}

	if len(args.hosts) == 0 {
		return 0
	}

	timeout := time.Duration(args.timeout) * time.Second

	var mu sync.Mutex
	var wg sync.WaitGroup
	hasError := false

	for _, host := range args.hosts {
		for _, keyType := range keyTypes {
			wg.Add(1)
			go func(host, keyType string) {
				defer wg.Done()
				key, err := scanHostKey(host, args.port, keyType, timeout)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if args.verbose {
						fmt.Fprintf(os.Stderr, "# %s:%d %s: %v\n", host, args.port, keyType, err)
					}
					hasError = true
					return
				}
				if args.hashHosts {
					fmt.Printf("%s %s\n", knownhosts.HashHostname(host), key)
				} else {
					if args.port != 22 {
						fmt.Printf("[%s]:%d %s\n", host, args.port, key)
					} else {
						fmt.Printf("%s %s\n", host, key)
					}
				}
			}(host, keyType)
		}
	}

	wg.Wait()

	if hasError && len(args.hosts) == 1 && !args.verbose {
		// Partial failure is common (e.g., host doesn't support all key types)
	}

	return 0
}

type scanArgs struct {
	hosts     []string
	hostFile  string
	port      int
	timeout   int
	keyTypes  []string
	hashHosts bool
	verbose   bool
	version   bool
}

func parseArgs(args []string) *scanArgs {
	a := &scanArgs{
		port:    22,
		timeout: 5,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f":
			i++
			if i < len(args) {
				a.hostFile = args[i]
			}
		case "-p":
			i++
			if i < len(args) {
				a.port, _ = strconv.Atoi(args[i])
			}
		case "-T":
			i++
			if i < len(args) {
				a.timeout, _ = strconv.Atoi(args[i])
			}
		case "-t":
			i++
			if i < len(args) {
				a.keyTypes = parseKeyTypes(args[i])
			}
		case "-H":
			a.hashHosts = true
		case "-v":
			a.verbose = true
		case "-4":
			// IPv4 only — hint for dialer (not enforced in this implementation)
		case "-6":
			// IPv6 only — hint for dialer (not enforced in this implementation)
		case "-V":
			a.version = true
		default:
			if !strings.HasPrefix(args[i], "-") {
				a.hosts = append(a.hosts, args[i])
			}
		}
	}

	return a
}

// parseKeyTypes translates user-friendly type names to SSH algorithm names.
func parseKeyTypes(spec string) []string {
	var result []string
	for _, t := range strings.Split(spec, ",") {
		t = strings.TrimSpace(t)
		switch strings.ToLower(t) {
		case "rsa":
			result = append(result, "ssh-rsa")
		case "ecdsa":
			result = append(result, "ecdsa-sha2-nistp256")
		case "ed25519":
			result = append(result, "ssh-ed25519")
		default:
			// Accept raw algorithm names
			result = append(result, t)
		}
	}
	return result
}

// scanHostKey connects to host:port and retrieves the host key of the specified type.
// Returns the key in known_hosts format "type base64-key".
func scanHostKey(host string, port int, keyType string, timeout time.Duration) (string, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{keyType},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil
		},
		Timeout: timeout,
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	// Set a deadline on the connection for the SSH handshake
	conn.SetDeadline(time.Now().Add(timeout))

	// We expect the handshake to fail with auth error — we only need the host key.
	sshConn, _, _, err := ssh.NewClientConn(conn, addr, config)
	if sshConn != nil {
		sshConn.Close()
	}

	if hostKey != nil {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))), nil
	}

	if err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	return "", fmt.Errorf("no host key received")
}
