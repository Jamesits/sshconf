package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jamesits/sshconf/pkg/logger"
	"github.com/jamesits/sshconf/pkg/sshserver"
	"github.com/jamesits/sshconf/pkg/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	args := &sshserver.CLIArgs{}
	if err := args.Parse(os.Args[1:]...); err != nil {
		fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
		return 255
	}

	if args.Version {
		fmt.Printf("sshd (sshconf) %s\n", version.Version)
		return 0
	}

	cliDirectives, err := args.Directives()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
		return 255
	}

	lookup := &sshserver.Lookup{
		ConfigFile:            args.ConfigFile,
		CommandLineDirectives: cliDirectives,
		Version:               "sshconf_" + version.Version,
	}

	opts, err := lookup.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
		return 255
	}

	// -G / -T : print resolved config and exit.
	if args.PrintConfig || args.TestMode {
		printConfig(opts)
		return 0
	}

	// -t : validate config (and, for a real sshd, host keys) and exit.
	if args.Validate {
		// The Resolve call above already validated the config file;
		// try loading host keys to ensure they are parseable.
		if _, err := opts.SSHServerConfig(sshserver.Handlers{}); err != nil {
			fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
			return 255
		}
		return 0
	}

	// Logger.
	lgr := logger.New(args.LogFile, args.DebugLevel, args.Quiet)
	if opts.LogLevel != nil {
		lgr.SetLevel(*opts.LogLevel)
	}

	// Register built-in subsystems. An application that wants to expose
	// a custom in-process subsystem can register it here before Serve.
	// (No internal subsystems are registered by the default sshd binary.)

	// Handlers — the default sshd wires up reasonable defaults for a
	// drop-in replacement.
	handlers := sshserver.Handlers{
		Logger:           lgr,
		PasswordAuth:     sshserver.DenyPasswordAuthenticator{},
		PublicKeyAuth:    &sshserver.AuthorizedKeysAuthenticator{},
		AccessController: sshserver.SimpleAccessController{},
		SessionHandler:   &sshserver.DefaultSessionHandler{ProcessLauncher: &sshserver.ExecProcessLauncher{}},
		TcpForwarder:     &sshserver.DefaultTcpForwarder{},
	}

	// Inetd mode: serve a single connection from stdin/stdout.
	if args.Inetd {
		return serveInetd(opts, handlers)
	}

	// Listen on configured addresses.
	listeners, err := opts.Listen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
		return 255
	}

	lgr.Log("INFO", fmt.Sprintf("sshd %s listening on %d address(es)", version.Version, len(listeners)))

	// Install signal handling for clean shutdown (SIGINT / SIGTERM).
	shutdownCh := make(chan struct{})
	var once sync.Once
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		lgr.Log("INFO", "shutting down")
		once.Do(func() { close(shutdownCh) })
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	// Serve each listener in its own goroutine.
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(listener net.Listener) {
			defer wg.Done()
			err := sshserver.Serve(listener, opts, handlers)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				lgr.Log("ERROR", fmt.Sprintf("serve error: %v", err))
			}
		}(l)
	}
	wg.Wait()

	return 0
}

// serveInetd handles the -i (inetd) mode: treat stdin/stdout as a single
// already-connected client and service it to completion. The stdio pair
// is wrapped as a net.Conn and handed to the server's accept path via
// sshserver.ServeConn.
func serveInetd(opts *sshserver.Options, handlers sshserver.Handlers) int {
	if err := sshserver.ServeConn(newStdioConn(), opts, handlers); err != nil {
		fmt.Fprintf(os.Stderr, "sshd: %v\n", err)
		return 255
	}
	return 0
}

// newStdioConn wraps os.Stdin/os.Stdout as a net.Conn for inetd mode.
func newStdioConn() net.Conn {
	return &stdioConn{
		reader: os.Stdin,
		writer: os.Stdout,
	}
}

// stdioConn is a minimal net.Conn wrapping a reader/writer pair.
type stdioConn struct {
	reader *os.File
	writer *os.File
}

func (c *stdioConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *stdioConn) Write(b []byte) (int, error) { return c.writer.Write(b) }
func (c *stdioConn) Close() error {
	_ = c.reader.Close()
	_ = c.writer.Close()
	return nil
}
func (c *stdioConn) LocalAddr() net.Addr                { return &stdioAddr{name: "local"} }
func (c *stdioConn) RemoteAddr() net.Addr               { return &stdioAddr{name: "remote"} }
func (c *stdioConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(_ time.Time) error { return nil }

type stdioAddr struct{ name string }

func (a *stdioAddr) Network() string { return "stdio" }
func (a *stdioAddr) String() string  { return a.name }

// printConfig writes the resolved options to stdout in a readable form.
// The format mimics `sshd -T` output loosely — it is not a round-trip
// representation of sshd_config.
func printConfig(opts *sshserver.Options) {
	fmt.Printf("addressfamily %s\n", strOrDefault(opts.AddressFamily, "any"))
	for _, p := range opts.Ports {
		fmt.Printf("port %d\n", p)
	}
	for _, a := range opts.ListenAddress {
		fmt.Printf("listenaddress %s\n", a)
	}
	for _, hk := range opts.HostKey {
		fmt.Printf("hostkey %s\n", hk)
	}
	fmt.Printf("loggracetime %d\n", intOrDefault(opts.LoginGraceTime, 120))
	fmt.Printf("permitrootlogin %s\n", strOrDefault(opts.PermitRootLogin, "prohibit-password"))
	fmt.Printf("passwordauthentication %s\n", boolOrDefault(opts.PasswordAuthentication, true))
	fmt.Printf("pubkeyauthentication %s\n", boolOrDefault(opts.PubkeyAuthentication, true))
	fmt.Printf("kbdinteractiveauthentication %s\n", boolOrDefault(opts.KbdInteractiveAuthentication, true))
	fmt.Printf("usepam %s\n", boolOrDefault(opts.UsePAM, false))
	fmt.Printf("maxauthtries %d\n", intOrDefault(opts.MaxAuthTries, 6))
	fmt.Printf("maxsessions %d\n", intOrDefault(opts.MaxSessions, 10))
	fmt.Printf("x11forwarding %s\n", boolOrDefault(opts.X11Forwarding, false))
	fmt.Printf("allowtcpforwarding %s\n", strOrDefault(opts.AllowTcpForwarding, "yes"))
	fmt.Printf("allowagentforwarding %s\n", boolOrDefault(opts.AllowAgentForwarding, true))
	fmt.Printf("compression %s\n", strOrDefault(opts.Compression, "yes"))
	fmt.Printf("loglevel %s\n", strOrDefault(opts.LogLevel, "INFO"))
	fmt.Printf("ciphers %s\n", strOrDefault(opts.Ciphers, "default"))
	fmt.Printf("kexalgorithms %s\n", strOrDefault(opts.KexAlgorithms, "default"))
	fmt.Printf("macs %s\n", strOrDefault(opts.MACs, "default"))
	for name, sub := range opts.Subsystems {
		if sub.Internal {
			fmt.Printf("subsystem %s (internal)\n", name)
		} else {
			fmt.Printf("subsystem %s %s\n", name, sub.Command)
		}
	}
}

func strOrDefault(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func intOrDefault(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

func boolOrDefault(p *bool, def bool) string {
	v := def
	if p != nil {
		v = *p
	}
	if v {
		return "yes"
	}
	return "no"
}
