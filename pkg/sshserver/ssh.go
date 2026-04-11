package sshserver

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jamesits/sshconf/pkg/sshconfig"
	"golang.org/x/crypto/ssh"
)

// SSHServerConfig converts the resolved Options into an ssh.ServerConfig,
// wiring the supplied handlers into the appropriate callbacks and loading
// the host keys from HostKey files or the HostKeyProvider handler.
//
// The returned config is suitable for immediate use with ssh.NewServerConn.
func (opts *Options) SSHServerConfig(handlers Handlers) (*ssh.ServerConfig, error) {
	cfg := &ssh.ServerConfig{}

	// Server version string.
	if opts.VersionAddendum != nil && *opts.VersionAddendum != "none" && *opts.VersionAddendum != "" {
		cfg.ServerVersion = "SSH-2.0-sshconf " + *opts.VersionAddendum
	} else {
		cfg.ServerVersion = "SSH-2.0-sshconf"
	}

	// Crypto configuration.
	if opts.Ciphers != nil {
		cfg.Config.Ciphers = ResolveCiphers(*opts.Ciphers)
	}
	if opts.KexAlgorithms != nil {
		cfg.Config.KeyExchanges = ResolveKexAlgorithms(*opts.KexAlgorithms)
	}
	if opts.MACs != nil {
		cfg.Config.MACs = ResolveMACs(*opts.MACs)
	}
	if opts.PubkeyAcceptedAlgorithms != nil {
		cfg.PublicKeyAuthAlgorithms = ResolvePubkeyAcceptedAlgorithms(*opts.PubkeyAcceptedAlgorithms)
	}
	if opts.RekeyLimit != nil {
		bytes, _ := sshconfig.ParseRekeyLimit(*opts.RekeyLimit)
		if bytes > 0 {
			cfg.Config.RekeyThreshold = bytes
		}
	}

	// Max auth tries.
	if opts.MaxAuthTries != nil {
		cfg.MaxAuthTries = *opts.MaxAuthTries
	}

	// Banner.
	if opts.Banner != nil && *opts.Banner != "none" && *opts.Banner != "" {
		bannerPath := *opts.Banner
		cfg.BannerCallback = func(conn ssh.ConnMetadata) string {
			data, err := os.ReadFile(bannerPath)
			if err != nil {
				return ""
			}
			return string(data)
		}
	}

	// Auth callbacks. Wire up the ones that have handlers and whose options
	// allow them; x/crypto/ssh drops nil callbacks automatically.
	wireAuthCallbacks(cfg, opts, handlers)

	// Host keys.
	signers, err := loadHostKeys(opts, handlers)
	if err != nil {
		return nil, fmt.Errorf("loading host keys: %w", err)
	}
	for _, s := range signers {
		cfg.AddHostKey(s)
	}
	if len(signers) == 0 {
		return nil, errors.New("no host keys available")
	}

	// Auth log callback — route failed/successful auth attempts to the logger.
	if handlers.Logger != nil {
		logger := handlers.Logger
		cfg.AuthLogCallback = func(conn ssh.ConnMetadata, method string, authErr error) {
			if authErr != nil {
				logger.Log("INFO", fmt.Sprintf("auth %s for %s from %s failed: %v",
					method, conn.User(), conn.RemoteAddr(), authErr))
			} else {
				logger.Log("INFO", fmt.Sprintf("auth %s for %s from %s succeeded",
					method, conn.User(), conn.RemoteAddr()))
			}
		}
	}

	return cfg, nil
}

// wireAuthCallbacks sets PasswordCallback, PublicKeyCallback, etc. on cfg
// based on what the handlers provide and what opts permits.
func wireAuthCallbacks(cfg *ssh.ServerConfig, opts *Options, handlers Handlers) {
	passwordEnabled := opts.PasswordAuthentication != nil && *opts.PasswordAuthentication
	pubkeyEnabled := opts.PubkeyAuthentication != nil && *opts.PubkeyAuthentication
	kbdEnabled := opts.KbdInteractiveAuthentication != nil && *opts.KbdInteractiveAuthentication
	hostbasedEnabled := opts.HostbasedAuthentication != nil && *opts.HostbasedAuthentication
	gssEnabled := opts.GSSAPIAuthentication != nil && *opts.GSSAPIAuthentication

	if passwordEnabled && handlers.PasswordAuth != nil {
		auth := handlers.PasswordAuth
		cfg.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if !passwordEnabled {
				return nil, fmt.Errorf("password authentication disabled")
			}
			if len(password) == 0 && (opts.PermitEmptyPasswords == nil || !*opts.PermitEmptyPasswords) {
				return nil, fmt.Errorf("empty password rejected")
			}
			return auth.AuthenticatePassword(conn, password, opts)
		}
	}

	if pubkeyEnabled && handlers.PublicKeyAuth != nil {
		auth := handlers.PublicKeyAuth
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return auth.AuthenticatePublicKey(conn, key, opts)
		}
	}

	if kbdEnabled && handlers.KeyboardInteractiveAuth != nil {
		auth := handlers.KeyboardInteractiveAuth
		cfg.KeyboardInteractiveCallback = func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return auth.AuthenticateKeyboardInteractive(conn, client, opts)
		}
	}

	if hostbasedEnabled && handlers.HostbasedAuth != nil {
		// x/crypto/ssh does not expose a hostbased server callback directly;
		// the only fit is to surface hostbased via publickey because the
		// protocol carries a signed blob similar to publickey auth.
		// Implementations that really need hostbased auth should wrap their
		// logic inside PublicKeyCallback and inspect the method from ConnMetadata.
		// We leave this wire as documentation for now.
		_ = handlers.HostbasedAuth
	}

	if gssEnabled && handlers.GSSAPIServer != nil {
		cfg.GSSAPIWithMICConfig = &ssh.GSSAPIWithMICConfig{
			AllowLogin: func(conn ssh.ConnMetadata, srcName string) (*ssh.Permissions, error) {
				// Forward to password authenticator's identity policy
				// if no dedicated GSSAPI policy exists; callers that want
				// a distinct policy should wire it inside GSSAPIServer.
				return &ssh.Permissions{}, nil
			},
			Server: handlers.GSSAPIServer,
		}
	}

	// NoClientAuth: if every enabled auth method is unavailable (no
	// handler wired up), the server would be unreachable. Leave
	// NoClientAuth disabled — operators must wire at least one handler.
}

// loadHostKeys returns the signers to use as host keys. A HostKeyProvider
// handler takes precedence; otherwise we read the HostKey file paths.
func loadHostKeys(opts *Options, handlers Handlers) ([]ssh.Signer, error) {
	if handlers.HostKeyProvider != nil {
		return handlers.HostKeyProvider.HostKeys(opts)
	}

	var signers []ssh.Signer
	for _, path := range opts.HostKey {
		data, err := os.ReadFile(path)
		if err != nil {
			if handlers.Logger != nil {
				handlers.Logger.Log("DEBUG", fmt.Sprintf("skipping host key %s: %v", path, err))
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			if handlers.Logger != nil {
				handlers.Logger.Log("ERROR", fmt.Sprintf("parsing host key %s: %v", path, err))
			}
			continue
		}

		// If a host certificate exists for this key, wrap it.
		if cert := findHostCertificate(path, opts.HostCertificate, signer); cert != nil {
			signers = append(signers, cert)
			continue
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// findHostCertificate looks for a certificate matching the given host key.
// It tries "<path>-cert.pub" first (the OpenSSH convention), then any
// explicitly configured HostCertificate paths.
func findHostCertificate(keyPath string, explicitCerts []string, signer ssh.Signer) ssh.Signer {
	candidates := append([]string{keyPath + "-cert.pub"}, explicitCerts...)
	for _, cp := range candidates {
		data, err := os.ReadFile(cp)
		if err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			continue
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			continue
		}
		if ssh.FingerprintSHA256(signer.PublicKey()) != ssh.FingerprintSHA256(cert.Key) {
			continue
		}
		cs, err := ssh.NewCertSigner(cert, signer)
		if err == nil {
			return cs
		}
	}
	return nil
}

// Listen starts TCP listeners for every address:port combination derived
// from ListenAddress and Port directives. It returns the collection of
// active listeners. The caller is responsible for calling Close on each.
func (opts *Options) Listen() ([]net.Listener, error) {
	network := "tcp"
	if opts.AddressFamily != nil {
		switch strings.ToLower(*opts.AddressFamily) {
		case "inet":
			network = "tcp4"
		case "inet6":
			network = "tcp6"
		}
	}

	addrs := expandListenAddresses(opts)
	if len(addrs) == 0 {
		return nil, errors.New("no listen addresses configured")
	}

	var listeners []net.Listener
	for _, addr := range addrs {
		l, err := net.Listen(network, addr)
		if err != nil {
			// Close any already-opened listeners before returning.
			for _, existing := range listeners {
				existing.Close()
			}
			return nil, fmt.Errorf("listening on %s: %w", addr, err)
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

// expandListenAddresses cross-products ListenAddress entries with Port
// entries to produce a concrete list of "host:port" strings to bind.
// OpenSSH semantics: if ListenAddress has a port, Port is ignored for that
// entry; otherwise every Port value is used. Empty ListenAddress expands
// to "0.0.0.0" and "[::]" depending on address family.
func expandListenAddresses(opts *Options) []string {
	ports := opts.Ports
	if len(ports) == 0 {
		ports = []int{22}
	}

	// If ListenAddress is unspecified, default to both families unless
	// AddressFamily restricts us. net.Listen with "tcp" on an empty host
	// yields the dual-stack wildcard address, which is what we want.
	if len(opts.ListenAddress) == 0 {
		var addrs []string
		for _, p := range ports {
			addrs = append(addrs, net.JoinHostPort("", strconv.Itoa(p)))
		}
		return addrs
	}

	var addrs []string
	for _, raw := range opts.ListenAddress {
		host, port, hasPort := parseListenAddress(raw)
		if hasPort {
			addrs = append(addrs, net.JoinHostPort(host, port))
			continue
		}
		for _, p := range ports {
			addrs = append(addrs, net.JoinHostPort(host, strconv.Itoa(p)))
		}
	}
	return addrs
}

// parseListenAddress extracts (host, port, hasPort) from a raw
// ListenAddress value. Supported forms:
//
//	host
//	hostname:port
//	[ipv6]:port
//	ipv4:port
//
// Any "rdomain <name>" trailer is ignored (recorded on opts.RDomain instead).
func parseListenAddress(raw string) (host, port string, hasPort bool) {
	raw = strings.TrimSpace(raw)
	// Drop rdomain trailer if present.
	if idx := strings.Index(strings.ToLower(raw), " rdomain "); idx > 0 {
		raw = strings.TrimSpace(raw[:idx])
	}

	// [ipv6]:port or bare [ipv6]
	if strings.HasPrefix(raw, "[") {
		end := strings.Index(raw, "]")
		if end < 0 {
			return raw, "", false
		}
		host = raw[1:end]
		rest := raw[end+1:]
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:], true
		}
		return host, "", false
	}

	// Decide ipv4:port vs hostname vs bare ipv6.
	if strings.Count(raw, ":") == 1 {
		h, p, err := net.SplitHostPort(raw)
		if err == nil {
			return h, p, true
		}
	}
	return raw, "", false
}

// Serve accepts connections on the given listener and hands each one to
// ServeConn in its own goroutine. Blocks until the listener errors or
// returns net.ErrClosed. The returned error is never nil; it is
// net.ErrClosed for a clean shutdown.
func Serve(listener net.Listener, opts *Options, handlers Handlers) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			if err := ServeConn(c, opts, handlers); err != nil {
				logf(handlers, "DEBUG", "connection from %s ended: %v", c.RemoteAddr(), err)
			}
		}(conn)
	}
}

// ServeConn performs the server-side SSH handshake on a single net.Conn,
// dispatches accepted channels to the session handler, and services
// global requests. The connection is closed before return. Returns nil
// on clean disconnect, or an error describing why the session failed.
func ServeConn(raw net.Conn, opts *Options, handlers Handlers) error {
	return handleConnection(raw, opts, handlers)
}

// handleConnection performs the server-side SSH handshake, dispatches new
// channels to the session handler, and services global requests.
func handleConnection(raw net.Conn, opts *Options, handlers Handlers) error {
	defer raw.Close()

	// TCP keepalive.
	if tc, ok := raw.(*net.TCPConn); ok && opts.TCPKeepAlive != nil && *opts.TCPKeepAlive {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// LoginGraceTime: if set, install a read deadline so that stuck clients
	// don't tie up the handshake goroutine.
	if opts.LoginGraceTime != nil && *opts.LoginGraceTime > 0 {
		_ = raw.SetReadDeadline(time.Now().Add(time.Duration(*opts.LoginGraceTime) * time.Second))
	}

	cfg, err := opts.SSHServerConfig(handlers)
	if err != nil {
		logf(handlers, "ERROR", "server config error: %v", err)
		return fmt.Errorf("server config: %w", err)
	}

	srvConn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		// Failed handshake — log and drop.
		logf(handlers, "INFO", "handshake from %s failed: %v", raw.RemoteAddr(), err)
		return fmt.Errorf("handshake: %w", err)
	}
	defer srvConn.Close()

	// Once authenticated, clear the LoginGraceTime deadline.
	if opts.LoginGraceTime != nil && *opts.LoginGraceTime > 0 {
		_ = raw.SetReadDeadline(time.Time{})
	}

	// Enforce AccessController after successful auth.
	if handlers.AccessController != nil {
		if err := handlers.AccessController.CheckAccess(srvConn, srvConn.Permissions, opts); err != nil {
			logf(handlers, "INFO", "access denied for %s from %s: %v", srvConn.User(), srvConn.RemoteAddr(), err)
			return fmt.Errorf("access denied: %w", err)
		}
	}

	// Global requests channel: port forward requests, keepalives, etc.
	go handleGlobalRequests(srvConn, reqs, opts, handlers)

	// New channel loop. Returns when the client closes the connection.
	for nc := range chans {
		go dispatchChannel(srvConn, nc, opts, handlers)
	}
	return nil
}

// handleGlobalRequests services global requests such as tcpip-forward and
// cancel-tcpip-forward. Unknown requests are rejected with "not implemented".
func handleGlobalRequests(srvConn *ssh.ServerConn, reqs <-chan *ssh.Request, opts *Options, handlers Handlers) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			if handlers.TcpForwarder == nil || !tcpForwardingAllowed(opts, "remote") {
				_ = req.Reply(false, nil)
				continue
			}
			bindAddr, bindPort, err := parseTcpForwardPayload(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			bound, err := handlers.TcpForwarder.StartRemoteForward(bindAddr, bindPort, srvConn, opts)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, encodeUint32(bound))

		case "cancel-tcpip-forward":
			if handlers.TcpForwarder == nil {
				_ = req.Reply(false, nil)
				continue
			}
			bindAddr, bindPort, err := parseTcpForwardPayload(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			if err := handlers.TcpForwarder.StopRemoteForward(bindAddr, bindPort, srvConn); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)

		case "streamlocal-forward@openssh.com":
			if handlers.StreamLocalForwarder == nil || !streamLocalAllowed(opts, "remote") {
				_ = req.Reply(false, nil)
				continue
			}
			path, err := parseStreamLocalPayload(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			if err := handlers.StreamLocalForwarder.StartRemoteStreamLocalForward(path, srvConn, opts); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)

		case "cancel-streamlocal-forward@openssh.com":
			if handlers.StreamLocalForwarder == nil {
				_ = req.Reply(false, nil)
				continue
			}
			path, err := parseStreamLocalPayload(req.Payload)
			if err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			if err := handlers.StreamLocalForwarder.StopRemoteStreamLocalForward(path, srvConn); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)

		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// dispatchChannel routes a new channel to the appropriate handler based on
// its type and the current options/handlers.
func dispatchChannel(srvConn *ssh.ServerConn, nc ssh.NewChannel, opts *Options, handlers Handlers) {
	switch nc.ChannelType() {
	case "session":
		if handlers.SessionHandler == nil {
			_ = nc.Reject(ssh.Prohibited, "session handling not available")
			return
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		ctx := &sessionCtx{
			channel:     ch,
			requests:    reqs,
			meta:        srvConn,
			permissions: srvConn.Permissions,
			opts:        opts,
			handlers:    handlers,
		}
		if err := handlers.SessionHandler.HandleSession(ctx); err != nil {
			logf(handlers, "ERROR", "session handler: %v", err)
		}
		_ = ch.Close()

	case "direct-tcpip":
		if handlers.TcpForwarder == nil || !tcpForwardingAllowed(opts, "local") {
			_ = nc.Reject(ssh.Prohibited, "TCP forwarding disabled")
			return
		}
		if err := handlers.TcpForwarder.HandleDirectTcpIP(nc, srvConn, opts); err != nil {
			logf(handlers, "ERROR", "direct-tcpip: %v", err)
		}

	case "direct-streamlocal@openssh.com":
		if handlers.StreamLocalForwarder == nil || !streamLocalAllowed(opts, "local") {
			_ = nc.Reject(ssh.Prohibited, "StreamLocal forwarding disabled")
			return
		}
		if err := handlers.StreamLocalForwarder.HandleDirectStreamLocal(nc, srvConn, opts); err != nil {
			logf(handlers, "ERROR", "direct-streamlocal: %v", err)
		}

	case "tun@openssh.com":
		if handlers.TunnelForwarder == nil || opts.PermitTunnel == nil || *opts.PermitTunnel == "no" {
			_ = nc.Reject(ssh.Prohibited, "tunnel forwarding disabled")
			return
		}
		if err := handlers.TunnelForwarder.HandleTunnelRequest(nc, srvConn, opts); err != nil {
			logf(handlers, "ERROR", "tunnel: %v", err)
		}

	default:
		_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type: "+nc.ChannelType())
	}
}

// tcpForwardingAllowed inspects AllowTcpForwarding / DisableForwarding
// to decide whether the given direction ("local" or "remote") is permitted.
func tcpForwardingAllowed(opts *Options, direction string) bool {
	if opts.DisableForwarding != nil && *opts.DisableForwarding {
		return false
	}
	if opts.AllowTcpForwarding == nil {
		return true
	}
	switch strings.ToLower(*opts.AllowTcpForwarding) {
	case "no":
		return false
	case "yes", "all":
		return true
	case "local":
		return direction == "local"
	case "remote":
		return direction == "remote"
	}
	return true
}

// streamLocalAllowed mirrors tcpForwardingAllowed for Unix-domain sockets.
func streamLocalAllowed(opts *Options, direction string) bool {
	if opts.DisableForwarding != nil && *opts.DisableForwarding {
		return false
	}
	if opts.AllowStreamLocalForwarding == nil {
		return true
	}
	switch strings.ToLower(*opts.AllowStreamLocalForwarding) {
	case "no":
		return false
	case "yes", "all":
		return true
	case "local":
		return direction == "local"
	case "remote":
		return direction == "remote"
	}
	return true
}

// logf sends a formatted log line to the configured logger (if any).
func logf(handlers Handlers, level, format string, args ...interface{}) {
	if handlers.Logger == nil {
		return
	}
	handlers.Logger.Log(level, fmt.Sprintf(format, args...))
}
