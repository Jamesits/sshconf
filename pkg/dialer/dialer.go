package dialer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Dialer is the shared connection interface used by config-derived dialers.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// DialerFunc adapts a function to the [Dialer] interface.
type DialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext calls f(ctx, network, addr).
func (f DialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// Wrapper wraps a config-derived dialer while preserving the resolved
// dialer configuration for caller-side extensions such as tracing or
// proxy handling.
type Wrapper interface {
	WrapDialer(inner Dialer, cfg DialConfig) Dialer
}

// WrapperFunc adapts a function to the [Wrapper] interface.
type WrapperFunc func(inner Dialer, cfg DialConfig) Dialer

// WrapDialer calls f(inner, cfg).
func (f WrapperFunc) WrapDialer(inner Dialer, cfg DialConfig) Dialer {
	return f(inner, cfg)
}

// DialConfig holds the connection customisation that affects how outbound
// TCP connections are established.
//
// The socket-local settings are applied directly by the returned dialer.
// ProxyCommand / ProxyJump / ProxyUseFdpass are surfaced for wrappers that
// replace the transport path but still need access to the resolved config.
type DialConfig struct {
	AddressFamily  string
	BindAddress    string
	BindInterface  string
	ConnectTimeout time.Duration
	IPQoS          string

	ProxyCommand   string
	ProxyJump      string
	ProxyUseFdpass bool

	// Wrapper optionally decorates or replaces the config-derived base
	// dialer. Callers can set this after parsing/resolution and before the
	// action starts.
	Wrapper Wrapper
}

// GetDialer returns a concrete dialer for cfg. If Wrapper is non-nil then it
// is applied around the config-derived base dialer.
func (cfg DialConfig) GetDialer() Dialer {
	base := &configuredDialer{cfg: cfg}
	if cfg.Wrapper == nil {
		return base
	}
	return cfg.Wrapper.WrapDialer(base, cfg)
}

// Network rewrites a generic network name according to AddressFamily.
func (cfg DialConfig) Network(network string) string {
	switch strings.ToLower(cfg.AddressFamily) {
	case "inet":
		switch network {
		case "tcp":
			return "tcp4"
		case "udp":
			return "udp4"
		}
	case "inet6":
		switch network {
		case "tcp":
			return "tcp6"
		case "udp":
			return "udp6"
		}
	}
	return network
}

type configuredDialer struct {
	cfg DialConfig
}

// DialContext applies the OpenSSH-derived dial settings and then performs
// the connection using the standard library dialer.
func (d *configuredDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	network = d.cfg.Network(network)
	nd := &net.Dialer{}
	if d.cfg.ConnectTimeout > 0 {
		nd.Timeout = d.cfg.ConnectTimeout
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.cfg.ConnectTimeout)
		defer cancel()
	}

	localAddr, err := d.cfg.localAddr(ctx, network)
	if err != nil {
		return nil, err
	}
	nd.LocalAddr = localAddr

	trafficClass, hasTrafficClass, err := parseIPQoS(d.cfg.IPQoS)
	if err != nil {
		return nil, err
	}
	if hasTrafficClass {
		nd.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
			return applyTrafficClass(c, network, trafficClass)
		}
	}

	return nd.DialContext(ctx, network, addr)
}

func (cfg DialConfig) localAddr(ctx context.Context, network string) (net.Addr, error) {
	if cfg.BindAddress != "" {
		ip, zone, err := resolveBindHost(ctx, cfg.BindAddress, network)
		if err != nil {
			return nil, err
		}
		return tcpOrUDPAddr(network, ip, zone), nil
	}
	if cfg.BindInterface == "" {
		return nil, nil
	}

	iface, err := net.InterfaceByName(cfg.BindInterface)
	if err != nil {
		return nil, fmt.Errorf("resolve bind interface %q: %w", cfg.BindInterface, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("resolve bind interface %q: %w", cfg.BindInterface, err)
	}
	for _, addr := range addrs {
		ip, zone := interfaceIP(addr, iface.Name)
		if ip == nil || !networkMatchesIP(network, ip) {
			continue
		}
		return tcpOrUDPAddr(network, ip, zone), nil
	}

	return nil, fmt.Errorf("bind interface %q has no address for %s", cfg.BindInterface, network)
}

func resolveBindHost(ctx context.Context, host, network string) (net.IP, string, error) {
	if ip, zone := parseIPAndZone(host); ip != nil {
		if !networkMatchesIP(network, ip) {
			return nil, "", fmt.Errorf("bind address %q does not match %s", host, network)
		}
		return ip, zone, nil
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, "", fmt.Errorf("resolve bind address %q: %w", host, err)
	}
	for _, addr := range addrs {
		if networkMatchesIP(network, addr.IP) {
			return addr.IP, addr.Zone, nil
		}
	}

	return nil, "", fmt.Errorf("bind address %q has no address for %s", host, network)
}

func parseIPAndZone(host string) (net.IP, string) {
	host = strings.TrimSpace(host)
	if i := strings.LastIndexByte(host, '%'); i > 0 {
		if ip := net.ParseIP(host[:i]); ip != nil {
			return ip, host[i+1:]
		}
	}
	return net.ParseIP(host), ""
}

func interfaceIP(addr net.Addr, ifaceName string) (net.IP, string) {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP, value.Zone
	case *net.IPNet:
		ip := value.IP
		zone := ""
		if ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			zone = ifaceName
		}
		return ip, zone
	default:
		return nil, ""
	}
}

func tcpOrUDPAddr(network string, ip net.IP, zone string) net.Addr {
	switch {
	case strings.HasPrefix(network, "udp"):
		return &net.UDPAddr{IP: ip, Zone: zone}
	default:
		return &net.TCPAddr{IP: ip, Zone: zone}
	}
}

func networkMatchesIP(network string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	switch {
	case strings.HasSuffix(network, "4"):
		return ip.To4() != nil
	case strings.HasSuffix(network, "6"):
		return ip.To4() == nil
	default:
		return true
	}
}

func parseIPQoS(value string) (int, bool, error) {
	fields := strings.Fields(strings.ToLower(value))
	if len(fields) == 0 {
		return 0, false, nil
	}
	token := fields[0]
	if token == "" || token == "none" {
		return 0, false, nil
	}
	if v, err := strconv.Atoi(token); err == nil {
		if v < 0 || v > 255 {
			return 0, false, fmt.Errorf("invalid IPQoS value %q", token)
		}
		return v, true, nil
	}

	if v, ok := ipQoSNames[token]; ok {
		return v, true, nil
	}

	return 0, false, fmt.Errorf("invalid IPQoS value %q", token)
}

var ipQoSNames = map[string]int{
	"af11": 10 << 2,
	"af12": 12 << 2,
	"af13": 14 << 2,
	"af21": 18 << 2,
	"af22": 20 << 2,
	"af23": 22 << 2,
	"af31": 26 << 2,
	"af32": 28 << 2,
	"af33": 30 << 2,
	"af41": 34 << 2,
	"af42": 36 << 2,
	"af43": 38 << 2,
	"cs0":  0 << 2,
	"cs1":  8 << 2,
	"cs2":  16 << 2,
	"cs3":  24 << 2,
	"cs4":  32 << 2,
	"cs5":  40 << 2,
	"cs6":  48 << 2,
	"cs7":  56 << 2,
	"ef":   46 << 2,
	"le":   1 << 2,
}
