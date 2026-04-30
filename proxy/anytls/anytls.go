package anytls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nadoo/glider/proxy"
)

const (
	defaultIdleSessionCheckInterval = 30 * time.Second
	defaultIdleSessionTimeout       = 30 * time.Second
	defaultMinIdleSession           = 5
	protocolVersion                 = "2"
	programVersionName              = "glider-anytls"
	uotMagicAddress                 = "sp.v2.udp-over-tcp.arpa"
)

type AnyTLS struct {
	dialer proxy.Dialer
	addr   string

	passwordSHA256 [32]byte
	tlsConfig      *tls.Config

	client *Client
}

func init() {
	proxy.RegisterDialer("anytls", NewAnyTLSDialer)
	proxy.AddUsage("anytls", `
AnyTLS client scheme:
  anytls://password@host:port[?sni=SERVERNAME][&insecure=1][&cert=PATH]
  anytls://password@host:port[?serverName=SERVERNAME][&skipVerify=true][&cert=PATH]
  anytls://password@host:port[?minIdleSession=5][&idleSessionCheckInterval=30s][&idleSessionTimeout=30s]
`)
}

func NewAnyTLSDialer(s string, d proxy.Dialer) (proxy.Dialer, error) {
	a, err := NewAnyTLS(s, d)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func NewAnyTLS(s string, d proxy.Dialer) (*AnyTLS, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("[anytls] parse url err: %w", err)
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
	}
	if password == "" {
		return nil, fmt.Errorf("[anytls] password must be specified")
	}

	addr := u.Host
	if addr == "" {
		return nil, fmt.Errorf("[anytls] server address must be specified")
	}
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "443")
	}

	query := u.Query()
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[anytls] invalid server address %q: %w", addr, err)
	}

	serverName := firstNonEmpty(query.Get("sni"), query.Get("serverName"))
	if serverName == "" {
		serverName = host
	}
	if net.ParseIP(serverName) != nil {
		serverName = ""
	}

	skipVerify := isTrue(query.Get("insecure")) || isTrue(query.Get("skipVerify"))
	certFile := query.Get("cert")

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	if certFile != "" {
		certData, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("[anytls] read cert file error: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(certData) {
			return nil, fmt.Errorf("[anytls] can not append cert file: %s", certFile)
		}
		tlsConfig.RootCAs = certPool
	}

	idleCheckInterval := defaultIdleSessionCheckInterval
	if value := query.Get("idleSessionCheckInterval"); value != "" {
		idleCheckInterval, err = time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("[anytls] invalid idleSessionCheckInterval: %w", err)
		}
	}

	idleTimeout := defaultIdleSessionTimeout
	if value := query.Get("idleSessionTimeout"); value != "" {
		idleTimeout, err = time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("[anytls] invalid idleSessionTimeout: %w", err)
		}
	}

	minIdleSession := defaultMinIdleSession
	if value := query.Get("minIdleSession"); value != "" {
		minIdleSession, err = strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("[anytls] invalid minIdleSession: %w", err)
		}
		if minIdleSession < 0 {
			minIdleSession = 0
		}
	}

	a := &AnyTLS{
		dialer:         d,
		addr:           addr,
		passwordSHA256: sha256.Sum256([]byte(password)),
		tlsConfig:      tlsConfig,
	}
	a.client = NewClient(a.createAuthenticatedConn, idleCheckInterval, idleTimeout, minIdleSession)

	return a, nil
}

func (a *AnyTLS) Addr() string {
	if a.addr == "" {
		return a.dialer.Addr()
	}
	return a.addr
}

func (a *AnyTLS) Dial(network, addr string) (net.Conn, error) {
	stream, err := a.client.CreateStream()
	if err != nil {
		return nil, err
	}

	target := socksAddr(addr)
	if target == nil {
		stream.Close()
		return nil, fmt.Errorf("[anytls] invalid target address: %s", addr)
	}

	if _, err := stream.Write(target); err != nil {
		stream.Close()
		return nil, err
	}

	return stream, nil
}

func (a *AnyTLS) DialUDP(network, addr string) (net.PacketConn, error) {
	target := parseAddrPort(addr)
	if !target.IsValid() {
		return nil, fmt.Errorf("[anytls] invalid udp target address: %s", addr)
	}

	stream, err := a.client.CreateStream()
	if err != nil {
		return nil, err
	}

	proxyTarget := socksAddr(net.JoinHostPort(uotMagicAddress, "0"))
	if proxyTarget == nil {
		stream.Close()
		return nil, fmt.Errorf("[anytls] invalid uot target")
	}

	if _, err := stream.Write(proxyTarget); err != nil {
		stream.Close()
		return nil, err
	}

	pc := NewPktConn(stream, target)
	if err := pc.writeRequest(); err != nil {
		stream.Close()
		return nil, err
	}

	return pc, nil
}

func (a *AnyTLS) createAuthenticatedConn() (net.Conn, error) {
	rawConn, err := a.dialer.Dial("tcp", a.addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, a.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	paddingLen := 0
	if padding := loadPaddingFactory(); padding != nil {
		sizes := padding.GenerateRecordPayloadSizes(0)
		if len(sizes) > 0 && sizes[0] > 0 {
			paddingLen = sizes[0]
		}
	}

	auth := make([]byte, 32+2+paddingLen)
	copy(auth[:32], a.passwordSHA256[:])
	auth[32] = byte(paddingLen >> 8)
	auth[33] = byte(paddingLen)

	if _, err := tlsConn.Write(auth); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func isTrue(value string) bool {
	value = strings.ToLower(value)
	return value == "1" || value == "true" || value == "yes" || value == "on"
}
