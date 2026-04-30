package anytls

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/nadoo/glider/pkg/socks"
)

const (
	uotAddrIPv4 = 0x00
	uotAddrIPv6 = 0x01
	uotAddrFQDN = 0x02
)

type addrPort struct {
	Addr netip.Addr
	FQDN string
	Port uint16
}

func (a addrPort) IsValid() bool {
	return a.Addr.IsValid() || a.FQDN != ""
}

func (a addrPort) UDPAddr() *net.UDPAddr {
	if a.Addr.IsValid() {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a.Addr, a.Port))
	}
	addr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(a.FQDN, strconv.Itoa(int(a.Port))))
	return addr
}

func parseAddrPort(value string) addrPort {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return addrPort{}
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return addrPort{}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return addrPort{Addr: ip, Port: uint16(portNum)}
	}

	return addrPort{FQDN: strings.TrimSuffix(host, "."), Port: uint16(portNum)}
}

func addrPortLen(addr addrPort) int {
	if !addr.IsValid() {
		return 1
	}
	if addr.Addr.IsValid() {
		if addr.Addr.Is4() {
			return 1 + 4 + 2
		}
		return 1 + 16 + 2
	}
	return 1 + 1 + len(addr.FQDN) + 2
}

func serializeAddrPort(addr addrPort) []byte {
	if !addr.IsValid() {
		return []byte{0}
	}

	if addr.Addr.IsValid() {
		if addr.Addr.Is4() {
			buf := make([]byte, 1+4+2)
			buf[0] = uotAddrIPv4
			copy(buf[1:5], addr.Addr.AsSlice())
			binaryPort(buf[5:7], addr.Port)
			return buf
		}
		buf := make([]byte, 1+16+2)
		buf[0] = uotAddrIPv6
		copy(buf[1:17], addr.Addr.AsSlice())
		binaryPort(buf[17:19], addr.Port)
		return buf
	}

	buf := make([]byte, 1+1+len(addr.FQDN)+2)
	buf[0] = uotAddrFQDN
	buf[1] = byte(len(addr.FQDN))
	copy(buf[2:2+len(addr.FQDN)], addr.FQDN)
	binaryPort(buf[2+len(addr.FQDN):], addr.Port)
	return buf
}

func binaryPort(dst []byte, port uint16) {
	dst[0] = byte(port >> 8)
	dst[1] = byte(port)
}

func socksAddr(addr string) socks.Addr {
	return socks.ParseAddr(addr)
}
