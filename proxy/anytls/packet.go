package anytls

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

type PktConn struct {
	net.Conn
	target addrPort
	init   bool
}

func NewPktConn(conn net.Conn, target addrPort) *PktConn {
	return &PktConn{Conn: conn, target: target}
}

func (pc *PktConn) writeRequest() error {
	if pc.init {
		return nil
	}

	req := make([]byte, 0, 1+addrPortLen(pc.target))
	req = append(req, 1)
	req = append(req, serializeAddrPort(pc.target)...)
	if _, err := pc.Conn.Write(req); err != nil {
		return err
	}
	pc.init = true
	return nil
}

func (pc *PktConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if len(b) < 2 {
		return 0, pc.target.UDPAddr(), errors.New("buf size is not enough")
	}

	if _, err := io.ReadFull(pc.Conn, b[:2]); err != nil {
		return 0, pc.target.UDPAddr(), err
	}
	length := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < length {
		return 0, pc.target.UDPAddr(), errors.New("buf size is not enough")
	}

	n, err := io.ReadFull(pc.Conn, b[:length])
	return n, pc.target.UDPAddr(), err
}

func (pc *PktConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	target := pc.target
	if addr != nil {
		target = parseAddrPort(addr.String())
	}
	if !target.IsValid() {
		return 0, errors.New("invalid addr")
	}

	if !pc.init {
		if err := pc.writeRequest(); err != nil {
			return 0, err
		}
	}

	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(b)))
	copy(frame[2:], b)

	n, err := pc.Conn.Write(frame)
	if n > 2 {
		return n - 2, err
	}
	return 0, err
}
