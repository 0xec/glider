package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/nadoo/glider/pkg/pool"
	"github.com/nadoo/glider/stats"
)

var (
	// TCPBufSize is the size of tcp buffer.
	TCPBufSize = 32 << 10

	// UDPBufSize is the size of udp buffer.
	UDPBufSize = 2 << 10
)

// Conn is a connection with buffered reader.
type Conn struct {
	r *bufio.Reader
	net.Conn
}

// NewConn returns a new conn.
func NewConn(c net.Conn) *Conn {
	if conn, ok := c.(*Conn); ok {
		return conn
	}
	return &Conn{pool.GetBufReader(c), c}
}

// Reader returns the internal bufio.Reader.
func (c *Conn) Reader() *bufio.Reader      { return c.r }
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Peek returns the next n bytes without advancing the reader.
func (c *Conn) Peek(n int) ([]byte, error) { return c.r.Peek(n) }

// WriteTo implements io.WriterTo.
func (c *Conn) WriteTo(w io.Writer) (n int64, err error) { return c.r.WriteTo(w) }

// Close closes the Conn.
func (c *Conn) Close() error {
	pool.PutBufReader(c.r)
	return c.Conn.Close()
}

// Relay relays between left and right.
func Relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	sourceIP := stats.SourceIP(left.RemoteAddr())

	wg.Add(1)
	go func() {
		defer wg.Done()
		if sourceIP == "" {
			_, err1 = Copy(right, left)
		} else {
			_, err1 = CopyWithObserver(right, left, func(written int) {
				stats.AddUpload(sourceIP, written)
			})
		}
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()

	if sourceIP == "" {
		_, err = Copy(left, right)
	} else {
		_, err = CopyWithObserver(left, right, func(written int) {
			stats.AddDownload(sourceIP, written)
		})
	}
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()

	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
		return err1
	}

	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}

	return nil
}

// CopyWithObserver copies from src to dst and reports successful writes.
func CopyWithObserver(dst io.Writer, src io.Reader, observer func(written int)) (written int64, err error) {
	if observer == nil {
		return Copy(dst, src)
	}

	size := TCPBufSize
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}

	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw > 0 {
				written += int64(nw)
				observer(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

// Copy copies from src to dst.
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	dst = underlyingWriter(dst)
	switch runtime.GOOS {
	case "linux", "windows", "dragonfly", "freebsd", "solaris":
		if _, ok := dst.(*net.TCPConn); ok && worthTry(src) {
			if wt, ok := src.(io.WriterTo); ok {
				return wt.WriteTo(dst)
			}
			if rt, ok := dst.(io.ReaderFrom); ok {
				return rt.ReadFrom(src)
			}
		}
	}
	return CopyBuffer(dst, src)
}

func underlyingWriter(c io.Writer) io.Writer {
	if wrap, ok := c.(*Conn); ok {
		return wrap.Conn
	}
	return c
}

func worthTry(src io.Reader) bool {
	switch v := src.(type) {
	case *net.TCPConn, *net.UnixConn:
		return true
	case *io.LimitedReader:
		return worthTry(v.R)
	case *Conn:
		return worthTry(v.Conn)
	case *os.File:
		fi, err := v.Stat()
		if err != nil {
			return false
		}
		return fi.Mode().IsRegular()
	default:
		return false
	}
}

// CopyN copies n bytes (or until an error) from src to dst.
func CopyN(dst io.Writer, src io.Reader, n int64) (written int64, err error) {
	written, err = Copy(dst, io.LimitReader(src, n))
	if written == n {
		return n, nil
	}
	if written < n && err == nil {
		// src stopped early; must have been EOF.
		err = io.EOF
	}
	return
}

// CopyBuffer copies from src to dst with a userspace buffer.
func CopyBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	size := TCPBufSize
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}

	buf := pool.GetBuffer(size)
	defer pool.PutBuffer(buf)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// CopyUDP copys from src to dst at target with read timeout.
// if step sets to non-zero value,
// the read timeout will be increased from 0 to timeout by step in every read operation.
func CopyUDP(dst net.PacketConn, writeTo net.Addr, src net.PacketConn, timeout time.Duration, step time.Duration) error {
	return CopyUDPWithObserver(dst, writeTo, src, timeout, step, nil)
}

// CopyUDPWithObserver copies packets and reports successful payload writes.
func CopyUDPWithObserver(dst net.PacketConn, writeTo net.Addr, src net.PacketConn, timeout time.Duration, step time.Duration, observer func(written int)) error {
	buf := pool.GetBuffer(UDPBufSize)
	defer pool.PutBuffer(buf)

	var t time.Duration
	for {
		if t += step; t == 0 || t > timeout {
			t = timeout
		}

		src.SetReadDeadline(time.Now().Add(t))
		n, addr, err := src.ReadFrom(buf)
		if err != nil {
			return err
		}

		if writeTo != nil {
			addr = writeTo
		}

		written, err := dst.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
		if observer != nil && written > 0 {
			observer(written)
		}
	}
}
