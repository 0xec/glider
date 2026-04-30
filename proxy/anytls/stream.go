package anytls

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Stream struct {
	id   uint32
	sess *Session

	mu         sync.Mutex
	readBuf    bytes.Buffer
	readNotify chan struct{}
	closed     chan struct{}
	dieOnce    sync.Once
	dieErr     error
	dieHook    func()

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

func newStream(id uint32, sess *Session) *Stream {
	return &Stream{
		id:         id,
		sess:       sess,
		readNotify: make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	for {
		s.mu.Lock()
		if s.readBuf.Len() > 0 {
			n, _ := s.readBuf.Read(b)
			err := error(nil)
			if n == 0 && s.dieErr != nil {
				err = s.dieErr
			}
			s.mu.Unlock()
			return n, err
		}
		err := s.dieErr
		s.mu.Unlock()

		if err != nil {
			return 0, err
		}

		deadline := s.loadDeadline(&s.readDeadline)
		if deadline.IsZero() {
			select {
			case <-s.readNotify:
			case <-s.closed:
			}
			continue
		}

		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(wait)
		select {
		case <-s.readNotify:
			timer.Stop()
		case <-s.closed:
			timer.Stop()
		case <-timer.C:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (s *Stream) Write(b []byte) (int, error) {
	if deadline := s.loadDeadline(&s.writeDeadline); !deadline.IsZero() && time.Until(deadline) <= 0 {
		return 0, os.ErrDeadlineExceeded
	}

	s.mu.Lock()
	err := s.dieErr
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}

	return s.sess.writeDataFrame(s.id, b)
}

func (s *Stream) Close() error {
	return s.closeWithError(io.ErrClosedPipe)
}

func (s *Stream) closeLocally() {
	var once bool
	s.dieOnce.Do(func() {
		s.mu.Lock()
		s.dieErr = net.ErrClosed
		s.mu.Unlock()
		close(s.closed)
		once = true
	})
	if once && s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}
}

func (s *Stream) closeWithError(err error) error {
	var once bool
	s.dieOnce.Do(func() {
		s.mu.Lock()
		s.dieErr = err
		s.mu.Unlock()
		close(s.closed)
		once = true
	})
	if !once {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.dieErr
	}
	if s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}
	return s.sess.streamClosed(s.id)
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Store(t)
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Store(t)
	return nil
}

func (s *Stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	_ = s.SetWriteDeadline(t)
	return nil
}

func (s *Stream) LocalAddr() net.Addr {
	if conn, ok := s.sess.conn.(interface{ LocalAddr() net.Addr }); ok {
		return conn.LocalAddr()
	}
	return nil
}

func (s *Stream) RemoteAddr() net.Addr {
	if conn, ok := s.sess.conn.(interface{ RemoteAddr() net.Addr }); ok {
		return conn.RemoteAddr()
	}
	return nil
}

func (s *Stream) feed(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dieErr != nil {
		return
	}
	_, _ = s.readBuf.Write(data)
	select {
	case s.readNotify <- struct{}{}:
	default:
	}
}

func (s *Stream) loadDeadline(value *atomic.Value) time.Time {
	v := value.Load()
	if v == nil {
		return time.Time{}
	}
	deadline, _ := v.(time.Time)
	return deadline
}
