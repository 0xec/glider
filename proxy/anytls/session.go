package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdUpdatePaddingScheme
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

const headerOverHeadSize = 1 + 4 + 2

type frame struct {
	cmd  byte
	sid  uint32
	data []byte
}

func newFrame(cmd byte, sid uint32) frame {
	return frame{cmd: cmd, sid: sid}
}

type rawHeader [headerOverHeadSize]byte

func (h rawHeader) Cmd() byte {
	return h[0]
}

func (h rawHeader) StreamID() uint32 {
	return binary.BigEndian.Uint32(h[1:5])
}

func (h rawHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[5:7])
}

type Session struct {
	conn     io.ReadWriteCloser
	connLock sync.Mutex

	streams    map[uint32]*Stream
	streamID   atomic.Uint32
	streamLock sync.RWMutex

	dieOnce sync.Once
	die     chan struct{}
	dieHook func()

	seq       uint64
	idleSince time.Time

	peerVersion byte
	isClient    bool
	sendPadding bool
	buffering   bool
	buffer      []byte
	pktCounter  atomic.Uint32
}

func NewClientSession(conn io.ReadWriteCloser) *Session {
	return &Session{
		conn:        conn,
		streams:     make(map[uint32]*Stream),
		die:         make(chan struct{}),
		isClient:    true,
		sendPadding: true,
	}
}

func (s *Session) Run() {
	settings := []byte("v=" + protocolVersion + "\nclient=" + programVersionName + "\npadding-md5=" + loadPaddingFactory().Md5)
	frame := newFrame(cmdSettings, 0)
	frame.data = settings
	s.buffering = true
	_, _ = s.writeControlFrame(frame)
	go s.recvLoop()
}

func (s *Session) IsClosed() bool {
	select {
	case <-s.die:
		return true
	default:
		return false
	}
}

func (s *Session) Close() error {
	var once bool
	s.dieOnce.Do(func() {
		close(s.die)
		once = true
	})
	if !once {
		return io.ErrClosedPipe
	}

	if s.dieHook != nil {
		s.dieHook()
		s.dieHook = nil
	}

	s.streamLock.Lock()
	for _, stream := range s.streams {
		stream.closeLocally()
	}
	s.streams = make(map[uint32]*Stream)
	s.streamLock.Unlock()

	return s.conn.Close()
}

func (s *Session) OpenStream() (*Stream, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}

	sid := s.streamID.Add(1)
	stream := newStream(sid, s)

	if _, err := s.writeControlFrame(newFrame(cmdSYN, sid)); err != nil {
		return nil, err
	}
	s.buffering = false

	s.streamLock.Lock()
	s.streams[sid] = stream
	s.streamLock.Unlock()

	return stream, nil
}

func (s *Session) recvLoop() error {
	defer s.Close()

	var hdr rawHeader
	for {
		if s.IsClosed() {
			return io.ErrClosedPipe
		}

		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return err
		}

		sid := hdr.StreamID()
		length := int(hdr.Length())

		switch hdr.Cmd() {
		case cmdPSH:
			if length == 0 {
				continue
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(s.conn, payload); err != nil {
				return err
			}
			s.streamLock.RLock()
			stream := s.streams[sid]
			s.streamLock.RUnlock()
			if stream != nil {
				stream.feed(payload)
			}
		case cmdSYNACK:
			payload, err := s.readPayload(length)
			if err != nil {
				return err
			}
			if len(payload) == 0 {
				continue
			}
			s.streamLock.RLock()
			stream := s.streams[sid]
			s.streamLock.RUnlock()
			if stream != nil {
				stream.closeWithError(fmt.Errorf("remote: %s", string(payload)))
			}
		case cmdFIN:
			s.streamLock.Lock()
			stream := s.streams[sid]
			delete(s.streams, sid)
			s.streamLock.Unlock()
			if stream != nil {
				stream.closeLocally()
			}
		case cmdWaste:
			if _, err := s.readPayload(length); err != nil {
				return err
			}
		case cmdAlert:
			payload, err := s.readPayload(length)
			if err != nil {
				return err
			}
			if len(payload) == 0 {
				return io.ErrUnexpectedEOF
			}
			return fmt.Errorf("[anytls] alert from server: %s", string(payload))
		case cmdUpdatePaddingScheme:
			payload, err := s.readPayload(length)
			if err != nil {
				return err
			}
			if len(payload) > 0 {
				UpdatePaddingScheme(payload)
			}
		case cmdHeartRequest:
			if _, err := s.writeControlFrame(newFrame(cmdHeartResponse, sid)); err != nil {
				return err
			}
		case cmdHeartResponse:
			if _, err := s.readPayload(length); err != nil {
				return err
			}
		case cmdServerSettings:
			payload, err := s.readPayload(length)
			if err != nil {
				return err
			}
			if len(payload) == 0 {
				continue
			}
			if version, err := strconv.Atoi(stringMapFromBytes(payload)["v"]); err == nil {
				s.peerVersion = byte(version)
			}
		default:
			if _, err := s.readPayload(length); err != nil {
				return err
			}
		}
	}
}

func (s *Session) readPayload(length int) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(s.conn, payload)
	return payload, err
}

func (s *Session) streamClosed(sid uint32) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	_, err := s.writeControlFrame(newFrame(cmdFIN, sid))
	s.streamLock.Lock()
	delete(s.streams, sid)
	s.streamLock.Unlock()
	return err
}

func (s *Session) writeDataFrame(sid uint32, data []byte) (int, error) {
	buffer := make([]byte, headerOverHeadSize+len(data))
	buffer[0] = cmdPSH
	binary.BigEndian.PutUint32(buffer[1:5], sid)
	binary.BigEndian.PutUint16(buffer[5:7], uint16(len(data)))
	copy(buffer[7:], data)

	if _, err := s.writeConn(buffer); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (s *Session) writeControlFrame(frame frame) (int, error) {
	buffer := make([]byte, headerOverHeadSize+len(frame.data))
	buffer[0] = frame.cmd
	binary.BigEndian.PutUint32(buffer[1:5], frame.sid)
	binary.BigEndian.PutUint16(buffer[5:7], uint16(len(frame.data)))
	copy(buffer[7:], frame.data)

	if conn, ok := s.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		defer conn.SetWriteDeadline(time.Time{})
	}

	if _, err := s.writeConn(buffer); err != nil {
		s.Close()
		return 0, err
	}

	return len(frame.data), nil
}

func (s *Session) writeConn(b []byte) (int, error) {
	s.connLock.Lock()
	defer s.connLock.Unlock()

	if s.buffering {
		s.buffer = append(s.buffer, b...)
		return len(b), nil
	}
	if len(s.buffer) > 0 {
		b = slices.Concat(s.buffer, b)
		s.buffer = nil
	}

	if s.sendPadding {
		padding := loadPaddingFactory()
		if padding != nil {
			pkt := s.pktCounter.Add(1)
			if pkt < padding.Stop {
				return s.writeWithPadding(b, padding.GenerateRecordPayloadSizes(pkt))
			}
		}
		s.sendPadding = false
	}

	return s.conn.Write(b)
}

func (s *Session) writeWithPadding(payload []byte, sizes []int) (int, error) {
	n := 0
	b := payload
	for _, size := range sizes {
		remain := len(b)
		if size == checkMark {
			if remain == 0 {
				break
			}
			continue
		}

		switch {
		case remain > size:
			written, err := s.conn.Write(b[:size])
			n += written
			if err != nil {
				return 0, err
			}
			b = b[size:]
		case remain > 0:
			paddingLen := size - remain - headerOverHeadSize
			if paddingLen > 0 {
				padding := make([]byte, headerOverHeadSize+paddingLen)
				padding[0] = cmdWaste
				binary.BigEndian.PutUint16(padding[5:7], uint16(paddingLen))
				b = slices.Concat(b, padding)
			}
			written, err := s.conn.Write(b)
			n += min(written, remain)
			if err != nil {
				return 0, err
			}
			b = nil
		case remain == 0:
			padding := make([]byte, headerOverHeadSize+size)
			padding[0] = cmdWaste
			binary.BigEndian.PutUint16(padding[5:7], uint16(size))
			if _, err := s.conn.Write(padding); err != nil {
				return 0, err
			}
		}
	}

	if len(b) == 0 {
		return n, nil
	}

	written, err := s.conn.Write(b)
	n += min(written, len(b))
	return n, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
