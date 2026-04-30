package anytls

import (
	"io"
	"math"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	dialOut func() (net.Conn, error)

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    []*Session

	sessionsLock sync.Mutex
	sessions     map[uint64]*Session

	idleSessionTimeout time.Duration
	minIdleSession     int
	closed             atomic.Bool
	stopCleanup        chan struct{}
}

func NewClient(dialOut func() (net.Conn, error), idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int) *Client {
	if idleSessionCheckInterval <= 5*time.Second {
		idleSessionCheckInterval = defaultIdleSessionCheckInterval
	}
	if idleSessionTimeout <= 5*time.Second {
		idleSessionTimeout = defaultIdleSessionTimeout
	}

	c := &Client{
		dialOut:            dialOut,
		sessions:           make(map[uint64]*Session),
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		stopCleanup:        make(chan struct{}),
	}

	go c.idleCleanupLoop(idleSessionCheckInterval)
	return c
}

func (c *Client) CreateStream() (*Stream, error) {
	if c.closed.Load() {
		return nil, io.ErrClosedPipe
	}

	var (
		session *Session
		err     error
	)

	session = c.getIdleSession()
	if session == nil {
		session, err = c.createSession()
	}
	if session == nil {
		if err == nil {
			err = io.ErrClosedPipe
		}
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		session.Close()
		return nil, err
	}

	stream.dieHook = func() {
		if c.closed.Load() || session.IsClosed() {
			session.Close()
			return
		}

		c.idleSessionLock.Lock()
		session.idleSince = time.Now()
		c.idleSessions = append(c.idleSessions, session)
		sort.Slice(c.idleSessions, func(i, j int) bool {
			return c.idleSessions[i].seq > c.idleSessions[j].seq
		})
		c.idleSessionLock.Unlock()
	}

	return stream, nil
}

func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return io.ErrClosedPipe
	}

	close(c.stopCleanup)

	c.sessionsLock.Lock()
	sessions := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessions {
		session.Close()
	}

	return nil
}

func (c *Client) getIdleSession() *Session {
	c.idleSessionLock.Lock()
	defer c.idleSessionLock.Unlock()

	for len(c.idleSessions) > 0 {
		session := c.idleSessions[0]
		c.idleSessions = c.idleSessions[1:]
		if session != nil && !session.IsClosed() {
			return session
		}
	}

	return nil
}

func (c *Client) createSession() (*Session, error) {
	underlying, err := c.dialOut()
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		c.idleSessionLock.Lock()
		filtered := c.idleSessions[:0]
		for _, idle := range c.idleSessions {
			if idle != session {
				filtered = append(filtered, idle)
			}
		}
		c.idleSessions = filtered
		c.idleSessionLock.Unlock()

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) idleCleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.idleCleanup(time.Now().Add(-c.idleSessionTimeout))
		case <-c.stopCleanup:
			return
		}
	}
}

func (c *Client) idleCleanup(expireBefore time.Time) {
	var toClose []*Session

	c.idleSessionLock.Lock()
	activeCount := 0
	kept := c.idleSessions[:0]
	for _, session := range c.idleSessions {
		if session == nil || session.IsClosed() {
			continue
		}
		if !session.idleSince.Before(expireBefore) {
			activeCount++
			kept = append(kept, session)
			continue
		}
		if activeCount < max(c.minIdleSession, 0) {
			activeCount++
			session.idleSince = time.Now()
			kept = append(kept, session)
			continue
		}
		toClose = append(toClose, session)
	}
	c.idleSessions = kept
	c.idleSessionLock.Unlock()

	for _, session := range toClose {
		session.Close()
	}
}

func max(a, b int) int {
	return int(math.Max(float64(a), float64(b)))
}
