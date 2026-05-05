package log

import (
	"bytes"
	"fmt"
	"io"
	stdlog "log"
	"os"
	"sync"
)

var enable = false

const defaultBufferSize = 1000

var buffer = newRingBuffer(defaultBufferSize)
var requestBuffer = newRingBuffer(defaultBufferSize)

type teeWriter struct {
	target  io.Writer
	mu      sync.Mutex
	partial bytes.Buffer
}

type ringBuffer struct {
	mu      sync.RWMutex
	entries []string
	next    int
	count   int
}

func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = defaultBufferSize
	}

	return &ringBuffer{entries: make([]string, size)}
}

func (w *teeWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.partial.Write(p)
	for {
		line, err := w.partial.ReadString('\n')
		if err != nil {
			w.partial.WriteString(line)
			break
		}
		buffer.add(line)
	}

	return w.target.Write(p)
}

func (b *ringBuffer) add(line string) {
	line = string(bytes.TrimRight([]byte(line), "\r\n"))
	if line == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.next] = line
	b.next = (b.next + 1) % len(b.entries)
	if b.count < len(b.entries) {
		b.count++
	}
}

func isRequestLogLine(line string) bool {
	return bytes.Contains([]byte(line), []byte("<->"))
}

func (b *ringBuffer) recent(limit int) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > b.count {
		limit = b.count
	}

	logs := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (b.next - 1 - i + len(b.entries)) % len(b.entries)
		logs = append(logs, b.entries[idx])
	}

	return logs
}

func init() {
	stdlog.SetOutput(&teeWriter{target: os.Stderr})
}

// Set sets the logger's verbose mode and output flags.
func Set(verbose bool, flag int) {
	enable = verbose
	stdlog.SetFlags(flag)
}

// Recent returns the latest log lines in reverse chronological order.
func Recent(limit int) []string {
	return buffer.recent(limit)
}

// RequestRecent returns the latest request log lines in reverse chronological order.
func RequestRecent(limit int) []string {
	return requestBuffer.recent(limit)
}

// F prints debug log.
func F(f string, v ...any) {
	line := fmt.Sprintf(f, v...)
	if isRequestLogLine(line) {
		requestBuffer.add(line)
	}

	if enable {
		stdlog.Output(2, line)
	}
}

// Print prints log.
func Print(v ...any) {
	stdlog.Print(v...)
}

// Printf prints log.
func Printf(f string, v ...any) {
	stdlog.Printf(f, v...)
}

// Fatal log and exit.
func Fatal(v ...any) {
	stdlog.Fatal(v...)
}

// Fatalf log and exit.
func Fatalf(f string, v ...any) {
	stdlog.Fatalf(f, v...)
}
