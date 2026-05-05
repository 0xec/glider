package stats

import (
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type trafficEntry struct {
	sourceIP string
	upload   atomic.Uint64
	down     atomic.Uint64
	seenUnix atomic.Int64
}

// TrafficSnapshot is the serialized view of per-source traffic counters.
type TrafficSnapshot struct {
	SourceIP      string `json:"source_ip"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
	TotalBytes    uint64 `json:"total_bytes"`
	UpdatedAt     string `json:"updated_at"`
}

var trafficEntries sync.Map

// SourceIP extracts an IP-only key from a network address.
func SourceIP(addr net.Addr) string {
	switch value := addr.(type) {
	case *net.TCPAddr:
		if value != nil && value.IP != nil {
			return value.IP.String()
		}
	case *net.UDPAddr:
		if value != nil && value.IP != nil {
			return value.IP.String()
		}
	case *net.IPAddr:
		if value != nil && value.IP != nil {
			return value.IP.String()
		}
	}

	if addr == nil {
		return ""
	}

	raw := strings.TrimSpace(addr.String())
	if raw == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}

	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")

	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}

	return ""
}

// AddUpload records upstream traffic from the source IP.
func AddUpload(sourceIP string, bytes int) {
	add(sourceIP, bytes, true)
}

// AddDownload records downstream traffic to the source IP.
func AddDownload(sourceIP string, bytes int) {
	add(sourceIP, bytes, false)
}

func add(sourceIP string, bytes int, upload bool) {
	if sourceIP == "" || bytes <= 0 {
		return
	}

	entry := getEntry(sourceIP)
	if upload {
		entry.upload.Add(uint64(bytes))
	} else {
		entry.down.Add(uint64(bytes))
	}
	entry.seenUnix.Store(time.Now().Unix())
}

func getEntry(sourceIP string) *trafficEntry {
	if value, ok := trafficEntries.Load(sourceIP); ok {
		return value.(*trafficEntry)
	}

	entry := &trafficEntry{sourceIP: sourceIP}
	entry.seenUnix.Store(time.Now().Unix())
	actual, _ := trafficEntries.LoadOrStore(sourceIP, entry)
	return actual.(*trafficEntry)
}

// Snapshot returns all traffic records sorted by total bytes descending.
func Snapshot() []TrafficSnapshot {
	records := make([]TrafficSnapshot, 0)
	trafficEntries.Range(func(_, value any) bool {
		entry := value.(*trafficEntry)
		upload := entry.upload.Load()
		down := entry.down.Load()
		seenUnix := entry.seenUnix.Load()

		record := TrafficSnapshot{
			SourceIP:      entry.sourceIP,
			UploadBytes:   upload,
			DownloadBytes: down,
			TotalBytes:    upload + down,
		}
		if seenUnix > 0 {
			record.UpdatedAt = time.Unix(seenUnix, 0).Format(time.RFC3339)
		}
		records = append(records, record)
		return true
	})

	sort.Slice(records, func(i, j int) bool {
		if records[i].TotalBytes != records[j].TotalBytes {
			return records[i].TotalBytes > records[j].TotalBytes
		}
		if records[i].DownloadBytes != records[j].DownloadBytes {
			return records[i].DownloadBytes > records[j].DownloadBytes
		}
		return records[i].SourceIP < records[j].SourceIP
	})

	return records
}
