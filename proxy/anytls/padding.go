package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	checkMark = -1
)

var defaultPaddingScheme = []byte(`stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

type PaddingFactory struct {
	scheme    map[string]string
	RawScheme []byte
	Stop      uint32
	Md5       string
}

var defaultPaddingFactory atomic.Pointer[PaddingFactory]

func init() {
	UpdatePaddingScheme(defaultPaddingScheme)
}

func UpdatePaddingScheme(rawScheme []byte) bool {
	padding := NewPaddingFactory(rawScheme)
	if padding == nil {
		return false
	}
	defaultPaddingFactory.Store(padding)
	return true
}

func NewPaddingFactory(rawScheme []byte) *PaddingFactory {
	scheme := stringMapFromBytes(rawScheme)
	if len(scheme) == 0 {
		return nil
	}

	stop, err := strconv.Atoi(scheme["stop"])
	if err != nil || stop <= 0 {
		return nil
	}

	rawCopy := append([]byte(nil), rawScheme...)
	return &PaddingFactory{
		scheme:    scheme,
		RawScheme: rawCopy,
		Stop:      uint32(stop),
		Md5:       fmt.Sprintf("%x", md5.Sum(rawCopy)),
	}
}

func loadPaddingFactory() *PaddingFactory {
	return defaultPaddingFactory.Load()
}

func (p *PaddingFactory) GenerateRecordPayloadSizes(pkt uint32) []int {
	if p == nil {
		return nil
	}

	raw, ok := p.scheme[strconv.Itoa(int(pkt))]
	if !ok {
		return nil
	}

	parts := strings.Split(raw, ",")
	sizes := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "c" {
			sizes = append(sizes, checkMark)
			continue
		}

		bounds := strings.SplitN(part, "-", 2)
		if len(bounds) != 2 {
			continue
		}

		minSize, err := strconv.ParseInt(bounds[0], 10, 64)
		if err != nil {
			continue
		}
		maxSize, err := strconv.ParseInt(bounds[1], 10, 64)
		if err != nil {
			continue
		}

		if minSize > maxSize {
			minSize, maxSize = maxSize, minSize
		}
		if minSize <= 0 || maxSize <= 0 {
			continue
		}

		if minSize == maxSize {
			sizes = append(sizes, int(minSize))
			continue
		}

		delta, err := rand.Int(rand.Reader, big.NewInt(maxSize-minSize+1))
		if err != nil {
			sizes = append(sizes, int(minSize))
			continue
		}
		sizes = append(sizes, int(minSize+delta.Int64()))
	}

	return sizes
}
