package anytls

import "strings"

func stringMapFromBytes(raw []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[key] = value
	}
	return result
}
