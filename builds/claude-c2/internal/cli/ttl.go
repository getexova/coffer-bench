package cli

import (
	"regexp"
	"strconv"
)

const (
	minTTLSeconds = 60
	maxTTLSeconds = 90 * 24 * 3600
)

var ttlRe = regexp.MustCompile(`^([0-9]{1,9})([smhd])$`)

// parseTTL parses <int><unit> (unit s, m, h or d) and enforces 1m..90d.
// Any invalid value is a validation error (exit 6) detected locally.
func parseTTL(s string) (int64, error) {
	m := ttlRe.FindStringSubmatch(s)
	if m == nil {
		return 0, validationErr("invalid --ttl %q: use <number><unit> with unit s, m, h or d (e.g. 30m, 12h, 7d)", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, validationErr("invalid --ttl %q", s)
	}
	mult := map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	secs := n * mult
	if secs < minTTLSeconds || secs > maxTTLSeconds {
		return 0, validationErr("--ttl must be between 1m and 90d, got %s", s)
	}
	return secs, nil
}
