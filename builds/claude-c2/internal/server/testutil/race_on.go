//go:build race

package testutil

// Race reports whether the race detector is enabled (timing assertions are
// relaxed under -race).
const Race = true
