package main

import (
	"io"
	"os"
)

// isTerminalFile reports whether w is a character device, i.e. a terminal.
//
// This is what decides whether `secrets get` appends a newline: through a pipe
// the exact value bytes are written and nothing else (SPEC §7.1). A writer that
// is not an *os.File (a buffer in a test, for example) counts as not a terminal.
func isTerminalFile(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
