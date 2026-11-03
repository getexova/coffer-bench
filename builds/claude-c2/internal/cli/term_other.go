//go:build !linux

package cli

import (
	"errors"
	"os"
)

func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func disableEcho(f *os.File) (func(), error) {
	return func() {}, errors.New("echo control not supported on this platform")
}
