//go:build linux

package cli

import (
	"os"
	"syscall"
	"unsafe"
)

func ioctlTermios(fd uintptr, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

// isTerminal reports whether f refers to a terminal (TCGETS succeeds).
// Unlike a ModeCharDevice check, /dev/null is correctly reported as not a TTY.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	var t syscall.Termios
	return ioctlTermios(f.Fd(), syscall.TCGETS, &t) == nil
}

// disableEcho turns off terminal echo on f and returns a function restoring
// the previous state. Best effort: errors are returned and may be ignored.
func disableEcho(f *os.File) (func(), error) {
	var t syscall.Termios
	if err := ioctlTermios(f.Fd(), syscall.TCGETS, &t); err != nil {
		return func() {}, err
	}
	old := t
	t.Lflag &^= syscall.ECHO
	t.Lflag |= syscall.ICANON
	if err := ioctlTermios(f.Fd(), syscall.TCSETS, &t); err != nil {
		return func() {}, err
	}
	return func() { _ = ioctlTermios(f.Fd(), syscall.TCSETS, &old) }, nil
}
