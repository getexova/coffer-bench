package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"unicode/utf8"
)

const (
	maxPasswordBytes = 1024
	maxValueBytes    = 65536
)

func (a *App) stdinReader() *bufio.Reader {
	if a.stdinBuf == nil {
		a.stdinBuf = bufio.NewReader(a.Stdin)
	}
	return a.stdinBuf
}

// readPassword reads one line from stdin (trailing \n or \r\n stripped).
// On a TTY it prompts on stderr and disables echo while reading.
func (a *App) readPassword(prompt string) (string, error) {
	tty := a.StdinIsTTY()
	if tty {
		fmt.Fprint(a.Stderr, prompt)
		if f, ok := a.Stdin.(*os.File); ok {
			if restore, err := disableEcho(f); err == nil {
				sigs := make(chan os.Signal, 1)
				signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
				done := make(chan struct{})
				go func() {
					select {
					case <-sigs:
						restore()
						fmt.Fprintln(a.Stderr)
						os.Exit(130)
					case <-done:
					}
				}()
				defer func() {
					signal.Stop(sigs)
					close(done)
					restore()
					fmt.Fprintln(a.Stderr)
				}()
			}
		}
	}
	line, err := a.readLine()
	if err != nil {
		return "", err
	}
	if line == "" {
		return "", usageErr("", "empty password on stdin")
	}
	if len(line) > maxPasswordBytes {
		return "", validationErr("password longer than %d bytes", maxPasswordBytes)
	}
	if !utf8.ValidString(line) {
		return "", validationErr("password is not valid UTF-8")
	}
	return line, nil
}

func (a *App) readLine() (string, error) {
	r := a.stdinReader()
	var buf []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		buf = append(buf, chunk...)
		if len(buf) > maxPasswordBytes+2 {
			return "", validationErr("password longer than %d bytes", maxPasswordBytes)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if len(buf) == 0 {
					return "", usageErr("", "expected a password on stdin")
				}
				return string(buf), nil
			}
			return "", genericErr("cannot read stdin: %v", err)
		}
		if !isPrefix {
			return string(buf), nil
		}
	}
}

// readValue reads stdin to EOF, byte-exact, for `secrets set KEY`.
func (a *App) readValue() (string, error) {
	if a.StdinIsTTY() {
		fmt.Fprintln(a.Stderr, "reading value from stdin; end with Ctrl-D")
	}
	data, err := io.ReadAll(io.LimitReader(a.stdinReader(), maxValueBytes+1))
	if err != nil {
		return "", genericErr("cannot read stdin: %v", err)
	}
	if len(data) > maxValueBytes {
		return "", validationErr("value exceeds %d bytes", maxValueBytes)
	}
	if !utf8.Valid(data) {
		return "", validationErr("value is not valid UTF-8")
	}
	return string(data), nil
}
