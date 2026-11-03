package main

import (
	"bufio"
	"io"
	"strings"
)

// inputReader owns stdin for one invocation.
//
// It is careful about two different reads that the spec distinguishes:
//   - passwords are read as ONE line, so an interactive `coffer login` returns
//     as soon as the password is typed instead of waiting for EOF;
//   - `secrets set KEY` with no VALUE reads to EOF and the bytes are exact, so a
//     piped file round-trips byte for byte.
//
// A buffered reader cannot be replayed, so a command that already consumed a
// password line refuses to also read a value from the same stdin rather than
// silently truncating it.
type inputReader struct {
	r         *bufio.Reader
	lineTaken bool
}

func newInputReader(r io.Reader) *inputReader {
	if br, ok := r.(*bufio.Reader); ok {
		return &inputReader{r: br}
	}
	return &inputReader{r: bufio.NewReaderSize(r, 4096)}
}

// line reads one line without its terminator. It never blocks for a second
// line: the first newline ends the read.
func (in *inputReader) line() (string, error) {
	s, err := in.r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	if s == "" {
		if err == io.EOF {
			return "", io.EOF
		}
		return "", nil
	}
	in.lineTaken = true
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s, nil
}

// password reads a password line. An empty password is always a usage error:
// SPEC §4 requires at least 12 characters, and a password is never accepted in
// argv.
func (in *inputReader) password(what string) (string, error) {
	s, err := in.line()
	if err != nil && err != io.EOF {
		return "", err
	}
	if s == "" {
		return "", usagef("%s is empty: pipe it on stdin (passwords are never accepted in argv)", what)
	}
	return s, nil
}

// rest reads every remaining byte with no trimming at all.
func (in *inputReader) rest() ([]byte, error) {
	if in.lineTaken {
		return nil, usagef("stdin was already read for a password; pipe the value on stdin instead of both")
	}
	data, err := io.ReadAll(in.r)
	if err != nil {
		return nil, usagef("cannot read stdin: %v", err)
	}
	return data, nil
}
