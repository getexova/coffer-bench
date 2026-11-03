package main

import (
	"errors"
	"fmt"
	"net/http"
)

// usageError is a locally decided usage failure: exit 2, decided without any
// network call (SPEC §7.1).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

// apiError is a non-2xx response from the server. The message is the stable,
// generic text from docs/CONTRACTS.md §2 and never contains a value or a token.
type apiError struct {
	Status  int
	Code    string
	Message string

	// Hint overrides the generic per-status hint for a command where the generic
	// one would be misleading. A 401 from `passwd` means the *current password*
	// is wrong, not that the caller needs to log in again.
	Hint string
}

func (e *apiError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s (HTTP %d)", msg, e.Status)
}

// exitError carries an explicit exit code and a message for stderr.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// silentError carries an explicit exit code with nothing further to print: the
// command has already written its outcome to stdout.
type silentError struct{ code int }

func (e *silentError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// errHelp means -h/--help was requested; it exits 0.
var errHelp = errors.New("help requested")

// statusExit maps an HTTP status onto the exit codes fixed by SPEC §7.1.
//
// 202 is checked first because it is the one 2xx that is not a plain success: a
// write to a protected environment is pending approval and exits 7.
func statusExit(status int) int {
	switch status {
	case http.StatusAccepted:
		return exitPending
	case http.StatusUnauthorized:
		return exitUnauthenticated
	case http.StatusForbidden:
		return exitForbidden
	case http.StatusNotFound:
		return exitNotFound
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		return exitValidation
	case http.StatusConflict:
		return exitConflict
	case http.StatusTooManyRequests:
		return exitRateLimited
	}
	if status >= 200 && status < 300 {
		return exitOK
	}
	return exitOther
}
