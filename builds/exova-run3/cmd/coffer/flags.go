package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Flags use the stdlib `flag` package with hand-written subcommand trees. The
// only thing added here is argument reordering, because the spec's synopsis
// interleaves positionals and flags (`coffer secrets get KEY -p P -e E`) while
// the stdlib parser stops at the first positional.

// stringOpt records whether a string flag was supplied, which matters when an
// empty value is a valid-but-explicit choice.
type stringOpt struct {
	value string
	set   bool
}

func (o *stringOpt) String() string { return o.value }

func (o *stringOpt) Set(s string) error {
	o.value = s
	o.set = true
	return nil
}

// intOpt is a non-negative integer flag such as --limit, --version or --to.
type intOpt struct {
	value int64
	set   bool
}

func (o *intOpt) String() string { return "" }

func (o *intOpt) Set(s string) error {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return errors.New("must be an integer")
	}
	if v < 0 {
		return errors.New("must not be negative")
	}
	o.value = v
	o.set = true
	return nil
}

// boolOpt records whether a boolean flag was supplied.
type boolOpt struct {
	value bool
	set   bool
}

func (o *boolOpt) String() string { return strconv.FormatBool(o.value) }

func (o *boolOpt) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return errors.New("must be true or false")
	}
	o.value = v
	o.set = true
	return nil
}

func (o *boolOpt) IsBoolFlag() bool { return true }

// newFlagSet builds a silent flag set; usage text is handled by the caller so
// every error message stays on stderr and every help page on stdout.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseFlags parses args after reordering them, so flags may appear before,
// between or after positionals. A bare `--` ends flag parsing and everything
// after it is positional.
//
// Errors are usage errors (exit 2) decided locally, and -h/--help is a success
// that prints the flag defaults to helpOut.
func parseFlags(fs *flag.FlagSet, args []string, helpOut io.Writer) error {
	fs.SetOutput(io.Discard)
	reordered := reorderFlags(fs, args)
	if err := fs.Parse(reordered); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintf(helpOut, "Usage of %s:\n", fs.Name())
			fs.SetOutput(helpOut)
			fs.PrintDefaults()
			fs.SetOutput(io.Discard)
			return errHelp
		}
		return usagef("%v", err)
	}
	fs.SetOutput(io.Discard)
	return nil
}

// reorderFlags moves registered flags (and their values) ahead of positionals.
//
// The order matters: flag.Parse stops at the first non-flag argument, so flags
// must come first and the positionals last, which is what lets
// `coffer secrets get KEY -p P -e E` parse.
func reorderFlags(fs *flag.FlagSet, args []string) []string {
	positional := make([]string, 0, len(args))
	flags := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' || a == "-" {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.ContainsRune(name, '=') {
			// --flag=value carries its own value.
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			// Unknown flag: leave it for flag.Parse to reject as a usage error.
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// requireArgs checks the positional count for a subcommand.
func requireArgs(fs *flag.FlagSet, want int, synopsis string) error {
	got := fs.NArg()
	if got == want {
		return nil
	}
	if got < want {
		return usagef("missing argument: expected `coffer %s`", synopsis)
	}
	return usagef("unexpected argument %q: expected `coffer %s`", fs.Arg(want), synopsis)
}

func requireNoArgs(fs *flag.FlagSet, synopsis string) error {
	if fs.NArg() > 0 {
		return usagef("unexpected argument %q: expected `coffer %s`", fs.Arg(0), synopsis)
	}
	return nil
}

// requiredString returns a flag's value or a usage error naming it.
func requiredString(fs *flag.FlagSet, opt *stringOpt, name, synopsis string) (string, error) {
	if !opt.set || opt.value == "" {
		return "", usagef("missing required flag %s: expected `coffer %s`", name, synopsis)
	}
	return opt.value, nil
}

// secretScope is the -p/-e pair shared by every secret command.
type secretScope struct {
	project stringOpt
	env     stringOpt
}

func (s *secretScope) register(fs *flag.FlagSet) {
	fs.Var(&s.project, "p", "project slug")
	fs.Var(&s.project, "project", "project slug")
	fs.Var(&s.env, "e", "environment slug")
	fs.Var(&s.env, "env", "environment slug")
}

// requireProject validates just -p/--project, for the commands that are scoped to
// a project but not to one environment (env create, grant set, grant revoke).
func (s *secretScope) requireProject(synopsis string) (string, error) {
	project, err := requiredString(nil, &s.project, "-p/--project", synopsis)
	if err != nil {
		return "", err
	}
	if err := validateSlug("project slug", project); err != nil {
		return "", err
	}
	return project, nil
}

// require validates both slugs locally, so a bad slug exits 2 before a request.
func (s *secretScope) require(synopsis string) (string, string, error) {
	project, err := requiredString(nil, &s.project, "-p/--project", synopsis)
	if err != nil {
		return "", "", err
	}
	if err := validateSlug("project slug", project); err != nil {
		return "", "", err
	}
	env, err := requiredString(nil, &s.env, "-e/--env", synopsis)
	if err != nil {
		return "", "", err
	}
	if err := validateSlug("environment slug", env); err != nil {
		return "", "", err
	}
	return project, env, nil
}
