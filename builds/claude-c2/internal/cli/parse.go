package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// flagSpec describes one long flag.
type flagSpec struct {
	isBool bool
}

// knownFlags is the full set of long flags (CONTRACT §6). Global flags
// (--url, --json, --help) are accepted by every command.
var knownFlags = map[string]flagSpec{
	"url":            {},
	"json":           {isBool: true},
	"help":           {isBool: true},
	"project":        {},
	"env":            {},
	"version":        {},
	"expect-version": {},
	"to":             {},
	"format":         {},
	"access":         {},
	"ttl":            {},
	"name":           {},
	"status":         {},
	"limit":          {},
	"actor":          {},
	"action":         {},
	"since":          {},
	"role":           {},
	"level":          {},
	"owner-email":    {},
	"email":          {},
	"protected":      {isBool: true},
}

var shortFlags = map[string]string{
	"p": "project",
	"e": "env",
	"h": "help",
}

var globalFlags = map[string]bool{"url": true, "json": true, "help": true}

// command describes one CLI command.
type command struct {
	path     []string
	usage    string           // argument synopsis (after the path)
	help     string           // one-line description
	flags    []string         // allowed long flags besides the globals
	required []string         // required flags
	minArgs  int              // minimum positional arguments
	maxArgs  int              // maximum positional arguments; -1 = unlimited
	stopAt   bool             // stop flag parsing at the first positional (run)
	run      func(*ctx) error // implementation
}

func (c *command) name() string { return strings.Join(c.path, " ") }

func (c *command) usageLine() string {
	s := "coffer " + c.name()
	if c.usage != "" {
		s += " " + c.usage
	}
	return s
}

func (c *command) allows(flag string) bool {
	if globalFlags[flag] {
		return true
	}
	for _, f := range c.flags {
		if f == flag {
			return true
		}
	}
	return false
}

// parsed holds the result of flag parsing.
type parsed struct {
	flags map[string]string
	args  []string
}

// parseFlags parses tokens (everything after the command path, with global
// flags possibly interleaved) for command c.
func parseFlags(c *command, tokens []string) (*parsed, error) {
	p := &parsed{flags: map[string]string{}}
	usage := c.usageLine()
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		if t == "--" {
			p.args = append(p.args, tokens[i+1:]...)
			break
		}
		if len(t) < 2 || t[0] != '-' {
			p.args = append(p.args, t)
			if c.stopAt {
				p.args = append(p.args, tokens[i+1:]...)
				break
			}
			continue
		}
		var name, value string
		hasValue := false
		if strings.HasPrefix(t, "--") {
			name = t[2:]
			if k := strings.IndexByte(name, '='); k >= 0 {
				name, value, hasValue = name[:k], name[k+1:], true
			}
		} else {
			short := t[1:]
			if k := strings.IndexByte(short, '='); k >= 0 {
				short, value, hasValue = short[:k], short[k+1:], true
			}
			long, ok := shortFlags[short]
			if !ok {
				return nil, usageErr(usage, "unknown flag %s", t)
			}
			name = long
		}
		spec, ok := knownFlags[name]
		if !ok || !c.allows(name) {
			return nil, usageErr(usage, "unknown flag --%s", name)
		}
		if spec.isBool {
			if hasValue {
				b, err := strconv.ParseBool(value)
				if err != nil {
					return nil, usageErr(usage, "invalid value for --%s: %q", name, value)
				}
				value = strconv.FormatBool(b)
			} else {
				value = "true"
			}
		} else if !hasValue {
			if i+1 >= len(tokens) {
				return nil, usageErr(usage, "flag --%s requires a value", name)
			}
			i++
			value = tokens[i]
		}
		p.flags[name] = value
	}
	if p.flags["help"] == "true" {
		return p, nil
	}
	for _, r := range c.required {
		if v, ok := p.flags[r]; !ok || v == "" {
			return nil, usageErr(usage, "missing required flag --%s", r)
		}
	}
	for name, v := range p.flags {
		if v == "" && !knownFlags[name].isBool {
			return nil, usageErr(usage, "flag --%s requires a non-empty value", name)
		}
	}
	if len(p.args) < c.minArgs {
		return nil, usageErr(usage, "missing argument")
	}
	if c.maxArgs >= 0 && len(p.args) > c.maxArgs {
		return nil, usageErr(usage, "unexpected argument %q", p.args[c.maxArgs])
	}
	return p, nil
}

// resolve finds the command named by the leading non-flag tokens of args.
// Global flags (and their values) may precede or be interleaved with the
// command words. It returns the command and the remaining tokens.
func resolve(args []string) (*command, []string, error) {
	var words []string
	var rest []string
	var cmd *command
	i := 0
	for ; i < len(args); i++ {
		t := args[i]
		if t == "--" {
			break
		}
		if strings.HasPrefix(t, "-") && len(t) > 1 {
			// Known flags may precede the command words; parseFlags later
			// checks that the resolved command accepts them.
			name := strings.TrimLeft(t, "-")
			if k := strings.IndexByte(name, '='); k >= 0 {
				name = name[:k]
			}
			if long, ok := shortFlags[name]; ok && !strings.HasPrefix(t, "--") {
				name = long
			}
			if _, known := knownFlags[name]; !known {
				break
			}
			rest = append(rest, t)
			if !knownFlags[name].isBool && !strings.Contains(t, "=") && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		cand := append(append([]string{}, words...), t)
		if c := findCommand(cand); c != nil {
			words, cmd = cand, c
			continue
		}
		if hasPrefix(cand) {
			words = cand
			continue
		}
		break
	}
	if cmd == nil || len(words) != len(cmd.path) {
		return nil, nil, &resolveError{words: words, next: at(args, i)}
	}
	rest = append(rest, args[i:]...)
	return cmd, rest, nil
}

type resolveError struct {
	words []string
	next  string
}

func (e *resolveError) Error() string {
	if len(e.words) == 0 {
		if e.next == "" {
			return "missing command"
		}
		return fmt.Sprintf("unknown command %q", e.next)
	}
	if e.next == "" || strings.HasPrefix(e.next, "-") {
		return fmt.Sprintf("missing subcommand for %q", strings.Join(e.words, " "))
	}
	return fmt.Sprintf("unknown command %q", strings.Join(append(e.words, e.next), " "))
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return ""
}

func findCommand(words []string) *command {
	for _, c := range commands {
		if equalPath(c.path, words) {
			return c
		}
	}
	return nil
}

func hasPrefix(words []string) bool {
	for _, c := range commands {
		if len(c.path) > len(words) && equalPath(c.path[:len(words)], words) {
			return true
		}
	}
	return false
}

func equalPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
