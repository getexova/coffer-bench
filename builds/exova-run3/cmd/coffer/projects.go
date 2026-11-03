package main

import (
	"fmt"
	"net/http"
)

// cmdProject dispatches `coffer project ...` (SPEC §7.1).
func (c *cli) cmdProject(args []string) error {
	if len(args) == 0 {
		return usagef("missing project command: expected `coffer project create|list`")
	}
	switch args[0] {
	case "create":
		return c.cmdProjectCreate(args[1:])
	case "list", "ls":
		return c.cmdProjectList(args[1:])
	default:
		return usagef("unknown project command %q: expected `coffer project create|list`", args[0])
	}
}

// cmdProjectCreate implements `coffer project create SLUG`.
func (c *cli) cmdProjectCreate(args []string) error {
	fs := newFlagSet("project create")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "project create SLUG"); err != nil {
		return err
	}
	slug := fs.Arg(0)
	if err := validateSlug("project slug", slug); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodPost, "/api/v1/projects", nil, map[string]string{"slug": slug})
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	fmt.Fprintf(c.stdout, "Created project %s\n", slug)
	return nil
}

// cmdProjectList implements `coffer project list`.
func (c *cli) cmdProjectList(args []string) error {
	fs := newFlagSet("project list")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "project list"); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/projects", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []projectRow
	if err := decodeList(resp.body, "projects", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		table = append(table, []string{r.Slug, r.ID, r.CreatedAt.String()})
	}
	return c.table([]string{"SLUG", "ID", "CREATED"}, table)
}

// cmdEnv dispatches `coffer env ...`.
func (c *cli) cmdEnv(args []string) error {
	if len(args) == 0 {
		return usagef("missing env command: expected `coffer env create|list`")
	}
	switch args[0] {
	case "create":
		return c.cmdEnvCreate(args[1:])
	case "list", "ls":
		return c.cmdEnvList(args[1:])
	default:
		return usagef("unknown env command %q: expected `coffer env create|list`", args[0])
	}
}

// cmdEnvCreate implements `coffer env create SLUG -p PROJECT [--protected]`.
func (c *cli) cmdEnvCreate(args []string) error {
	fs := newFlagSet("env create")
	var scope secretScope
	var protected boolOpt
	scope.register(fs)
	fs.Var(&protected, "protected", "require approval for writes")
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireArgs(fs, 1, "env create SLUG -p PROJECT [--protected]"); err != nil {
		return err
	}
	slug := fs.Arg(0)
	if err := validateSlug("environment slug", slug); err != nil {
		return err
	}
	project, err := scope.requireProject("env create SLUG -p PROJECT [--protected]")
	if err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	body := map[string]any{"slug": slug, "protected": protected.value}
	resp, err := cl.raw(http.MethodPost, "/api/v1/projects/"+escapePath(project)+"/envs", nil, body)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	if protected.value {
		fmt.Fprintf(c.stdout, "Created protected environment %s in %s\n", slug, project)
	} else {
		fmt.Fprintf(c.stdout, "Created environment %s in %s\n", slug, project)
	}
	return nil
}

// cmdEnvList implements `coffer env list -p PROJECT`.
func (c *cli) cmdEnvList(args []string) error {
	fs := newFlagSet("env list")
	var scope secretScope
	scope.register(fs)
	if err := parseFlags(fs, args, c.stdout); err != nil {
		return err
	}
	if err := requireNoArgs(fs, "env list -p PROJECT"); err != nil {
		return err
	}
	project, err := requiredString(fs, &scope.project, "-p/--project", "env list -p PROJECT")
	if err != nil {
		return err
	}
	if err := validateSlug("project slug", project); err != nil {
		return err
	}
	cl, err := c.authClient()
	if err != nil {
		return err
	}
	resp, err := cl.raw(http.MethodGet, "/api/v1/projects/"+escapePath(project)+"/envs", nil, nil)
	if err != nil {
		return err
	}
	if c.json {
		return c.printJSONBytes(resp.body)
	}
	var rows []envRow
	if err := decodeList(resp.body, "environments", &rows); err != nil {
		return fmt.Errorf("the server returned an unreadable response: %w", err)
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		protection := "no"
		if r.Protected {
			protection = "yes"
		}
		table = append(table, []string{r.Slug, r.ID, protection, r.CreatedAt.String()})
	}
	return c.table([]string{"SLUG", "ID", "PROTECTED", "CREATED"}, table)
}
