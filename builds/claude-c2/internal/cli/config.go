package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const defaultURL = "http://127.0.0.1:8420"

// config is the on-disk CLI configuration (CONTRACT §6).
type config struct {
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
}

// configDir returns ${XDG_CONFIG_HOME:-$HOME/.config}/coffer.
func (a *App) configDir() (string, error) {
	if x, ok := a.env("XDG_CONFIG_HOME"); ok && x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "coffer"), nil
	}
	home, ok := a.env("HOME")
	if !ok || home == "" {
		h, err := os.UserHomeDir()
		if err != nil || h == "" {
			return "", genericErr("cannot determine config directory: HOME is not set")
		}
		home = h
	}
	return filepath.Join(home, ".config", "coffer"), nil
}

func (a *App) configPath() (string, error) {
	d, err := a.configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.json"), nil
}

// envToken returns COFFER_TOKEN if it is set (even if empty).
func (a *App) envToken() (string, bool) {
	v, ok := a.env("COFFER_TOKEN")
	if !ok {
		return "", false
	}
	return strings.TrimSpace(v), true
}

// loadConfig reads the config file. It must never be called when COFFER_TOKEN
// is set. A missing file yields an empty config.
func (a *App) loadConfig() (*config, error) {
	if _, ok := a.envToken(); ok {
		return &config{}, nil // defensive: never touch the file
	}
	p, err := a.configPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &config{}, nil
		}
		return nil, genericErr("cannot read config file %s: %v", p, pathErrReason(err))
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, genericErr("config file %s is not valid JSON", p)
	}
	if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(a.Stderr, "warning: config file %s is accessible by other users (mode %04o); expected 0600\n", p, fi.Mode().Perm())
	}
	return &c, nil
}

// saveConfig atomically writes the config file with mode 0600 inside a 0700
// directory. It must never be called when COFFER_TOKEN is set.
func (a *App) saveConfig(c *config) error {
	if _, ok := a.envToken(); ok {
		return genericErr("refusing to write config while COFFER_TOKEN is set")
	}
	dir, err := a.configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return genericErr("cannot create config directory %s: %v", dir, pathErrReason(err))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return genericErr("cannot set mode on %s: %v", dir, pathErrReason(err))
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return genericErr("cannot encode config")
	}
	data = append(data, '\n')

	f, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	if err := f.Close(); err != nil {
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	final := filepath.Join(dir, "config.json")
	if err := os.Rename(tmp, final); err != nil {
		return genericErr("cannot write config: %v", pathErrReason(err))
	}
	ok = true
	_ = os.Chmod(final, 0o600)
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

func pathErrReason(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// normalizeURL validates a server base URL.
func normalizeURL(raw, source string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", usageErr("", "invalid server URL from %s: must be http(s)://host[:port][/path]", source)
	}
	if u.User != nil {
		return "", usageErr("", "invalid server URL from %s: credentials in the URL are not allowed", source)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", usageErr("", "invalid server URL from %s: query and fragment are not allowed", source)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// resolveURL applies: --url, COFFER_URL, config url, default.
// cfg may be nil (COFFER_TOKEN set or config not loaded).
func (a *App) resolveURL(flagURL string, cfg *config) (string, error) {
	if flagURL != "" {
		return normalizeURL(flagURL, "--url")
	}
	if v, ok := a.env("COFFER_URL"); ok && strings.TrimSpace(v) != "" {
		return normalizeURL(v, "COFFER_URL")
	}
	if cfg != nil && cfg.URL != "" {
		return normalizeURL(cfg.URL, "config file")
	}
	return defaultURL, nil
}
