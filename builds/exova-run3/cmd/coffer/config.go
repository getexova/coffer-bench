package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The CLI's own config directory, fixed by SPEC §7.1:
// ${XDG_CONFIG_HOME:-$HOME/.config}/coffer/ with mode 0700, and a file inside
// with mode 0600. The PAT it stores is the single place §4 permits a plaintext
// credential.
const (
	configDirName  = "coffer"
	configFileName = "config.json"
	defaultBaseURL = "http://127.0.0.1:8420"

	dirMode  fs.FileMode = 0o700
	fileMode fs.FileMode = 0o600
)

// cliConfig is the resolved CLI configuration for one invocation.
type cliConfig struct {
	URL   string
	Token string

	// envToken records that COFFER_TOKEN supplied the credential. When it is
	// set, no config file is read or written, which is what makes the CLI
	// usable in CI.
	envToken bool

	// pathErr records why the config directory could not be located, so a save
	// can report it instead of failing obscurely.
	pathErr error
}

// configDir resolves ${XDG_CONFIG_HOME:-$HOME/.config}/coffer.
func configDir() (string, error) {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, configDirName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot locate a config directory: set XDG_CONFIG_HOME or HOME")
	}
	return filepath.Join(home, ".config", configDirName), nil
}

func configPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}

// configFile is the on-disk shape. It holds only the server URL and the CLI's
// own token.
type configFile struct {
	URL   string `json:"url,omitempty"`
	Token string `json:"token,omitempty"`
}

// loadConfig reads the CLI configuration. COFFER_URL and COFFER_TOKEN override
// whatever the file holds; with COFFER_TOKEN set the file is not read at all.
func loadConfig() (*cliConfig, error) {
	cfg := &cliConfig{}
	if t := strings.TrimSpace(os.Getenv("COFFER_TOKEN")); t != "" {
		cfg.Token = t
		cfg.envToken = true
	}
	if u := strings.TrimSpace(os.Getenv("COFFER_URL")); u != "" {
		cfg.URL = u
	}
	if cfg.envToken {
		// Stateless mode: no config file is read or written.
		return cfg, nil
	}

	path, err := configPath()
	if err != nil {
		cfg.pathErr = err
		return cfg, nil
	}
	data, err := readConfigFile(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return cfg, nil
	}
	var file configFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("the config file %s is not valid JSON: %w", path, err)
	}
	if cfg.URL == "" {
		cfg.URL = file.URL
	}
	if cfg.Token == "" {
		cfg.Token = file.Token
	}
	return cfg, nil
}

// readConfigFile returns nil bytes when the file does not exist. An existing
// file with looser permissions than 0600 is tightened, because it holds a
// credential.
func readConfigFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read the config file %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("the config path %s is a directory", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		// Best effort: a failure here is not fatal, the file is still readable.
		_ = os.Chmod(path, fileMode)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the config file %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("cannot read the config file %s: %w", path, err)
	}
	return data, nil
}

// save writes the config file with directory mode 0700 and file mode 0600. It is
// a no-op when COFFER_TOKEN supplied the credential.
func (c *cliConfig) save() error {
	if c.envToken {
		return nil
	}
	if c.pathErr != nil {
		return c.pathErr
	}
	dir, err := configDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("cannot create the config directory %s: %w", dir, err)
	}
	// MkdirAll leaves an existing directory's mode alone, so tighten it here.
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("cannot set mode 0700 on %s: %w", dir, err)
	}
	payload, err := json.MarshalIndent(configFile{URL: c.URL, Token: c.Token}, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot encode the config file: %w", err)
	}
	payload = append(payload, '\n')
	path := filepath.Join(dir, configFileName)
	if err := writeFileMode(path, payload, fileMode); err != nil {
		return err
	}
	return nil
}

// clear removes the stored credential, keeping the server URL.
func (c *cliConfig) clear() error {
	if c.envToken {
		return nil
	}
	c.Token = ""
	if c.pathErr != nil {
		return c.pathErr
	}
	return c.save()
}

// writeFileMode writes atomically with the given mode: a temporary file in the
// same directory, then a rename. A reader never sees a half-written credential.
func writeFileMode(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".coffer-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot set mode %#o on %s: %w", mode, name, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	// Rename keeps the temp file's mode, but set it again so the result is
	// certain even on filesystems that do not carry the mode across.
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("cannot set mode %#o on %s: %w", mode, path, err)
	}
	return nil
}

// baseURL resolves the server URL: --url flag, then COFFER_URL, then the URL
// stored at login, then the local default.
func (c *cliConfig) baseURL(flagURL string) string {
	base := firstNonEmpty(flagURL, c.URL, defaultBaseURL)
	return strings.TrimRight(base, "/")
}

func (c *cliConfig) credential() string { return c.Token }
