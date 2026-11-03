package store

import (
	"os"
	"path/filepath"
)

// readSource returns the text of a file in this package, so a test can assert on
// source-level invariants that are cheap to check and easy to regress.
func readSource(name string) (string, error) {
	body, err := os.ReadFile(filepath.Join(".", name))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
