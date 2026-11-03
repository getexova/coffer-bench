// Command coffer is the command-line client for the Coffer secrets service.
package main

import (
	"os"

	"github.com/coffer-dev/coffer/internal/cli"
)

func main() {
	os.Exit(cli.New().Run(os.Args[1:]))
}
