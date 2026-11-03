// Command coffer-server runs the Coffer HTTP API.
//
//	coffer-server              run the server (configuration from the environment)
//	coffer-server healthcheck  exit 0 if /readyz answers 200 on the local listener
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coffer-dev/coffer/internal/server/app"
	"github.com/coffer-dev/coffer/internal/server/config"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(healthcheck())
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stderr, "usage: coffer-server [healthcheck]\nConfiguration is read from environment variables; see .env.example.")
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "usage: coffer-server [healthcheck]\n")
			os.Exit(2)
		}
	}
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	log := app.NewLogger(os.Stdout)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	os.Exit(app.Run(ctx, cfg, log))
}

// healthcheck is used as the container HEALTHCHECK (the runtime image has no
// shell or curl).
func healthcheck() int {
	port := "8420"
	if addr := os.Getenv("COFFER_LISTEN_ADDR"); addr != "" {
		if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
			port = p
		}
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/readyz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "not ready:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "not ready: status", resp.StatusCode)
		return 1
	}
	return 0
}
