// Command xnux-agent is the Xnux probe: it collects metrics and events on a
// Linux host, redacts them locally and ships them outbound only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"

	"github.com/xyfu/xnux-agent/internal/app"
)

// Set at build time via -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	// Resource envelope (spec A1): small heap, two OS threads.
	if os.Getenv("GOMAXPROCS") == "" {
		runtime.GOMAXPROCS(2)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(12 << 20)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("xnux-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "/etc/xnux/agent.yaml", "config file path")
	dryRun := fs.Bool("dry-run", false, "collect and redact normally, print payloads to stdout, open no network connections")
	once := fs.Bool("once", false, "collect one round and exit")
	printConfig := fs.Bool("print-config", false, "print the effective config (token masked)")
	check := fs.Bool("check", false, "self-check collectors and endpoint reachability")
	stateDir := fs.String("state-dir", "/var/lib/xnux", "state and spool directory")
	logDir := fs.String("log-dir", "/var/log/xnux", "agent.log and mirror file directory")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: xnux-agent [run|version] [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}

	cmd := "run"
	if len(args) > 0 && (args[0] == "run" || args[0] == "version") {
		cmd, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cmd == "version" {
		fmt.Fprintf(stdout, "xnux-agent %s (commit %s, %s, %s/%s)\n",
			version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}

	err := app.Run(ctx, app.Options{
		ConfigPath:  *configPath,
		DryRun:      *dryRun,
		Once:        *once,
		PrintConfig: *printConfig,
		Check:       *check,
		Version:     version,
		StateDir:    *stateDir,
		LogDir:      *logDir,
		Stdout:      stdout,
		Stderr:      stderr,
		StdoutTTY:   isTTY(stdout),
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "xnux-agent:", err)
		return 1
	}
	return 0
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
