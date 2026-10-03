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
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/xyfu/xnux-agent/internal/app"
	"github.com/xyfu/xnux-agent/internal/cli"
	"github.com/xyfu/xnux-agent/internal/ipc"
)

// Set at build time via -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "unknown"
)

// With transparent huge pages set to "always", 2 MB pages back a heap of a
// few MB and the daemon's resident set grows by several MB. The runtime's
// GODEBUG=disablethp=1 avoids that but is read only at startup, so the
// daemon re-executes itself once with it set.
func init() {
	if len(os.Args) > 1 && os.Args[1] == "cli" || filepath.Base(os.Args[0]) == "xnux" {
		return
	}
	godebug := os.Getenv("GODEBUG")
	if strings.Contains(godebug, "disablethp") {
		return
	}
	if b, err := os.ReadFile("/sys/kernel/mm/transparent_hugepage/enabled"); err != nil || !strings.Contains(string(b), "[always]") {
		return
	}
	if godebug != "" {
		godebug += ","
	}
	// The binary's own path, not /proc/self/exe: the process name (comm)
	// comes from it and must stay "xnux-agent". A binary replaced by an
	// upgrade reads as "… (deleted)" and fails to exec; it then runs as is.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	env := append(os.Environ(), "GODEBUG="+godebug+"disablethp=1")
	_ = syscall.Exec(exe, os.Args, env) //nolint:gosec // this same binary
}

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
	// Installed as /usr/local/bin/xnux-agent with a symlink xnux: called as
	// "xnux" (or "xnux-agent cli …") it is the local CLI (spec v1.1 delta 2).
	if filepath.Base(os.Args[0]) == "xnux" {
		os.Exit(runCLI(os.Args[1:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "cli" {
		os.Exit(runCLI(os.Args[2:]))
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
	printConfig := fs.Bool("print-config", false, "print the effective config (agent key masked)")
	check := fs.Bool("check", false, "self-check collectors and endpoint reachability")
	stateDir := fs.String("state-dir", "/var/lib/xnux", "state and spool directory")
	logDir := fs.String("log-dir", "/var/log/xnux", "agent.log and mirror file directory")
	socket := fs.String("socket", envOr("XNUX_SOCKET", ipc.DefaultPath), "local socket the xnux CLI talks to")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: xnux-agent [run|version|cli …] [flags]\n\nflags:\n")
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
		Socket:      *socket,
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

func runCLI(args []string) int {
	intr := make(chan os.Signal, 1)
	signal.Notify(intr, syscall.SIGINT, syscall.SIGTERM)
	socket := envOr("XNUX_SOCKET", ipc.DefaultPath)
	conf := os.Getenv("XNUX_CONFIG")
	if conf == "" {
		conf = "/etc/xnux/agent.yaml"
	}
	lang := "en"
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			if strings.HasPrefix(v, "zh") {
				lang = "zh-CN"
			}
			break
		}
	}
	return cli.Run(args, cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin, Socket: socket, ConfigPath: conf,
		TTY: isTTY(os.Stdout), Lang: lang, Interrupt: intr, Width: func() int {
			ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
			if err != nil {
				return 0
			}
			return int(ws.Col)
		}})
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
