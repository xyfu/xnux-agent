// Package cli is the "xnux" command (spec v1.1 delta 2): a terminal view
// of the local black box, talking to the running agent over its Unix
// socket. Every command takes --json.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/xyfu/xnux-agent/internal/ipc"
)

const usage = `xnux — the Xnux agent's local black box

  xnux top                      live panel: CPU, load, memory, swap, disks, temperature,
                                top processes, recent events and the health score
  xnux events [--type T,…] [--since 24h] [--severity P0,…] [--limit N]
                                events recorded on this machine (kept 30 days)
  xnux event ID                 one event in full: exit code, signal, log tail,
                                processes and the 10 minutes before it
  xnux history [--metric cpu,mem,…] [--hours 24]
                                the last 24 hours as terminal charts
  xnux status                   collectors, mode (standalone or connected), health
  xnux payload [--last|--next]  what was last uploaded, or what would be next
  xnux connect --token xat_… [--endpoint URL]
                                start uploading to Xnux (needs root)
  xnux disconnect               stop uploading, keep recording locally (needs root)

Every command takes --json. Without root, join the "xnux" group.
`

// Env is what the commands need from the outside world.
type Env struct {
	Stdout, Stderr io.Writer
	Stdin          io.Reader
	Socket         string
	ConfigPath     string
	TTY            bool
	Width          func() int
	Lang           string
	Interrupt      <-chan os.Signal
}

// Run executes one command and returns the exit code.
func Run(args []string, env Env) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(env.Stdout, usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "top":
		err = top(rest, env)
	case "events":
		err = events(rest, env)
	case "event":
		err = event(rest, env)
	case "history":
		err = history(rest, env)
	case "status":
		err = status(rest, env)
	case "payload":
		err = payload(rest, env)
	case "connect":
		err = connect(rest, env)
	case "disconnect":
		err = disconnect(rest, env)
	default:
		fmt.Fprintf(env.Stderr, "xnux: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, "xnux:", err)
		return 1
	}
	return 0
}

func newFlags(name string, env Env) (*flag.FlagSet, *bool) {
	fs := flag.NewFlagSet("xnux "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs, fs.Bool("json", false, "print JSON")
}

func call(env Env, cmd string, args, out any) error {
	c, err := ipc.Dial(env.Socket)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(cmd, args, out)
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSince accepts 90m, 24h, 7d.
func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 24 * time.Hour, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if _, err := fmt.Sscan(d, &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("--since: %q is not a duration", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--since: %q is not a duration (e.g. 90m, 24h, 7d)", s)
	}
	return d, nil
}
