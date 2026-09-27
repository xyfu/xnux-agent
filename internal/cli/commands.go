package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xyfu/xnux-shared/health"
	"github.com/xyfu/xnux-shared/proto"

	"github.com/xyfu/xnux-agent/internal/collect"
	"github.com/xyfu/xnux-agent/internal/localhealth"
	"github.com/xyfu/xnux-agent/internal/localstore"
)

type topData struct {
	Metric   *proto.Metric      `json:"metric"`
	Events   []localstore.Event `json:"events"`
	Health   localhealth.Result `json:"health"`
	Cores    int                `json:"cores"`
	Hostname string             `json:"hostname"`
	Mode     string             `json:"mode"`
	TopCPU   []proto.Process    `json:"top_cpu"`
	TopRSS   []proto.Process    `json:"top_rss"`
	// Net are the interface counters now; top shows the rate between two
	// frames, 2 s apart (spec v1.1 delta 9.5).
	Net *collect.NetCounters `json:"net,omitempty"`
	// rate is that rate, or the sampled one on the first frame.
	rate *proto.Net
}

type statusData struct {
	Version         string             `json:"version"`
	Mode            string             `json:"mode"`
	Endpoint        string             `json:"endpoint"`
	UptimeS         int64              `json:"uptime_s"`
	Capabilities    []string           `json:"capabilities"`
	CollectorErrors map[string]int     `json:"collector_errors"`
	Host            map[string]any     `json:"host"`
	Storage         map[string]any     `json:"storage"`
	Health          localhealth.Result `json:"health"`
	RSSMB           float64            `json:"rss_mb"`
}

// ---- top ----

func top(args []string, env Env) error {
	fs, asJSON := newFlags("top", env)
	once := fs.Bool("once", false, "print one frame and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asJSON || !env.TTY {
		*once = true
	}
	var prev *collect.NetCounters
	for {
		var d topData
		if err := call(env, "top", nil, &d); err != nil {
			return err
		}
		if d.Metric != nil {
			d.rate = d.Metric.Net
		}
		if prev != nil && d.Net != nil {
			if n, ok := collect.NetRate(*prev, *d.Net); ok {
				d.rate = &n
			}
		}
		prev = d.Net
		if *asJSON {
			return printJSON(env.Stdout, d)
		}
		var b strings.Builder
		if !*once {
			b.WriteString("\033[H\033[2J") // home, clear
		}
		renderTop(&b, d, env)
		fmt.Fprint(env.Stdout, b.String())
		if *once {
			return nil
		}
		select {
		case <-env.Interrupt:
			fmt.Fprintln(env.Stdout)
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

func renderTop(b *strings.Builder, d topData, env Env) {
	w := 100
	if env.Width != nil {
		if x := env.Width(); x > 0 {
			w = x
		}
	}
	narrow := w < 80
	c := colors(env.TTY)
	fmt.Fprintf(b, "%sxnux top%s  %s  %s  %s\n", c.bold, c.reset, d.Hostname, d.Mode, time.Now().Format("15:04:05"))
	b.WriteString(healthLine(d.Health, c, env.Lang, narrow))
	m := d.Metric
	if m == nil {
		b.WriteString("\nwaiting for the first sample…\n")
		return
	}
	bar := func(label string, pct float64, extra string) {
		width := 30
		if narrow {
			width = max(10, w-36)
		}
		fmt.Fprintf(b, "%-8s %s %5.1f%% %s\n", label, meter(pct, width, c), pct, extra)
	}
	b.WriteString("\n")
	bar("CPU", m.CPU.TotalPct, fmt.Sprintf("iowait %.1f%%", m.CPU.IOWaitPct))
	load := fmt.Sprintf("load %.2f %.2f %.2f", m.Load.L1, m.Load.L5, m.Load.L15)
	if d.Cores > 0 {
		load += fmt.Sprintf("  (%d cores)", d.Cores)
	}
	fmt.Fprintf(b, "%-8s %s\n", "LOAD", load)
	bar("MEM", m.Mem.UsedPct, fmt.Sprintf("%d MB free of %d MB", m.Mem.AvailableMB, m.Mem.TotalMB))
	if m.Swap != nil && m.Swap.TotalMB > 0 {
		bar("SWAP", float64(m.Swap.UsedMB)/float64(m.Swap.TotalMB)*100, fmt.Sprintf("in %.0f/s", m.Swap.InPS))
	}
	for _, dk := range m.Disks {
		extra := fmt.Sprintf("%.1f GB free", dk.FreeGB)
		if dk.DaysToFull != nil {
			extra += fmt.Sprintf(", full in %.1f days", *dk.DaysToFull)
		}
		bar(trunc(dk.Mount, 8), dk.UsedPct, extra)
	}
	if n := d.rate; n != nil {
		fmt.Fprintf(b, "%-8s down %-11s up %s\n", "NET", collect.FormatBps(n.RxBps), collect.FormatBps(n.TxBps))
	}
	if len(m.Temps) > 0 {
		hot := m.Temps[0]
		for _, t := range m.Temps {
			if t.C > hot.C {
				hot = t
			}
		}
		fmt.Fprintf(b, "%-8s %.0f°C (%s)\n", "TEMP", hot.C, hot.Name)
	}
	procs := func(title string, list []proto.Process, val func(proto.Process) string) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(b, "\n%s%s%s\n", c.bold, title, c.reset)
		for i, p := range list {
			if i == 5 {
				break
			}
			cmd := p.Cmdline
			if cmd == "" {
				cmd = p.Comm
			}
			fmt.Fprintf(b, "  %7d %8s  %s\n", p.PID, val(p), trunc(cmd, max(20, w-22)))
		}
	}
	procs("Top CPU", d.TopCPU, func(p proto.Process) string { return fmt.Sprintf("%.1f%%", p.CPUPct) })
	if !narrow {
		procs("Top memory", d.TopRSS, func(p proto.Process) string { return fmt.Sprintf("%.0f MB", p.RSSMB) })
	}
	b.WriteString("\n" + c.bold + "Recent events" + c.reset + "\n")
	if len(d.Events) == 0 {
		b.WriteString("  none\n")
	}
	// The full ID, so it can be pasted into "xnux event"; the summary
	// takes whatever width is left.
	for _, e := range d.Events {
		line := fmt.Sprintf("  %s %s  %-16s ", sev(e.Severity, c), time.Unix(lastTS(e), 0).Format("01-02 15:04"), e.Type)
		if room := w - 38 - len(e.ID); !narrow && room >= 12 {
			line += fmt.Sprintf("%-*s ", room, trunc(summary(e), room))
		}
		b.WriteString(line + c.dim + e.ID + c.reset + "\n")
	}
	if !narrow {
		b.WriteString("\n" + c.dim + "Ctrl-C to quit · refreshes every 2 s" + c.reset + "\n")
	}
}

func healthLine(h localhealth.Result, c palette, lang string, narrow bool) string {
	if h.State != "scored" || h.Score == nil {
		return "health  collecting (scored after an hour of data)\n"
	}
	r := h.Score
	s := fmt.Sprintf("health  %s%s%d %s%s", c.bold, levelColor(r.Level, c), r.Score, r.Level, c.reset)
	var why []string
	if r.Cap != nil {
		why = append(why, fmt.Sprintf("capped at %d: %s", r.Cap.Limit, health.Describe(r.Cap.Item, 0, "", lang)))
	}
	for i, d := range r.Deductions {
		if i == 2 || (narrow && i == 1) {
			break
		}
		why = append(why, fmt.Sprintf("−%g %s", d.Deduct, health.Describe(d.Item, d.Value, d.Subject, lang)))
	}
	if len(why) > 0 {
		s += "  " + strings.Join(why, "; ")
	}
	return s + "\n"
}

func levelColor(level string, c palette) string {
	return map[string]string{health.LevelHealthy: c.green, health.LevelNotice: c.yellow, health.LevelRisk: c.orange, health.LevelCritical: c.red}[level]
}

// ---- events ----

func events(args []string, env Env) error {
	fs, asJSON := newFlags("events", env)
	types := fs.String("type", "", "event types, comma-separated (e.g. oom_kill,service_failed)")
	since := fs.String("since", "24h", "how far back (90m, 24h, 7d; up to 30d)")
	severity := fs.String("severity", "", "levels, comma-separated (P0,P1,P2,P3)")
	limit := fs.Int("limit", 50, "at most this many")
	if err := fs.Parse(args); err != nil {
		return err
	}
	d, err := parseSince(*since)
	if err != nil {
		return err
	}
	var list []localstore.Event
	if err := call(env, "events", map[string]any{"since_s": int64(d.Seconds()), "types": splitList(*types),
		"severity": splitList(strings.ToUpper(*severity)), "limit": *limit}, &list); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, list)
	}
	c := colors(env.TTY)
	if len(list) == 0 {
		fmt.Fprintln(env.Stdout, "no events")
		return nil
	}
	for _, e := range list {
		n := ""
		if e.Count > 1 {
			n = fmt.Sprintf(" ×%d", e.Count)
		}
		// The ID (fixed width) before the free-form summary keeps columns aligned.
		fmt.Fprintf(env.Stdout, "%s %s  %-18s %s  %s%s\n", sev(e.Severity, c), time.Unix(lastTS(e), 0).Format("2006-01-02 15:04:05"),
			e.Type, c.dim+e.ID+c.reset, summary(e), n)
	}
	return nil
}

// summary is one line about an event from its data.
func summary(e localstore.Event) string {
	var parts []string
	for _, k := range []string{"unit", "comm", "process", "user", "from", "ip", "device", "mount", "exit_code", "signal", "result"} {
		if v, ok := e.Data[k]; ok && v != nil && fmt.Sprint(v) != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

// ---- event ----

func event(args []string, env Env) error {
	fs, asJSON := newFlags("event", env)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: xnux event ID")
	}
	var d struct {
		Event  localstore.Event    `json:"event"`
		Before []localstore.Minute `json:"before"`
	}
	if err := call(env, "event", map[string]string{"id": fs.Arg(0)}, &d); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, d)
	}
	c := colors(env.TTY)
	e := d.Event
	w := env.Stdout
	fmt.Fprintf(w, "%s %s%s%s  %s\n", sev(e.Severity, c), c.bold, e.Type, c.reset, e.ID)
	fmt.Fprintf(w, "first  %s\n", time.Unix(e.TS, 0).Format(time.RFC3339))
	if e.LastTS > 0 && e.LastTS != e.TS {
		fmt.Fprintf(w, "last   %s (×%d)\n", time.Unix(e.LastTS, 0).Format(time.RFC3339), e.Count)
	}
	keys := make([]string, 0, len(e.Data))
	for k := range e.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := e.Data[k]
		switch x := v.(type) {
		case []any:
			fmt.Fprintf(w, "%s:\n", k)
			for _, line := range x {
				fmt.Fprintf(w, "  │ %v\n", line)
			}
		default:
			fmt.Fprintf(w, "%-12s %v\n", k, v)
		}
	}
	if sn := e.Snapshot; sn != nil {
		for _, l := range []struct {
			title string
			ps    []proto.Process
			val   func(proto.Process) string
		}{
			{"processes by memory", sn.TopRSS, func(p proto.Process) string { return fmt.Sprintf("%.0f MB", p.RSSMB) }},
			{"processes by CPU", sn.TopCPU, func(p proto.Process) string { return fmt.Sprintf("%.1f%%", p.CPUPct) }},
		} {
			if len(l.ps) == 0 {
				continue
			}
			fmt.Fprintf(w, "\n%s%s%s\n", c.bold, l.title, c.reset)
			for _, p := range l.ps {
				cmd := p.Cmdline
				if cmd == "" {
					cmd = p.Comm
				}
				fmt.Fprintf(w, "  %7d %8s  %s\n", p.PID, l.val(p), trunc(cmd, 90))
			}
		}
	}
	if len(d.Before) > 0 {
		fmt.Fprintf(w, "\n%sthe 10 minutes before%s\n", c.bold, c.reset)
		for _, def := range metricDefs {
			if contains([]string{"cpu", "mem", "load", "net"}, def.name) {
				series(w, def.label, d.Before, def.get, def.show, d.Before[0].TS, 60)
			}
		}
	}
	return nil
}

// ---- history ----

var metricDefs = []struct {
	name, label string
	get         func(localstore.Minute) *float64
	show        func(float64) string // default: one decimal
}{
	{"cpu", "cpu %", func(m localstore.Minute) *float64 { v := m.CPU; return &v }, nil},
	{"iowait", "iowait %", func(m localstore.Minute) *float64 { v := m.IOWait; return &v }, nil},
	{"load", "load1", func(m localstore.Minute) *float64 { v := m.Load1; return &v }, nil},
	{"mem", "mem %", func(m localstore.Minute) *float64 { v := m.MemUsed; return &v }, nil},
	{"swap", "swap MB", func(m localstore.Minute) *float64 { return m.SwapUsedMB }, nil},
	{"disk", "disk %", func(m localstore.Minute) *float64 { return m.DiskUsedMax }, nil},
	{"temp", "temp °C", func(m localstore.Minute) *float64 { return m.TempMax }, nil},
	{"net", "down", func(m localstore.Minute) *float64 { return m.NetRx }, bps},
	{"net", "up", func(m localstore.Minute) *float64 { return m.NetTx }, bps},
}

func bps(v float64) string { return collect.FormatBps(int64(v)) }

func history(args []string, env Env) error {
	fs, asJSON := newFlags("history", env)
	metrics := fs.String("metric", "cpu,mem,load,disk,net", "metrics: cpu, iowait, load, mem, swap, disk, temp, net")
	hours := fs.Int("hours", 24, "hours back (1–24)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var mins []localstore.Minute
	if err := call(env, "history", map[string]int{"hours": *hours}, &mins); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, mins)
	}
	if len(mins) == 0 {
		fmt.Fprintln(env.Stdout, "no history yet (one point per minute)")
		return nil
	}
	w := 100
	if env.Width != nil && env.Width() > 0 {
		w = env.Width()
	}
	// Columns are fixed time slices, so a stretch without data (agent
	// stopped, host down) shows as blank columns rather than being squeezed out.
	cols := max(20, w-30)
	start, end := mins[0].TS, mins[len(mins)-1].TS+60
	step := ((end-start)/int64(cols) + 59) / 60 * 60
	step = max(step, 60)
	fmt.Fprintf(env.Stdout, "%s → %s, one column = %s\n", time.Unix(start, 0).Format("01-02 15:04"),
		time.Unix(end, 0).Format("01-02 15:04"), time.Duration(step)*time.Second)
	want := splitList(*metrics)
	for _, def := range metricDefs {
		for _, n := range want {
			if n == def.name {
				series(env.Stdout, def.label, mins, def.get, def.show, start, step)
			}
		}
	}
	return nil
}

var blocks = []rune("▁▂▃▄▅▆▇█")

// series prints label, a sparkline with one column per step seconds from
// start (the worst value in each; blank where there is no data), and
// min / avg / max.
func series(w io.Writer, label string, mins []localstore.Minute, get func(localstore.Minute) *float64,
	show func(float64) string, start, step int64) {
	var cols []*float64
	lo, hi, sum, n := 0.0, 0.0, 0.0, 0
	for _, m := range mins {
		v := get(m)
		if v == nil {
			continue
		}
		i := int((m.TS - start) / step)
		for len(cols) <= i {
			cols = append(cols, nil)
		}
		if cols[i] == nil || *v > *cols[i] {
			x := *v
			cols[i] = &x
		}
		if n == 0 {
			lo, hi = *v, *v
		}
		lo, hi, sum, n = min(lo, *v), max(hi, *v), sum+*v, n+1
	}
	if n == 0 {
		return
	}
	// Percentages are drawn on 0–100, so a disk at 71% does not look full.
	top := hi
	if strings.HasSuffix(label, "%") {
		top = 100
	}
	if top <= 0 {
		top = 1
	}
	var line strings.Builder
	for _, v := range cols {
		if v == nil {
			line.WriteRune(' ')
			continue
		}
		i := int(*v / top * float64(len(blocks)))
		line.WriteRune(blocks[max(0, min(i, len(blocks)-1))])
	}
	if show == nil {
		show = func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }
	}
	fmt.Fprintf(w, "%-8s %s  %s / %s / %s\n", label, line.String(), show(lo), show(sum/float64(n)), show(hi))
}

// ---- status ----

func status(args []string, env Env) error {
	fs, asJSON := newFlags("status", env)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var d statusData
	if err := call(env, "status", nil, &d); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, d)
	}
	c := colors(env.TTY)
	w := env.Stdout
	fmt.Fprintf(w, "xnux-agent %s, up %s, %.1f MB resident\n", d.Version, (time.Duration(d.UptimeS) * time.Second).String(), d.RSSMB)
	if d.Mode == "standalone" {
		fmt.Fprintf(w, "mode       %sstandalone%s: recording locally, no network connections (xnux connect to upload)\n", c.bold, c.reset)
	} else {
		fmt.Fprintf(w, "mode       %sconnected%s to %s\n", c.bold, c.reset, d.Endpoint)
	}
	fmt.Fprintf(w, "host       %v %v %v, %v cores\n", d.Host["os"], d.Host["kernel"], d.Host["arch"], d.Host["cores"])
	fmt.Fprintf(w, "collectors %s\n", strings.Join(d.Capabilities, ", "))
	for k, n := range d.CollectorErrors {
		fmt.Fprintf(w, "           %s%s: %d errors%s\n", c.yellow, k, n, c.reset)
	}
	fmt.Fprintf(w, "storage    %v (events %s, metrics %s)\n", d.Storage["dir"], size(d.Storage["events_bytes"]), size(d.Storage["metrics_bytes"]))
	if r := d.Health.Score; d.Health.State == "scored" && r != nil {
		fmt.Fprintf(w, "health     %s%s%d %s%s\n", c.bold, levelColor(r.Level, c), r.Score, r.Level, c.reset)
		if r.Cap != nil {
			fmt.Fprintf(w, "           capped at %d: %s\n", r.Cap.Limit, health.Describe(r.Cap.Item, 0, "", env.Lang))
		}
		for _, x := range r.Deductions {
			fmt.Fprintf(w, "           −%-5g %s\n", x.Deduct, health.Describe(x.Item, x.Value, x.Subject, env.Lang))
		}
	} else {
		fmt.Fprintln(w, "health     collecting (scored after an hour of data)")
	}
	return nil
}

// ---- payload ----

func payload(args []string, env Env) error {
	fs, _ := newFlags("payload", env)
	last := fs.Bool("last", false, "the last payload the server accepted (default)")
	next := fs.Bool("next", false, "the newest payload built, sent or not")
	if err := fs.Parse(args); err != nil {
		return err
	}
	which := "last"
	if *next && !*last {
		which = "next"
	}
	var raw json.RawMessage
	if err := call(env, "payload", map[string]string{"which": which}, &raw); err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	return printJSON(env.Stdout, v)
}

// ---- connect / disconnect ----

var tokenRe = regexp.MustCompile(`^xat_[A-Za-z0-9]{8,}$`)

func connect(args []string, env Env) error {
	fs, asJSON := newFlags("connect", env)
	token := fs.String("token", "", "agent token from the Xnux console (xat_…)")
	endpoint := fs.String("endpoint", "", "upload address (default https://ingest.xnux.net, or your Cloudflare Worker)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !tokenRe.MatchString(*token) {
		return errors.New("--token xat_… is required (Xnux console → Servers → Add server)")
	}
	set := map[string]string{"token": *token}
	if *endpoint != "" {
		if !strings.HasPrefix(*endpoint, "https://") && !strings.HasPrefix(*endpoint, "http://") {
			return errors.New("--endpoint must be an http(s) URL")
		}
		set["endpoint"] = *endpoint
	}
	if err := editConfig(env.ConfigPath, set, nil); err != nil {
		return err
	}
	var d statusData
	if err := call(env, "reload", nil, &d); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, d)
	}
	fmt.Fprintf(env.Stdout, "connected to %s; the first upload goes out now. Local recording continues.\n", d.Endpoint)
	return nil
}

func disconnect(args []string, env Env) error {
	fs, asJSON := newFlags("disconnect", env)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := editConfig(env.ConfigPath, nil, []string{"token"}); err != nil {
		return err
	}
	var d statusData
	if err := call(env, "reload", nil, &d); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(env.Stdout, d)
	}
	fmt.Fprintln(env.Stdout, "disconnected: nothing is uploaded any more; the agent keeps recording locally.")
	fmt.Fprintln(env.Stdout, "Delete the server in the Xnux console too, so its token is revoked and its data removed.")
	return nil
}

// editConfig sets or removes top-level keys, keeping everything else
// (comments included). The file stays 0600.
func editConfig(path string, set map[string]string, remove []string) error {
	b, err := os.ReadFile(path) //nolint:gosec // the agent's config path
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("run with sudo: " + path + " is root's")
		}
		return err
	}
	var out []string
	done := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := sc.Text()
		key, _, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		top := ok && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(key, "#")
		if top && contains(remove, key) {
			continue
		}
		if v, want := set[key]; top && want {
			out = append(out, fmt.Sprintf("%s: %q", key, v))
			done[key] = true
			continue
		}
		out = append(out, line)
	}
	for _, k := range []string{"token", "endpoint"} {
		if v, ok := set[k]; ok && !done[k] {
			out = append([]string{fmt.Sprintf("%s: %q", k, v)}, out...)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil { //nolint:gosec // the agent config path, root-owned
		if errors.Is(err, os.ErrPermission) {
			return errors.New("run with sudo: " + path + " is root's")
		}
		return err
	}
	return os.Rename(tmp, path)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ---- formatting ----

type palette struct{ bold, dim, reset, red, orange, yellow, green string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{bold: "\033[1m", dim: "\033[2m", reset: "\033[0m", red: "\033[31m", orange: "\033[38;5;208m", yellow: "\033[33m", green: "\033[32m"}
}

func sev(s string, c palette) string {
	col := map[string]string{"P0": c.red, "P1": c.orange, "P2": c.yellow}[strings.ToUpper(s)]
	return col + s + c.reset
}

func meter(pct float64, width int, c palette) string {
	n := int(pct / 100 * float64(width))
	n = max(0, min(n, width))
	col := c.green
	switch {
	case pct >= 95:
		col = c.red
	case pct >= 80:
		col = c.yellow
	}
	return "[" + col + strings.Repeat("|", n) + c.reset + strings.Repeat(" ", width-n) + "]"
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:max(0, n-1)]) + "…"
}

func lastTS(e localstore.Event) int64 {
	if e.LastTS > e.TS {
		return e.LastTS
	}
	return e.TS
}

func size(v any) string {
	f, _ := v.(float64)
	switch {
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.0f KB", f/(1<<10))
	}
	return fmt.Sprintf("%.0f B", f)
}
