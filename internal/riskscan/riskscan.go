// Package riskscan is the local risk scan (spec v1.1 delta 10): a few
// configuration checks whose results decide which security events are worth
// reporting. Results stay in memory and in "xnux status"; they are never
// written to disk or sent.
//
// What it reads, and nothing else: the output of "sshd -T", the sshd
// configuration (/etc/ssh/sshd_config and the files it includes),
// /proc/net/tcp and /proc/net/tcp6, the command line of dockerd and
// /etc/docker/daemon.json. Never /etc/shadow, keys, application
// configuration or environment variables.
package riskscan

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

// Check names, as "xnux status" shows them and docs/risk-scan.md lists them
// (a test keeps the two in step).
const (
	CheckSSHPassword  = "ssh_password"
	CheckRootPassword = "root_password"
	CheckDBPublic     = "db_public"
	CheckDockerAPI    = "docker_api"
)

// Checks lists every check in display order.
var Checks = []string{CheckSSHPassword, CheckRootPassword, CheckDBPublic, CheckDockerAPI}

// Sources lists what the scan reads or runs, as docs/risk-scan.md names
// them (a test keeps the two in step). sshd_config may Include further
// files; dockerd's command line is /proc/<pid>/cmdline.
var Sources = []string{
	"sshd -T",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/",
	"/proc/net/tcp",
	"/proc/net/tcp6",
	"/proc/<pid>/cmdline",
	"/etc/docker/daemon.json",
}

// DBPorts are the database ports checked, with their service names.
var DBPorts = map[int]string{
	6379:  "redis",
	27017: "mongodb",
	3306:  "mysql",
	5432:  "postgresql",
	9200:  "elasticsearch",
	11211: "memcached",
}

// Exposure is a port listening where the internet can reach it.
type Exposure struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Addr    string `json:"addr"` // the bound address
}

// BindScope tells whether the port listens on every interface or on one
// address (spec v1.1 delta 10.7); events carry it instead of the address.
func (e Exposure) BindScope() string {
	if a, err := netip.ParseAddr(e.Addr); err == nil && a.IsUnspecified() {
		return proto.BindAllInterfaces
	}
	return proto.BindPublicAddress
}

// SSH is the result of the SSH checks.
type SSH struct {
	Present      bool   `json:"present"` // sshd is installed
	Password     bool   `json:"password"`
	RootPassword bool   `json:"root_password"`
	Source       string `json:"source,omitempty"` // "sshd -T" or "config files"
	Err          string `json:"error,omitempty"`
}

// Result is the latest scan.
type Result struct {
	At       time.Time  `json:"at"`      // the latest scan of any check
	FullAt   time.Time  `json:"full_at"` // the latest scan of all checks
	SSH      SSH        `json:"ssh"`     // CheckSSHPassword, CheckRootPassword
	DB       []Exposure `json:"db"`      // CheckDBPublic
	Docker   []Exposure `json:"docker"`  // CheckDockerAPI
	PortsErr string     `json:"ports_error,omitempty"`
}

// Scanner runs the checks against the filesystem under Root.
type Scanner struct {
	Root string // "/" in production; a fixture directory in tests
	// SSHD runs "sshd -T"; nil runs the installed sshd. Tests replace it.
	SSHD func(ctx context.Context) ([]byte, error)
	Now  func() time.Time
}

func (s *Scanner) path(p string) string { return filepath.Join(s.root(), p) }

func (s *Scanner) root() string {
	if s.Root == "" {
		return "/"
	}
	return s.Root
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Full runs every check.
func (s *Scanner) Full(ctx context.Context) Result {
	r := Result{SSH: s.ScanSSH(ctx)}
	s.scanPorts(&r)
	r.Docker = s.ScanDocker()
	r.At = s.now()
	r.FullAt = r.At
	return r
}

// ScanPorts refreshes the database check of r.
func (s *Scanner) ScanPorts(r *Result) {
	s.scanPorts(r)
	r.At = s.now()
}

func (s *Scanner) scanPorts(r *Result) {
	listen, err := ReadSockets(s.root(), StateListen)
	r.PortsErr = ""
	if err != nil {
		r.PortsErr = err.Error()
		r.DB = nil
		return
	}
	r.DB = dbExposures(listen)
}

func dbExposures(listen []Socket) []Exposure {
	seen := map[int]bool{}
	var out []Exposure
	for _, l := range listen {
		svc, ok := DBPorts[int(l.Local.Port())]
		if !ok || seen[int(l.Local.Port())] || !Reachable(l.Local.Addr()) {
			continue
		}
		seen[int(l.Local.Port())] = true
		out = append(out, Exposure{Port: int(l.Local.Port()), Service: svc, Addr: l.Local.Addr().String()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
