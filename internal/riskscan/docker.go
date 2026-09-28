package riskscan

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DockerPort is the conventional port of the Docker API without TLS.
const DockerPort = 2375

// ScanDocker finds a Docker API served over TCP without TLS on an address
// other than loopback: from dockerd's command line (-H / --host), from
// /etc/docker/daemon.json ("hosts"), or a socket listening on 2375.
func (s *Scanner) ScanDocker() []Exposure {
	var hosts []string
	tls := false
	for _, args := range s.dockerdArgs() {
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "-H" || a == "--host":
				if i+1 < len(args) {
					hosts = append(hosts, args[i+1])
					i++
				}
			case strings.HasPrefix(a, "--host="):
				hosts = append(hosts, strings.TrimPrefix(a, "--host="))
			case strings.HasPrefix(a, "-H"):
				hosts = append(hosts, strings.TrimPrefix(strings.TrimPrefix(a, "-H"), "="))
			case a == "--tls" || a == "--tlsverify" || a == "--tls=true" || a == "--tlsverify=true":
				tls = true
			}
		}
	}
	if b, err := os.ReadFile(s.path("etc/docker/daemon.json")); err == nil {
		var d struct {
			Hosts     []string `json:"hosts"`
			TLS       bool     `json:"tls"`
			TLSVerify bool     `json:"tlsverify"`
		}
		if json.Unmarshal(b, &d) == nil {
			hosts = append(hosts, d.Hosts...)
			tls = tls || d.TLS || d.TLSVerify
		}
	}
	found := map[int]Exposure{}
	if !tls {
		for _, h := range hosts {
			if e, ok := tcpHost(h); ok {
				found[e.Port] = e
			}
		}
	}
	if listen, err := ReadSockets(s.root(), StateListen); err == nil {
		for _, l := range listen {
			if l.Local.Port() == DockerPort && !l.Local.Addr().IsLoopback() {
				found[DockerPort] = Exposure{Port: DockerPort, Service: "docker", Addr: l.Local.Addr().String()}
			}
		}
	}
	out := make([]Exposure, 0, len(found))
	for _, e := range found {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	if len(out) == 0 {
		return nil
	}
	return out
}

// tcpHost parses a dockerd host such as tcp://0.0.0.0:2375, tcp://:2375 or
// tcp://10.0.0.5; an address on loopback is not exposed.
func tcpHost(h string) (Exposure, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(h), "tcp://")
	if !ok {
		return Exposure{}, false
	}
	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		host, portStr = rest, strconv.Itoa(DockerPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Exposure{}, false
	}
	if host == "localhost" {
		return Exposure{}, false
	}
	if a, err := netip.ParseAddr(host); err == nil && a.IsLoopback() {
		return Exposure{}, false
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return Exposure{Port: port, Service: "docker", Addr: host}, true
}

// dockerdArgs returns the command lines of running dockerd processes.
func (s *Scanner) dockerdArgs() [][]string {
	ents, err := os.ReadDir(s.path("proc"))
	if err != nil {
		return nil
	}
	var out [][]string
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := filepath.Join(s.path("proc"), e.Name())
		comm, err := os.ReadFile(filepath.Join(dir, "comm")) //nolint:gosec // /proc paths
		if err != nil || strings.TrimSpace(string(comm)) != "dockerd" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "cmdline")) //nolint:gosec // /proc paths
		if err != nil {
			continue
		}
		var args []string
		for _, a := range bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0}) {
			args = append(args, string(a))
		}
		out = append(out, args)
	}
	return out
}
