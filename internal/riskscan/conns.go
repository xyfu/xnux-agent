package riskscan

import (
	"net/netip"
	"sort"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

// accessEvery limits db_public_access and docker_api_access to one per
// port per hour (spec v1.1 delta 10.4).
const accessEvery = time.Hour

// maxSources bounds the source networks an access event lists.
const maxSources = 10

// Access is connections from outside to an exposed port, seen in one check.
type Access struct {
	Type        string // proto.EventDBPublicAccess or proto.EventDockerAPIAccess
	Port        int
	Service     string
	Connections int
	Sources     []string // networks with the host part hidden
}

// Monitor looks, at each metric tick, for ESTABLISHED connections to the
// ports the scan found exposed: from public addresses to a database, from
// any address other than loopback to the Docker API.
type Monitor struct {
	Root string
	last map[string]time.Time // type:port -> last reported
}

// Check returns the accesses due for reporting now. It reads /proc/net/tcp
// only while an exposure exists.
func (m *Monitor) Check(r *Result, now time.Time) []Access {
	if len(r.DB) == 0 && len(r.Docker) == 0 {
		return nil
	}
	root := m.Root
	if root == "" {
		root = "/"
	}
	socks, err := ReadSockets(root, StateEstablished)
	if err != nil {
		return nil
	}
	if m.last == nil {
		m.last = map[string]time.Time{}
	}
	var out []Access
	for _, e := range r.DB {
		out = m.collect(out, proto.EventDBPublicAccess, e, socks, Public, now)
	}
	for _, e := range r.Docker {
		out = m.collect(out, proto.EventDockerAPIAccess, e, socks, func(a netip.Addr) bool { return !a.Unmap().IsLoopback() }, now)
	}
	return out
}

func (m *Monitor) collect(out []Access, typ string, e Exposure, socks []Socket, from func(netip.Addr) bool, now time.Time) []Access {
	key := typ + ":" + itoa(e.Port)
	if t, ok := m.last[key]; ok && now.Sub(t) < accessEvery {
		return out
	}
	n := 0
	nets := map[string]bool{}
	for _, s := range socks {
		if int(s.Local.Port()) != e.Port || !from(s.Remote.Addr()) {
			continue
		}
		n++
		if len(nets) < maxSources {
			nets[MaskNet(s.Remote.Addr())] = true
		}
	}
	if n == 0 {
		return out
	}
	m.last[key] = now
	srcs := make([]string, 0, len(nets))
	for s := range nets {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	return append(out, Access{Type: typ, Port: e.Port, Service: e.Service, Connections: n, Sources: srcs})
}

func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}
