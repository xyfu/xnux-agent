package collect

import (
	"bytes"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

// DefaultNetExclude are the interfaces left out of the throughput unless
// network.include names them: loopback and container / VM bridges and
// veths, whose traffic also crosses a physical interface (spec v1.1 delta
// 9.2).
var DefaultNetExclude = []string{"lo", "docker*", "veth*", "br-*", "virbr*", "cni*", "flannel*", "cali*"}

// NetFilter selects the interfaces summed into the throughput. With
// Include set only matching interfaces count; Exclude always applies, and
// the defaults apply unless Include is set.
type NetFilter struct {
	Include []string
	Exclude []string
}

func (f NetFilter) match(name []byte) bool {
	glob := func(pats []string) bool {
		for _, p := range pats {
			if matchGlob(p, name) {
				return true
			}
		}
		return false
	}
	if glob(f.Exclude) {
		return false
	}
	if len(f.Include) > 0 {
		return glob(f.Include)
	}
	return !glob(DefaultNetExclude)
}

// Iface is one interface's byte counters.
type Iface struct {
	Name string `json:"name"`
	Rx   uint64 `json:"rx"` // bytes received
	Tx   uint64 `json:"tx"` // bytes sent
}

// NetCounters are the counters of the included interfaces, in
// /proc/net/dev order.
type NetCounters struct {
	At     time.Time `json:"at"`
	Ifaces []Iface   `json:"ifaces"`
}

// NetRate is the throughput between two readings, or false when there is
// none: no interface is included, an interface appeared or went away, or a counter went backwards
// (wrapped, or the interface was recreated). The caller then starts over
// from cur.
func NetRate(prev, cur NetCounters) (proto.Net, bool) {
	dt := cur.At.Sub(prev.At).Seconds()
	if prev.At.IsZero() || dt <= 0 || len(cur.Ifaces) == 0 || len(prev.Ifaces) != len(cur.Ifaces) {
		return proto.Net{}, false
	}
	var rx, tx uint64
	for i, c := range cur.Ifaces {
		p := prev.Ifaces[i]
		if p.Name != c.Name || c.Rx < p.Rx || c.Tx < p.Tx {
			return proto.Net{}, false
		}
		rx += c.Rx - p.Rx
		tx += c.Tx - p.Tx
	}
	return proto.Net{RxBps: int64(float64(rx) * 8 / dt), TxBps: int64(float64(tx) * 8 / dt)}, true
}

// parseNetDev reads /proc/net/dev: two header lines, then
// "name: rx_bytes rx_packets … (8 receive fields) tx_bytes …". It reuses
// dst and its names, so an unchanged set of interfaces allocates nothing.
func parseNetDev(b []byte, f NetFilter, dst []Iface) []Iface {
	dst = dst[:0]
	_, b = nextLine(b)
	_, b = nextLine(b)
	for len(b) > 0 {
		var line []byte
		line, b = nextLine(b)
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := bytes.TrimSpace(line[:i])
		if len(name) == 0 || !f.match(name) {
			continue
		}
		rest := line[i+1:]
		var rx, tx uint64
		ok := true
		for k := 0; k < 9 && ok; k++ {
			var fld []byte
			fld, rest = nextField(rest)
			v, good := parseUint(fld)
			ok = good
			switch k {
			case 0:
				rx = v
			case 8:
				tx = v
			}
		}
		if !ok {
			continue
		}
		n := len(dst)
		if n < cap(dst) {
			dst = dst[:n+1]
			if dst[n].Name != string(name) {
				dst[n].Name = string(name)
			}
		} else {
			dst = append(dst, Iface{Name: string(name)})
		}
		dst[n].Rx, dst[n].Tx = rx, tx
	}
	return dst
}

// matchGlob is path.Match on a name held in bytes. Names are short and
// the patterns few; the common trailing-"*" form needs no conversion.
func matchGlob(pattern string, name []byte) bool {
	if n := len(pattern); n > 0 && pattern[n-1] == '*' && !strings.ContainsAny(pattern[:n-1], "*?[\\") {
		return bytes.HasPrefix(name, []byte(pattern[:n-1]))
	}
	if !strings.ContainsAny(pattern, "*?[\\") {
		return string(name) == pattern
	}
	ok, _ := path.Match(pattern, string(name))
	return ok
}

// NetReader reads the counters from one open /proc/net/dev.
type NetReader struct {
	f      *procFile
	filter NetFilter
}

// OpenNet opens procRoot/net/dev; interfaces are chosen by filter.
func OpenNet(procRoot string, filter NetFilter) (*NetReader, error) {
	f, err := openProcFile(procRoot+"/net/dev", 4096)
	if err != nil {
		return nil, err
	}
	return &NetReader{f: f, filter: filter}, nil
}

// Read takes the counters now.
func (r *NetReader) Read(now time.Time) (NetCounters, error) {
	b, err := r.f.read()
	if err != nil {
		return NetCounters{}, err
	}
	return NetCounters{At: now, Ifaces: parseNetDev(b, r.filter, nil)}, nil
}

// Close releases the file.
func (r *NetReader) Close() {
	if r != nil {
		_ = r.f.Close()
	}
}

// sampleNet returns the throughput since the previous sample; the first
// call, and a call after interfaces or counters changed, only record the
// baseline.
func (s *Sampler) sampleNet(now time.Time) *proto.Net {
	if s.net == nil {
		return nil
	}
	b, err := s.net.f.read()
	if err != nil {
		s.prevNet = NetCounters{}
		return nil
	}
	// Two buffers take turns, so steady sampling does not allocate.
	cur := NetCounters{At: now, Ifaces: parseNetDev(b, s.net.filter, s.spareNet)}
	n, ok := NetRate(s.prevNet, cur)
	s.spareNet, s.prevNet = s.prevNet.Ifaces, cur
	if !ok {
		return nil
	}
	return &n
}

// FormatBps shows a rate in bit/s with a decimal unit: 850 bps, 18.4 Mbps,
// 184 Mbps, 1.2 Gbps.
func FormatBps(v int64) string {
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	f := float64(v)
	i := 0
	for f >= 999.5 && i < len(units)-1 {
		f /= 1000
		i++
	}
	if i == 0 || f >= 99.95 {
		return strconv.FormatFloat(f, 'f', 0, 64) + " " + units[i]
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
}
