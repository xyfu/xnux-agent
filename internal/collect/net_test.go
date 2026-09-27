package collect

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const netDevHeader = "Inter-|   Receive |  Transmit\n face |bytes packets|bytes packets\n"

func netDev(lines string) []byte { return []byte(netDevHeader + lines) }

func names(ifs []Iface) (out []string) {
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	return out
}

func TestNetFilter(t *testing.T) {
	b := netDev("lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n" +
		"eth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n" +
		"docker0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n" +
		"veth9: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n" +
		"br-4f2a: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n" +
		"cali7: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n" +
		"ens5: 30 0 0 0 0 0 0 0 40 0 0 0 0 0 0 0\n" +
		"wg0: 5 0 0 0 0 0 0 0 6 0 0 0 0 0 0 0\n" +
		"broken: x\n")
	for _, tc := range []struct {
		f    NetFilter
		want string
	}{
		{NetFilter{}, "eth0,ens5,wg0"},
		{NetFilter{Exclude: []string{"wg*"}}, "eth0,ens5"},
		{NetFilter{Include: []string{"eth0", "docker0"}}, "eth0,docker0"},
		{NetFilter{Include: []string{"e*"}, Exclude: []string{"ens[0-9]"}}, "eth0"},
	} {
		got := names(parseNetDev(b, tc.f, nil))
		if s := strings.Join(got, ","); s != tc.want {
			t.Errorf("%+v: got %s, want %s", tc.f, s, tc.want)
		}
	}
	ifs := parseNetDev(b, NetFilter{Include: []string{"ens5"}}, nil)
	if ifs[0].Rx != 30 || ifs[0].Tx != 40 {
		t.Errorf("counters = %+v", ifs[0])
	}
}

func TestNetRate(t *testing.T) {
	t0 := time.Unix(1790000000, 0)
	at := func(sec int, ifs ...Iface) NetCounters {
		return NetCounters{At: t0.Add(time.Duration(sec) * time.Second), Ifaces: ifs}
	}
	base := at(0, Iface{"eth0", 1000, 2000}, Iface{"wg0", 0, 0})

	// 15 s: eth0 +1,875,000 B in / +375,000 B out, wg0 +0 / +93,750
	n, ok := NetRate(base, at(15, Iface{"eth0", 1876000, 377000}, Iface{"wg0", 0, 93750}))
	if !ok || n != (proto.Net{RxBps: 1000000, TxBps: 250000}) {
		t.Errorf("rate = %+v %v", n, ok)
	}
	for name, cur := range map[string]NetCounters{
		"first reading":      at(15, base.Ifaces...),
		"counter wrapped":    at(15, Iface{"eth0", 10, 3000}, Iface{"wg0", 0, 0}),
		"interface added":    at(15, Iface{"eth0", 1000, 2000}, Iface{"wg0", 0, 0}, Iface{"eth1", 0, 0}),
		"interface replaced": at(15, Iface{"eth0", 1000, 2000}, Iface{"wg1", 0, 0}),
		"no time passed":     at(0, base.Ifaces...),
		"nothing included":   at(15),
	} {
		prev := base
		if name == "first reading" {
			prev = NetCounters{}
		}
		if _, ok := NetRate(prev, cur); ok {
			t.Errorf("%s: want no rate", name)
		}
	}
}

// A counter that goes backwards drops that tick and resets the baseline,
// so the next tick is normal again: no spike after an interface restarts.
func TestSampleNetReset(t *testing.T) {
	s, root, _ := newFixtureSampler(t)
	t0 := time.Unix(1790000000, 0)
	s.Sample(t0)
	dev := func(eth0rx, eth0tx int) {
		write(t, root, "proc/net/dev", string(netDev(
			"lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n"+
				"eth0: "+strconv.Itoa(eth0rx)+" 0 0 0 0 0 0 0 "+strconv.Itoa(eth0tx)+" 0 0 0 0 0 0 0\n"+
				"wg0: 30000 0 0 0 0 0 0 0 10000 0 0 0 0 0 0 0\n")))
	}
	step := func(sec int) *proto.Net {
		write(t, root, "proc/stat", "cpu  "+strconv.Itoa(2000+sec)+" 0 500 10000 600 0 0 500 0 0\ncpu0 1 0 0 0\ncpu1 1 0 0 0\n")
		m, ok := s.Sample(t0.Add(time.Duration(sec) * time.Second))
		if !ok {
			t.Fatalf("sample at %d failed", sec)
		}
		return m.Net
	}
	dev(2875000, 575000) // +1,875,000 / +375,000 B over the fixture's eth0 in 15 s
	if n := step(15); n == nil || *n != (proto.Net{RxBps: 1000000, TxBps: 200000}) {
		t.Fatalf("net = %+v", n)
	}
	dev(500, 100) // interface recreated
	if n := step(30); n != nil {
		t.Fatalf("after reset net = %+v, want omitted", n)
	}
	dev(15500, 7600)
	if n := step(45); n == nil || *n != (proto.Net{RxBps: 8000, TxBps: 4000}) {
		t.Fatalf("after baseline net = %+v", n)
	}
}

func TestParseNetDevNoAllocs(t *testing.T) {
	b := netDev("lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\neth0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\nwg0: 5 0 0 0 0 0 0 0 6 0 0 0 0 0 0 0\n")
	buf := parseNetDev(b, NetFilter{}, nil)
	if n := testing.AllocsPerRun(100, func() { buf = parseNetDev(b, NetFilter{}, buf) }); n != 0 {
		t.Errorf("allocs = %v", n)
	}
}

func TestFormatBps(t *testing.T) {
	for v, want := range map[int64]string{0: "0 bps", 850: "850 bps", 999: "999 bps", 1000: "1.0 Kbps", 18400000: "18.4 Mbps",
		99940000: "99.9 Mbps", 99960000: "100 Mbps", 184000000: "184 Mbps", 999600000: "1.0 Gbps", 1260000000: "1.3 Gbps"} {
		if got := FormatBps(v); got != want {
			t.Errorf("FormatBps(%d) = %q, want %q", v, got, want)
		}
	}
}
