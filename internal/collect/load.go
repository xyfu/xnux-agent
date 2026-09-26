package collect

import "github.com/xyfu/xnux-shared/proto"

// parseLoadavg reads the first three columns of /proc/loadavg.
func parseLoadavg(b []byte) (proto.Load, bool) {
	var v [3]float64
	rest := b
	for i := range v {
		var f []byte
		f, rest = nextField(rest)
		x, ok := parseFloat(f)
		if !ok {
			return proto.Load{}, false
		}
		v[i] = round(x, 2)
	}
	return proto.Load{L1: v[0], L5: v[1], L15: v[2]}, true
}
