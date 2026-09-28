package riskscan

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TCP states in /proc/net/tcp.
const (
	StateEstablished = "01"
	StateListen      = "0A"
)

// Socket is one TCP socket.
type Socket struct {
	Local, Remote netip.AddrPort
}

// ReadSockets returns the TCP sockets (IPv4 and IPv6) in the given state.
func ReadSockets(root, state string) ([]Socket, error) {
	var out []Socket
	var firstErr error
	read := 0
	for _, table := range []string{"proc/net/tcp", "proc/net/tcp6"} {
		f, err := os.Open(filepath.Join(root, table))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		read++
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			// sl local rem st …
			fl := strings.Fields(sc.Text())
			if len(fl) < 4 || fl[3] != state {
				continue
			}
			l, ok1 := decodeAddr(fl[1])
			r, ok2 := decodeAddr(fl[2])
			if ok1 && ok2 {
				out = append(out, Socket{Local: l, Remote: r})
			}
		}
		_ = f.Close()
	}
	if read == 0 {
		return nil, firstErr
	}
	return out, nil
}

// decodeAddr turns "0100007F:1F90" (32-bit words in host, little-endian,
// order) into 127.0.0.1:8080; IPv4-mapped IPv6 addresses are unmapped.
func decodeAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, ok := netip.AddrFromSlice(b)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}

// Private and reserved ranges: the same set the redaction barrier keeps.
var private = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Public reports whether a is a public (globally routed) address.
func Public(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return false
	}
	for _, p := range private {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Reachable reports whether a socket bound to a can be reached from the
// internet: bound to every interface (0.0.0.0 or ::) or to a public address.
// A firewall may still block it; the scan does not read firewall rules.
func Reachable(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsUnspecified() || Public(a)
}

// MaskNet hides the host part of an address the way the redaction barrier
// does: 203.0.113.x, 2400:cb00:1:x::.
func MaskNet(a netip.Addr) string {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + ".x"
	}
	b := a.As16()
	g := func(i int) string { return strconv.FormatUint(uint64(b[i])<<8|uint64(b[i+1]), 16) }
	return g(0) + ":" + g(2) + ":" + g(4) + ":x::"
}
