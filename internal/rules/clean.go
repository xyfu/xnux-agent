package rules

import (
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxField bounds every string field (spec A4.1).
const MaxField = 512

// maxSkew is how far an event time may be from the local clock before it is
// replaced with the current time.
const maxSkew = 24 * time.Hour

// Clean makes a string safe to report: invalid UTF-8 becomes U+FFFD, ANSI
// escape sequences and control characters are removed, and the result is
// cut to max bytes (on a rune boundary) with "…" appended.
func Clean(s string, max int) string {
	if isPlain(s) && len(s) <= max {
		return s
	}
	var b strings.Builder
	b.Grow(min(len(s), max+3))
	for i := 0; i < len(s); {
		if s[i] == 0x1b { // ESC: skip a CSI/OSC sequence or the lone escape
			i = skipEscape(s, i)
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n == 1:
			r = utf8.RuneError
		case r == '\t':
			r = ' '
		case unicode.IsControl(r):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			b.WriteString("…")
			return b.String()
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c >= 0x80 {
			return false
		}
	}
	return true
}

// skipEscape returns the index after the escape sequence starting at s[i].
func skipEscape(s string, i int) int {
	i++
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '[': // CSI: parameters, then one final byte in 0x40–0x7e
		for i++; i < len(s); i++ {
			if s[i] >= 0x40 && s[i] <= 0x7e {
				return i + 1
			}
		}
		return i
	case ']': // OSC: until BEL or ESC \
		for i++; i < len(s); i++ {
			if s[i] == 0x07 {
				return i + 1
			}
			if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '\\' {
				return i + 2
			}
		}
		return i
	default:
		return i + 1
	}
}

// Cmdline turns /proc/<pid>/cmdline (NUL-separated) into a cleaned,
// space-separated string of at most 256 bytes.
func Cmdline(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	// Arguments may contain newlines (python -c scripts): keep words apart.
	s = strings.NewReplacer("\x00", " ", "\n", " ", "\r", " ").Replace(s)
	return Clean(s, 256)
}

// cleanValue applies Clean to every string in event data and drops numbers
// that JSON cannot carry (NaN, ±Inf).
func cleanValue(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		return Clean(t, MaxField), true
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = Clean(s, MaxField)
		}
		return out, true
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return nil, false
		}
		return t, true
	case map[string]any:
		cleanData(t)
		return t, true
	case []any:
		out := t[:0]
		for _, x := range t {
			if c, ok := cleanValue(x); ok {
				out = append(out, c)
			}
		}
		return out, true
	default:
		return v, true
	}
}

func cleanData(d map[string]any) {
	for k, v := range d {
		if c, ok := cleanValue(v); ok {
			d[k] = c
		} else {
			delete(d, k)
		}
	}
}

// eventTime replaces a timestamp that is more than a day off the local clock.
func eventTime(ts, now time.Time) (t time.Time, adjusted bool) {
	if ts.IsZero() {
		return now, false
	}
	if d := ts.Sub(now); d > maxSkew || d < -maxSkew {
		return now, true
	}
	return ts, false
}
