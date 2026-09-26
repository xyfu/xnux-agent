// Package collect samples /proc and /sys on a single ticker: CPU, load,
// memory, swap, disks, temperatures and host info (spec A2). It never runs
// external commands.
package collect

import (
	"errors"
	"io"
	"os"
)

// procFile is a /proc or /sys file opened once and re-read on every sample by
// seeking to 0, into a buffer that is reused across reads.
type procFile struct {
	f   *os.File
	buf []byte
}

func openProcFile(path string, size int) (*procFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &procFile{f: f, buf: make([]byte, size)}, nil
}

// read returns the file content; it is only valid until the next read. The
// buffer grows if the file does not fit.
func (p *procFile) read() ([]byte, error) {
	for {
		if _, err := p.f.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		n := 0
		for n < len(p.buf) {
			m, err := p.f.Read(p.buf[n:])
			n += m
			if errors.Is(err, io.EOF) || (err == nil && m == 0) {
				return p.buf[:n], nil
			}
			if err != nil {
				return nil, err
			}
		}
		p.buf = make([]byte, 2*len(p.buf))
	}
}

func (p *procFile) Close() error {
	if p == nil {
		return nil
	}
	return p.f.Close()
}

// Byte-level parsing helpers; the hot path avoids strings.Split and allocations.

// nextLine returns the first line of b and the rest after the newline.
func nextLine(b []byte) (line, rest []byte) {
	for i, c := range b {
		if c == '\n' {
			return b[:i], b[i+1:]
		}
	}
	return b, nil
}

// nextField skips leading spaces and returns the next space-separated field.
func nextField(b []byte) (field, rest []byte) {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	j := i
	for j < len(b) && b[j] != ' ' && b[j] != '\t' {
		j++
	}
	return b[i:j], b[j:]
}

func parseUint(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, true
}

func parseInt(b []byte) (int64, bool) {
	if len(b) > 0 && b[0] == '-' {
		v, ok := parseUint(b[1:])
		return -int64(v), ok
	}
	v, ok := parseUint(b)
	return int64(v), ok
}

// parseFloat handles the plain decimal numbers found in /proc (e.g. "0.42").
func parseFloat(b []byte) (float64, bool) {
	intPart, frac := b, []byte(nil)
	for i, c := range b {
		if c == '.' {
			intPart, frac = b[:i], b[i+1:]
			break
		}
	}
	iv, ok := parseUint(intPart)
	if !ok {
		return 0, false
	}
	v := float64(iv)
	scale := 0.1
	for _, c := range frac {
		if c < '0' || c > '9' {
			return 0, false
		}
		v += float64(c-'0') * scale
		scale /= 10
	}
	return v, true
}

func hasPrefix(b []byte, p string) bool {
	return len(b) >= len(p) && string(b[:len(p)]) == p
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\n') {
		b = b[:len(b)-1]
	}
	return b
}
