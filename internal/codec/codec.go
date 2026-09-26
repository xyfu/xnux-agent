// Package codec compresses payload bodies for the wire and the spool.
package codec

import (
	"bytes"
	"compress/gzip"
	"io"
)

// Level is the gzip level used on the wire (spec A7.1).
const Level = 6

// Gzip compresses b.
func Gzip(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, Level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Gunzip decompresses at most limit bytes and fails beyond that.
func Gunzip(b []byte, limit int64) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, io.ErrShortBuffer
	}
	return out, nil
}
