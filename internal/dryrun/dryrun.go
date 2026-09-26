// Package dryrun prints sanitized payloads to the terminal instead of
// sending them (spec A8.1). It never opens a network connection.
package dryrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/xyfu/xnux-shared/proto"
	"github.com/xyfu/xnux-shared/sanitize"
)

const (
	cyan     = "\x1b[36m"
	yellow   = "\x1b[33m"
	redBG    = "\x1b[41;97m"
	reset    = "\x1b[0m"
	markerOn = redBG
)

// Printer writes payloads to w. With color, keys are cyan, numbers yellow
// and redaction markers white on red; without it the output is plain JSON
// (one document per payload) suitable for jq.
type Printer struct {
	w       io.Writer
	summary io.Writer
	color   bool
	markers *regexp.Regexp
}

// New prints payloads to w and the one-line summary to summary (stderr when
// piping, so stdout stays valid JSON).
func New(w, summary io.Writer, color bool) (*Printer, error) {
	var ms []struct {
		Re string `json:"re"`
	}
	if err := json.Unmarshal(proto.RedactionMarkers, &ms); err != nil {
		return nil, err
	}
	var alts []string
	for _, m := range ms {
		alts = append(alts, "(?:"+m.Re+")")
	}
	re, err := regexp.Compile(strings.Join(alts, "|"))
	if err != nil {
		return nil, err
	}
	return &Printer{w: w, summary: summary, color: color, markers: re}, nil
}

// Print writes one payload and its summary line.
func (p *Printer) Print(sp sanitize.SanitizedPayload) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, sp.Bytes(), "", "  "); err != nil {
		return err
	}
	out := pretty.String()
	if p.color {
		out = p.colorize(out)
	}
	if _, err := fmt.Fprintln(p.w, out); err != nil {
		return err
	}
	_, err := fmt.Fprintln(p.summary, Summary(sp))
	return err
}

// Summary is "seq=… size=…KB redactions={…}".
func Summary(sp sanitize.SanitizedPayload) string {
	var hdr struct {
		Redactions map[string]int `json:"redactions"`
	}
	_ = json.Unmarshal(sp.Bytes(), &hdr)
	keys := make([]string, 0, len(hdr.Redactions))
	for k := range hdr.Redactions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%d", k, hdr.Redactions[k])
	}
	seq := fmt.Sprint(sp.Seq())
	if sp.Part() > 0 {
		seq += fmt.Sprintf(".%d", sp.Part())
	}
	return fmt.Sprintf("seq=%s size=%.1fKB redactions={%s}", seq, float64(len(sp.Bytes()))/1024, strings.Join(parts, ","))
}

// colorize walks indented JSON: a string followed by ':' is a key.
func (p *Printer) colorize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			j++ // closing quote
			str := s[i:min(j, len(s))]
			if j < len(s) && s[j] == ':' {
				b.WriteString(cyan + str + reset)
			} else {
				b.WriteString(p.markers.ReplaceAllStringFunc(str, func(m string) string { return markerOn + m + reset }))
			}
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			for j < len(s) && strings.IndexByte("-+.eE0123456789", s[j]) >= 0 {
				j++
			}
			b.WriteString(yellow + s[i:j] + reset)
			i = j
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}
