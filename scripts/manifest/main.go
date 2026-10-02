// Command manifest writes the release manifest (C-AG-RELEASE-MANIFEST,
// spec v1.1 delta 12.6) and checks the release notes it is made of.
//
//	go run ./scripts/manifest check
//	go run ./scripts/manifest build -version v1.4.0 -bin bin -out bin/manifest.json
//	go run ./scripts/manifest sign -in bin/manifest.json   # key in XNUX_MANIFEST_KEY
//
// Each release has releases/notes/{version}.json in the repository, added
// in the pull request that makes the change: its level and highlights in
// both languages. The manifest lists every release with a notes file and a
// tag (plus the one being released), newest first; the one being released
// also carries its downloads, from bin/SHA256SUMS.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xyfu/xnux-shared/proto"
)

const (
	repo     = "xyfu/xnux-agent"
	notesDir = "releases/notes"
)

type notes struct {
	Level      string              `json:"level"`
	Highlights map[string][]string `json:"highlights"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: manifest check | build | sign"))
	}
	var err error
	switch os.Args[1] {
	case "check":
		_, err = readNotes()
	case "build":
		err = build(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "manifest:", err)
	os.Exit(1)
}

// readNotes loads and checks every notes file, keyed by version.
func readNotes() (map[string]notes, error) {
	paths, err := filepath.Glob(filepath.Join(notesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := map[string]notes{}
	for _, p := range paths {
		v := strings.TrimSuffix(filepath.Base(p), ".json")
		if _, ok := proto.ParseVersion(v); !ok || strings.HasPrefix(v, "v") {
			return nil, fmt.Errorf("%s: name it after the version without v, e.g. 1.4.0.json", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var n notes
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&n); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if proto.LevelRank(n.Level) == 0 {
			return nil, fmt.Errorf("%s: level must be security, recommended or optional", p)
		}
		for _, lang := range []string{"zh-Hans", "en"} {
			if len(n.Highlights[lang]) == 0 {
				return nil, fmt.Errorf("%s: highlights.%s is empty", p, lang)
			}
			for _, h := range n.Highlights[lang] {
				if strings.TrimSpace(h) == "" || len(h) > 200 {
					return nil, fmt.Errorf("%s: a %s highlight is empty or longer than 200 bytes", p, lang)
				}
			}
		}
		if len(n.Highlights) != 2 {
			return nil, fmt.Errorf("%s: highlights take zh-Hans and en only", p)
		}
		out[v] = n
	}
	return out, nil
}

// tagTime is when a tag's commit was made, from git; false without the tag.
func tagTime(tag string) (int64, bool) {
	out, err := exec.Command("git", "log", "-1", "--format=%ct", tag).Output() //nolint:gosec // tag names come from our own notes files
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return n, err == nil
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	tag := fs.String("version", "", "the tag being released, e.g. v1.4.0")
	bin := fs.String("bin", "bin", "directory with the release files and SHA256SUMS")
	out := fs.String("out", "bin/manifest.json", "where to write the manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cur := strings.TrimPrefix(*tag, "v")
	if _, ok := proto.ParseVersion(cur); !ok || !strings.HasPrefix(*tag, "v") {
		return fmt.Errorf("-version must look like v1.4.0, not %q", *tag)
	}
	all, err := readNotes()
	if err != nil {
		return err
	}
	if _, ok := all[cur]; !ok {
		return fmt.Errorf("no %s/%s.json: add the release notes in the pull request", notesDir, cur)
	}
	sums, err := readSums(filepath.Join(*bin, "SHA256SUMS"))
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	m := proto.Manifest{Schema: 1, Latest: cur, GeneratedAt: now}
	for v, n := range all {
		if proto.CompareVersions(v, cur) > 0 {
			continue // notes for a later release, not out yet
		}
		r := proto.Release{Version: v, Tag: "v" + v, Prerelease: strings.Contains(v, "-"), Level: n.Level, Highlights: n.Highlights}
		if v == cur {
			r.ReleasedAt = now
			dl := "https://github.com/" + repo + "/releases/download/" + *tag + "/"
			r.Artifacts = map[string]proto.Artifact{}
			for _, arch := range []string{"amd64", "arm64"} {
				name := "xnux-agent-linux-" + arch
				sum, ok := sums[name]
				if !ok {
					return fmt.Errorf("SHA256SUMS has no %s", name)
				}
				r.Artifacts["linux-"+arch] = proto.Artifact{URL: dl + name, SHA256: sum, Sig: dl + name + ".sig", Cert: dl + name + ".pem"}
			}
			sum, ok := sums["install.sh"]
			if !ok {
				return errors.New("SHA256SUMS has no install.sh")
			}
			r.InstallScript = &proto.Download{URL: dl + "install.sh", SHA256: sum}
		} else {
			t, ok := tagTime(r.Tag)
			if !ok {
				continue // never released under that tag
			}
			r.ReleasedAt = t
		}
		m.Releases = append(m.Releases, r)
	}
	sort.Slice(m.Releases, func(i, j int) bool { return proto.CompareVersions(m.Releases[i].Version, m.Releases[j].Version) > 0 })
	if err := m.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*out, append(b, '\n'), 0o644) //nolint:gosec // a public release file
}

func readSums(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // a path the release workflow passes
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 {
			out[strings.TrimPrefix(strings.TrimPrefix(fields[1], "*"), "./")] = fields[0]
		}
	}
	return out, sc.Err()
}

// sign writes {in}.ed25519 with the key in XNUX_MANIFEST_KEY (base64 of
// the 32-byte seed); without the key it does nothing.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	in := fs.String("in", "bin/manifest.json", "the manifest to sign")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key := strings.TrimSpace(os.Getenv("XNUX_MANIFEST_KEY"))
	if key == "" {
		fmt.Fprintln(os.Stderr, "manifest: XNUX_MANIFEST_KEY is not set; the manifest is not signed")
		return nil
	}
	seed, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("XNUX_MANIFEST_KEY must be base64 of a 32-byte ed25519 seed")
	}
	body, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), body)
	return os.WriteFile(*in+".ed25519", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644) //nolint:gosec // public
}
