package riskscan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// sshdTimeout bounds "sshd -T", the third exception to spec G-2's ban on
// external commands (spec v1.1 delta 10.2).
const sshdTimeout = 3 * time.Second

var sshdPaths = []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"}

func sshdBinary() string {
	for _, p := range sshdPaths {
		if exists(p) {
			return p
		}
	}
	return ""
}

// runSSHD prints sshd's effective global configuration: defaults, Include
// files and all, but not Match blocks, which it evaluates only for a given
// connection.
func runSSHD(ctx context.Context) ([]byte, error) {
	bin := sshdBinary()
	if bin == "" {
		return nil, errors.New("sshd not found")
	}
	ctx, cancel := context.WithTimeout(ctx, sshdTimeout)
	defer cancel()
	return exec.CommandContext(ctx, bin, "-T").Output() //nolint:gosec // fixed binary paths, fixed argument
}

// The settings the SSH checks look at, lowercased as sshd -T prints them.
type sshSettings map[string]string

// OpenSSH defaults for the settings the checks read.
var sshDefaults = sshSettings{
	"passwordauthentication":       "yes",
	"kbdinteractiveauthentication": "yes",
	"usepam":                       "no",
	"permitrootlogin":              "prohibit-password",
}

// aliases of the settings the checks read.
var sshAliases = map[string]string{"challengeresponseauthentication": "kbdinteractiveauthentication"}

func (m sshSettings) get(k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return sshDefaults[k]
}

// ScanSSH decides whether sshd accepts passwords, and for root.
//
// Password login counts as on when PasswordAuthentication is yes, or
// keyboard-interactive is on with PAM (which asks for the password), or any
// Match block turns either on. Root password login needs that and
// PermitRootLogin yes (globally or in a Match block).
func (s *Scanner) ScanSSH(ctx context.Context) SSH {
	cfg := s.path("etc/ssh/sshd_config")
	run := s.SSHD
	if run == nil {
		if s.root() != "/" {
			run = func(context.Context) ([]byte, error) { return nil, errors.New("sshd -T only runs on the real root") }
		} else {
			run = runSSHD
		}
	}
	out := SSH{Present: exists(cfg) || (s.root() == "/" && sshdBinary() != "")}
	if !out.Present {
		return out
	}
	parsed, err := parseSSHConfig(s.root(), cfg)
	global := parsed.global
	out.Source = "config files"
	if b, terr := run(ctx); terr == nil && len(b) > 0 {
		global = parseSSHDT(b)
		out.Source = "sshd -T"
	} else if err != nil {
		out.Err = err.Error()
		return out
	}
	usePAM := global.get("usepam") == "yes"
	out.Password = global.get("passwordauthentication") == "yes" ||
		(global.get("kbdinteractiveauthentication") == "yes" && usePAM) ||
		parsed.matchPassword || (parsed.matchKbd && usePAM)
	out.RootPassword = out.Password && (global.get("permitrootlogin") == "yes" || parsed.matchRoot)
	return out
}

func parseSSHDT(b []byte) sshSettings {
	m := sshSettings{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		if a, ok := sshAliases[k]; ok {
			k = a
		}
		if _, want := sshDefaults[k]; want {
			if _, seen := m[k]; !seen {
				m[k] = strings.ToLower(strings.TrimSpace(v))
			}
		}
	}
	return m
}

type sshConfig struct {
	global                             sshSettings
	matchPassword, matchKbd, matchRoot bool
}

// maxIncludeDepth stops Include loops.
const maxIncludeDepth = 16

// parseSSHConfig reads sshd_config the way sshd does: keywords are case
// insensitive, the first value of a keyword wins, Include pulls in files
// (globs, relative to /etc/ssh) in place, and a Match block runs to the next
// Match or the end of its file.
func parseSSHConfig(root, path string) (sshConfig, error) {
	c := sshConfig{global: sshSettings{}}
	err := c.file(root, path, false, 0)
	return c, err
}

func (c *sshConfig) file(root, path string, inMatch bool, depth int) error {
	if depth > maxIncludeDepth {
		return errors.New("sshd_config: Include nested too deeply")
	}
	b, err := os.ReadFile(path) //nolint:gosec // sshd configuration paths only
	if err != nil {
		if depth > 0 && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, args := splitKeyword(sc.Text())
		switch k {
		case "":
			continue
		case "match":
			inMatch = len(args) == 0 || !strings.EqualFold(args[0], "all")
			continue
		case "include":
			for _, pat := range args {
				if filepath.IsAbs(pat) {
					pat = filepath.Join(root, pat)
				} else {
					pat = filepath.Join(root, "etc/ssh", pat)
				}
				files, _ := filepath.Glob(pat) // sorted, as sshd sorts them
				for _, f := range files {
					if err := c.file(root, f, inMatch, depth+1); err != nil {
						return err
					}
				}
			}
			continue
		}
		if a, ok := sshAliases[k]; ok {
			k = a
		}
		if _, want := sshDefaults[k]; !want || len(args) == 0 {
			continue
		}
		v := strings.ToLower(args[0])
		if inMatch {
			switch {
			case k == "passwordauthentication" && v == "yes":
				c.matchPassword = true
			case k == "kbdinteractiveauthentication" && v == "yes":
				c.matchKbd = true
			case k == "permitrootlogin" && v == "yes":
				c.matchRoot = true
			}
			continue
		}
		if _, seen := c.global[k]; !seen {
			c.global[k] = v
		}
	}
	return sc.Err()
}

// splitKeyword splits "Keyword value", "Keyword=value" or "Keyword = value"
// and drops comments; the keyword comes back lowercased.
func splitKeyword(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil
	}
	k := strings.ToLower(line[:i])
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	var args []string
	for _, a := range strings.Fields(rest) {
		if strings.HasPrefix(a, "#") {
			break
		}
		args = append(args, strings.Trim(a, `"`))
	}
	return k, args
}
