package riskscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fixture writes files under a temporary root.
func fixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// noSSHD is a host where "sshd -T" does not work, so the files decide.
func noSSHD(context.Context) ([]byte, error) { return nil, errors.New("no sshd") }

// Distribution defaults, shortened to the lines that matter.
const (
	ubuntuDefault = `Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
#PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
Subsystem sftp /usr/lib/openssh/sftp-server
`
	rockyDefault = `Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
#PasswordAuthentication yes
Subsystem sftp /usr/libexec/openssh/sftp-server
`
	rockyRedhatConf = `ChallengeResponseAuthentication no
GSSAPIAuthentication yes
UsePAM yes
X11Forwarding yes
`
)

func TestSSHChecks(t *testing.T) {
	for _, c := range []struct {
		name           string
		files          map[string]string
		password, root bool
	}{
		{"ubuntu default", map[string]string{"etc/ssh/sshd_config": ubuntuDefault}, true, false},
		{"ubuntu cloud image", map[string]string{"etc/ssh/sshd_config": ubuntuDefault,
			"etc/ssh/sshd_config.d/60-cloudimg-settings.conf": "PasswordAuthentication no\n"}, false, false},
		{"debian default", map[string]string{"etc/ssh/sshd_config": ubuntuDefault}, true, false},
		{"rocky default", map[string]string{"etc/ssh/sshd_config": rockyDefault,
			"etc/ssh/sshd_config.d/50-redhat.conf": rockyRedhatConf}, true, false},
		{"rocky installer allowed root password", map[string]string{"etc/ssh/sshd_config": rockyDefault,
			"etc/ssh/sshd_config.d/01-permitrootlogin.conf": "PermitRootLogin yes\n",
			"etc/ssh/sshd_config.d/50-redhat.conf":          rockyRedhatConf}, true, true},

		{"password and keyboard-interactive off", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM yes\n"}, false, false},
		{"keyboard-interactive with PAM asks for the password", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication yes\nUsePAM yes\n"}, true, false},
		{"keyboard-interactive without PAM", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication yes\nUsePAM no\n"}, false, false},
		{"first value wins", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPasswordAuthentication yes\n"}, false, false},
		{"include before the main file's value", map[string]string{
			"etc/ssh/sshd_config":          "Include sshd_config.d/*.conf\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\n",
			"etc/ssh/sshd_config.d/a.conf": "PasswordAuthentication no\n"}, false, false},
		{"match block turns passwords on", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nMatch User deploy\n  PasswordAuthentication yes\n"}, true, false},
		{"match block allows root", map[string]string{"etc/ssh/sshd_config": "KbdInteractiveAuthentication no\nMatch Address 10.0.0.0/8\n  PermitRootLogin yes\n"}, true, true},
		{"root allowed but passwords off", map[string]string{"etc/ssh/sshd_config": "PermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"}, false, false},
		{"equals sign and upper case", map[string]string{"etc/ssh/sshd_config": "PASSWORDAUTHENTICATION=no\nKbdInteractiveAuthentication = no # trailing comment\n"}, false, false},
		{"old keyword challenge-response", map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication no\nChallengeResponseAuthentication yes\nUsePAM yes\n"}, true, false},
		{"match in an included file ends with it", map[string]string{
			"etc/ssh/sshd_config":          "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
			"etc/ssh/sshd_config.d/m.conf": "Match User backup\n  X11Forwarding no\n"}, false, false},
		{"match all returns to global", map[string]string{"etc/ssh/sshd_config": "Match User x\n  X11Forwarding no\nMatch all\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &Scanner{Root: fixture(t, c.files), SSHD: noSSHD}
			got := s.ScanSSH(context.Background())
			if !got.Present || got.Password != c.password || got.RootPassword != c.root || got.Err != "" {
				t.Errorf("got %+v, want password=%v root=%v", got, c.password, c.root)
			}
			if got.Source != "config files" {
				t.Errorf("source %q", got.Source)
			}
		})
	}
}

func TestSSHDTakesPrecedence(t *testing.T) {
	// sshd -T knows the effective global values; Match blocks still come
	// from the files, since sshd -T does not evaluate them.
	root := fixture(t, map[string]string{"etc/ssh/sshd_config": "Match User deploy\n  PasswordAuthentication yes\n"})
	s := &Scanner{Root: root, SSHD: func(context.Context) ([]byte, error) {
		return []byte("port 22\npasswordauthentication no\nkbdinteractiveauthentication no\nusepam yes\npermitrootlogin yes\n"), nil
	}}
	got := s.ScanSSH(context.Background())
	if got.Source != "sshd -T" || !got.Password || !got.RootPassword {
		t.Fatalf("got %+v", got)
	}
	root = fixture(t, map[string]string{"etc/ssh/sshd_config": "PasswordAuthentication yes\n"})
	s = &Scanner{Root: root, SSHD: func(context.Context) ([]byte, error) {
		return []byte("passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\n"), nil
	}}
	if got := s.ScanSSH(context.Background()); got.Password || got.RootPassword {
		t.Fatalf("sshd -T says off: %+v", got)
	}
}

func TestNoSSHServer(t *testing.T) {
	s := &Scanner{Root: t.TempDir(), SSHD: noSSHD}
	if got := s.ScanSSH(context.Background()); got.Present || got.Password {
		t.Fatalf("got %+v", got)
	}
}

func TestIncludeLoopStops(t *testing.T) {
	root := fixture(t, map[string]string{"etc/ssh/sshd_config": "Include sshd_config\n"})
	s := &Scanner{Root: root, SSHD: noSSHD}
	if got := s.ScanSSH(context.Background()); got.Err == "" {
		t.Fatalf("an Include loop should be reported: %+v", got)
	}
}
