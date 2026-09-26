// Package config loads and validates /etc/xnux/agent.yaml (spec A1).
// Built-in redaction rules cannot be disabled by config.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	Token           string `yaml:"token"`
	Endpoint        string `yaml:"endpoint"`
	IntervalSeconds int    `yaml:"interval_seconds"`
	FlushSeconds    int    `yaml:"flush_seconds"`
	HideHostname    bool   `yaml:"hide_hostname"`
	MirrorHistory   int    `yaml:"mirror_history"`

	Collectors Collectors `yaml:"collectors"`
	Systemd    Systemd    `yaml:"systemd"`
	Security   Security   `yaml:"security"`
	Procscan   Procscan   `yaml:"procscan"`
	Sanitize   Sanitize   `yaml:"sanitize"`
	TLS        TLS        `yaml:"tls"`
	Proxy      string     `yaml:"proxy"`
}

type Collectors struct {
	Metrics  bool `yaml:"metrics"`
	Systemd  bool `yaml:"systemd"`
	Kmsg     bool `yaml:"kmsg"`
	Authlog  bool `yaml:"authlog"`
	Procscan bool `yaml:"procscan"`
}

type Systemd struct {
	IgnoreUnits []string `yaml:"ignore_units"`
}

type Security struct {
	BruteforceFailThreshold int      `yaml:"bruteforce_fail_threshold"`
	SprayUserThreshold      int      `yaml:"spray_user_threshold"`
	BreachFailThreshold     int      `yaml:"breach_fail_threshold"`
	SudoSensitiveExtra      []string `yaml:"sudo_sensitive_extra"`
}

type Procscan struct {
	WhitelistExe  []string `yaml:"whitelist_exe"`
	WhitelistComm []string `yaml:"whitelist_comm"`
}

type Sanitize struct {
	MaskEmail     bool     `yaml:"mask_email"`
	ExtraPatterns []string `yaml:"extra_patterns"`
}

type TLS struct {
	CAFile string `yaml:"ca_file"`
}

// Default returns the configuration used for keys absent from the file.
func Default() *Config {
	return &Config{
		IntervalSeconds: 15,
		FlushSeconds:    60,
		Collectors:      Collectors{Metrics: true, Systemd: true, Kmsg: true, Authlog: true, Procscan: true},
		Systemd:         Systemd{IgnoreUnits: []string{"apt-daily.service", "man-db.service"}},
		Security:        Security{BruteforceFailThreshold: 20, SprayUserThreshold: 5, BreachFailThreshold: 10},
		Sanitize:        Sanitize{MaskEmail: true},
	}
}

// Load reads and validates the config file. Warnings are non-fatal problems
// (such as loose file permissions) the caller should log.
func Load(path string) (cfg *Config, warnings []string, err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		warnings = append(warnings, fmt.Sprintf("%s has mode %#o, want 0600: it contains the agent token", path, perm))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, warnings, err
	}
	cfg, err = Parse(b)
	return cfg, warnings, err
}

// Parse decodes YAML on top of Default and validates the result.
func Parse(b []byte) (*Config, error) {
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) { // io.EOF: empty file
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks ranges and formats.
func (c *Config) Validate() error {
	var errs []error
	if c.Token == "" {
		errs = append(errs, errors.New("token is required"))
	} else if !strings.HasPrefix(c.Token, "xat_") {
		errs = append(errs, errors.New(`token must start with "xat_"`))
	}
	if u, err := url.Parse(c.Endpoint); c.Endpoint == "" || err != nil || u.Host == "" {
		errs = append(errs, errors.New("endpoint must be an absolute URL"))
	} else if u.Scheme != "https" && u.Scheme != "http" {
		errs = append(errs, errors.New("endpoint scheme must be https (or http for local testing)"))
	}
	if c.IntervalSeconds < 10 || c.IntervalSeconds > 60 {
		errs = append(errs, errors.New("interval_seconds must be within 10–60"))
	}
	if c.FlushSeconds < 30 || c.FlushSeconds > 300 {
		errs = append(errs, errors.New("flush_seconds must be within 30–300"))
	}
	if c.MirrorHistory < 0 || c.MirrorHistory > 1000 {
		errs = append(errs, errors.New("mirror_history must be within 0–1000"))
	}
	if c.Proxy != "" {
		if u, err := url.Parse(c.Proxy); err != nil || u.Host == "" {
			errs = append(errs, errors.New("proxy must be an absolute URL"))
		}
	}
	for _, p := range c.Sanitize.ExtraPatterns {
		if _, err := regexp.Compile(p); err != nil {
			errs = append(errs, fmt.Errorf("sanitize.extra_patterns: %q: %w", p, err))
		}
	}
	// The security state keeps at most 64 failure times and 32 user names
	// per source (spec A4.2), which bounds the thresholds.
	if t := c.Security.BruteforceFailThreshold; t < 2 || t > 64 {
		errs = append(errs, errors.New("security.bruteforce_fail_threshold must be within 2–64"))
	}
	if t := c.Security.SprayUserThreshold; t < 2 || t > 32 {
		errs = append(errs, errors.New("security.spray_user_threshold must be within 2–32"))
	}
	if t := c.Security.BreachFailThreshold; t < 1 || t > 64 {
		errs = append(errs, errors.New("security.breach_fail_threshold must be within 1–64"))
	}
	for _, p := range c.Security.SudoSensitiveExtra {
		if _, err := regexp.Compile(p); err != nil {
			errs = append(errs, fmt.Errorf("security.sudo_sensitive_extra: %q: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// MaskedToken shows only the last 4 characters of the token.
func (c *Config) MaskedToken() string {
	if len(c.Token) <= 4 {
		return "****"
	}
	return "****" + c.Token[len(c.Token)-4:]
}

// Printable returns the effective config as YAML with the token masked.
func (c *Config) Printable() string {
	cp := *c
	cp.Token = c.MaskedToken()
	b, err := yaml.Marshal(&cp)
	if err != nil {
		return err.Error()
	}
	return string(b)
}
