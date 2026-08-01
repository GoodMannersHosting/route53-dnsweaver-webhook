package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
)

// clearEnv unsets every variable Load consults so cases don't leak into each
// other or pick up the developer's own environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"ROUTE53_HOSTED_ZONE_ID", "ROUTE53_DEFAULT_TTL", "PORT",
		"WEBHOOK_AUTH_HEADER", "WEBHOOK_AUTH_TOKEN", "WEBHOOK_AUTH_TOKEN_FILE",
		"LOG_LEVEL",
	} {
		t.Setenv(k, "")
	}
	// Load searches the working directory for config.yaml; run from a clean one.
	t.Chdir(t.TempDir())
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "Z0123456789ABCDEFGHI")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultTTL != 300 {
		t.Errorf("DefaultTTL = %d, want 300", cfg.DefaultTTL)
	}
	if cfg.Addr() != ":8080" {
		t.Errorf("Addr() = %q, want :8080", cfg.Addr())
	}
	if cfg.AuthEnabled() {
		t.Error("AuthEnabled() = true with no secret configured")
	}
}

func TestLoadFromEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "/hostedzone/Z0123456789ABCDEFGHI")
	t.Setenv("ROUTE53_DEFAULT_TTL", "60")
	t.Setenv("PORT", "9090")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HostedZoneID != "Z0123456789ABCDEFGHI" {
		t.Errorf("HostedZoneID = %q, want the /hostedzone/ prefix stripped", cfg.HostedZoneID)
	}
	if cfg.DefaultTTL != 60 || cfg.Addr() != ":9090" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestFlagsBeatEnv(t *testing.T) {
	clearEnv(t)
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "ZFROMENVIRONMENT")
	t.Setenv("PORT", "9090")

	cfg, err := Load([]string{"--hosted-zone-id", "ZFROMFLAG", "--port", "7070"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HostedZoneID != "ZFROMFLAG" {
		t.Errorf("HostedZoneID = %q, want the flag to win", cfg.HostedZoneID)
	}
	if cfg.Addr() != ":7070" {
		t.Errorf("Addr() = %q, want the flag to win", cfg.Addr())
	}
}

func TestEnvBeatsConfigFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	contents := "hosted-zone-id: ZFROMFILE\ndefault-ttl: 45\nport: 6060\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTE53_DEFAULT_TTL", "90")

	cfg, err := Load([]string{"--config", path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HostedZoneID != "ZFROMFILE" {
		t.Errorf("HostedZoneID = %q, want the file value", cfg.HostedZoneID)
	}
	if cfg.DefaultTTL != 90 {
		t.Errorf("DefaultTTL = %d, want the environment to win over the file", cfg.DefaultTTL)
	}
	if cfg.Addr() != ":6060" {
		t.Errorf("Addr() = %q, want the file value", cfg.Addr())
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]struct {
		env  map[string]string
		args []string
	}{
		"missing zone":        {},
		"bogus zone":          {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "not-a-zone"}},
		"zone with traversal": {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "../../secrets"}},
		"ttl zero":            {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "Z0123456789ABCDEFGHI", "ROUTE53_DEFAULT_TTL": "0"}},
		"port out of range":   {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "Z0123456789ABCDEFGHI", "PORT": "70000"}},
		"unknown flag":        {args: []string{"--nope"}},
		"missing config file": {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "Z0123456789ABCDEFGHI"}, args: []string{"--config", "/nonexistent/config.yaml"}},
		// A half-configured shared secret must not start up unprotected.
		"header without token": {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "Z0123456789ABCDEFGHI", "WEBHOOK_AUTH_HEADER": "X-Webhook-Token"}},
		"token without header": {env: map[string]string{"ROUTE53_HOSTED_ZONE_ID": "Z0123456789ABCDEFGHI", "WEBHOOK_AUTH_TOKEN": "s3cret"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(tc.args); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestLoadTokenFile(t *testing.T) {
	clearEnv(t)
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "Z0123456789ABCDEFGHI")
	t.Setenv("WEBHOOK_AUTH_HEADER", "X-Webhook-Token")

	cfg, err := Load([]string{"--auth-token-file", path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AuthToken != "s3cret" {
		t.Errorf("AuthToken = %q", cfg.AuthToken)
	}
	if !cfg.AuthEnabled() {
		t.Error("AuthEnabled() = false")
	}

	// An unmounted or unreadable secret must fail loudly rather than fall
	// back to an empty token.
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Load([]string{"--auth-token-file", missing}); err == nil {
		t.Error("expected error for unreadable token file")
	}
}

func TestNoAuthTokenFlag(t *testing.T) {
	// A secret on argv is visible to every user on the host via ps.
	clearEnv(t)
	t.Setenv("ROUTE53_HOSTED_ZONE_ID", "Z0123456789ABCDEFGHI")
	if _, err := Load([]string{"--auth-token", "s3cret"}); err == nil {
		t.Fatal("--auth-token should not be a flag")
	}
}

func TestHelpIsNotAFailure(t *testing.T) {
	clearEnv(t)
	_, err := Load([]string{"--help"})
	if !errors.Is(err, ErrHelp) || !errors.Is(err, pflag.ErrHelp) {
		t.Fatalf("error = %v, want ErrHelp", err)
	}
}

func TestVersionSkipsValidation(t *testing.T) {
	// --version has to answer on a host with nothing else configured.
	clearEnv(t)
	_, err := Load([]string{"--version"})
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("error = %v, want ErrVersion", err)
	}
}

func TestSlogLevel(t *testing.T) {
	cases := map[string]string{"debug": "DEBUG", "info": "INFO", "WARN": "WARN", "error": "ERROR", "": "INFO"}
	for in, want := range cases {
		if got := (Config{LogLevel: in}).SlogLevel().String(); got != want {
			t.Errorf("SlogLevel(%q) = %s, want %s", in, got, want)
		}
	}
}
