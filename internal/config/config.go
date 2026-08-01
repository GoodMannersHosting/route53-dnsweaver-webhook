// Package config resolves the service's settings from flags, environment
// variables and an optional config file, in that order of precedence.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	AppName = "route53-dnsweaver-webhook"

	// TTL bounds accepted by Route53.
	MinTTL = 1
	MaxTTL = 2147483647
)

// ErrHelp is returned when the user asked for --help, so the caller can exit
// cleanly rather than treating it as a failure.
var ErrHelp = pflag.ErrHelp

// ErrVersion is returned when the user asked for --version. The caller owns
// the version string, so it prints and exits rather than Load doing it.
var ErrVersion = errors.New("version requested")

var hostedZoneIDPattern = regexp.MustCompile(`^Z[A-Z0-9]{1,31}$`)

// Config is the fully resolved, validated configuration.
type Config struct {
	HostedZoneID  string `mapstructure:"hosted-zone-id"`
	DefaultTTL    int    `mapstructure:"default-ttl"`
	Port          int    `mapstructure:"port"`
	AuthHeader    string `mapstructure:"auth-header"`
	AuthToken     string `mapstructure:"auth-token"`
	AuthTokenFile string `mapstructure:"auth-token-file"`
	LogLevel      string `mapstructure:"log-level"`
}

// Addr is the listen address for the HTTP server.
func (c Config) Addr() string { return ":" + strconv.Itoa(c.Port) }

// AuthEnabled reports whether incoming requests are checked against a shared
// secret. Load guarantees the header and token are either both set or neither.
func (c Config) AuthEnabled() bool { return c.AuthHeader != "" && c.AuthToken != "" }

// SlogLevel maps the configured level name onto slog's levels.
func (c Config) SlogLevel() slog.Level {
	switch strings.ToLower(c.LogLevel) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Load parses args, layers in environment variables and any config file, and
// validates the result.
func Load(args []string) (Config, error) {
	fs := flagSet()
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	// Answered before any validation so --version works on a host that has
	// no zone id or credentials configured.
	if showVersion, _ := fs.GetBool("version"); showVersion {
		return Config{}, ErrVersion
	}

	v := viper.New()
	bindEnv(v)
	if err := v.BindPFlags(fs); err != nil {
		return Config{}, fmt.Errorf("binding flags: %w", err)
	}
	if err := readConfigFile(v, fs); err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("decoding configuration: %w", err)
	}
	if err := cfg.resolveToken(); err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func flagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet(AppName, pflag.ContinueOnError)
	fs.String("config", "", "path to a config file (default: ./config.yaml or /etc/"+AppName+"/config.yaml)")
	fs.String("hosted-zone-id", "", "Route53 hosted zone to manage [ROUTE53_HOSTED_ZONE_ID]")
	fs.Int("default-ttl", 300, "TTL applied when the caller doesn't send one [ROUTE53_DEFAULT_TTL]")
	fs.Int("port", 8080, "port to listen on [PORT]")
	fs.String("auth-header", "", "header carrying the shared secret, e.g. X-Webhook-Token [WEBHOOK_AUTH_HEADER]")
	// Deliberately no --auth-token flag: process arguments are readable by
	// every user on the host. The token comes from the environment, a file,
	// or the config file.
	fs.String("auth-token-file", "", "file holding the shared secret [WEBHOOK_AUTH_TOKEN_FILE]")
	fs.String("log-level", "info", "debug, info, warn or error [LOG_LEVEL]")
	fs.Bool("version", false, "print the version and exit")
	return fs
}

// bindEnv maps the historical environment variable names onto config keys.
// They don't share a prefix, so each is bound explicitly rather than through
// AutomaticEnv.
func bindEnv(v *viper.Viper) {
	//nolint:gosec // G101: these are environment variable names, not values
	for key, env := range map[string]string{
		"hosted-zone-id":  "ROUTE53_HOSTED_ZONE_ID",
		"default-ttl":     "ROUTE53_DEFAULT_TTL",
		"port":            "PORT",
		"auth-header":     "WEBHOOK_AUTH_HEADER",
		"auth-token":      "WEBHOOK_AUTH_TOKEN",
		"auth-token-file": "WEBHOOK_AUTH_TOKEN_FILE",
		"log-level":       "LOG_LEVEL",
	} {
		// BindEnv only fails when called with no arguments.
		_ = v.BindEnv(key, env)
	}
}

func readConfigFile(v *viper.Viper, fs *pflag.FlagSet) error {
	path, _ := fs.GetString("config")
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("reading config file: %w", err)
		}
		return nil
	}

	v.SetConfigName("config")
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/" + AppName)

	var notFound viper.ConfigFileNotFoundError
	if err := v.ReadInConfig(); err != nil && !errors.As(err, &notFound) {
		return fmt.Errorf("reading config file: %w", err)
	}
	return nil
}

// resolveToken loads the shared secret from disk when a file is configured.
// An unreadable file is an error rather than a fallback: a failed secret
// mount must not quietly leave the endpoint open.
func (c *Config) resolveToken() error {
	c.AuthToken = strings.TrimSpace(c.AuthToken)
	if c.AuthTokenFile == "" {
		return nil
	}
	b, err := os.ReadFile(c.AuthTokenFile)
	if err != nil {
		return fmt.Errorf("reading auth token file: %w", err)
	}
	c.AuthToken = strings.TrimSpace(string(b))
	return nil
}

func (c *Config) validate() error {
	c.HostedZoneID = strings.TrimPrefix(strings.TrimSpace(c.HostedZoneID), "/hostedzone/")
	if !hostedZoneIDPattern.MatchString(c.HostedZoneID) {
		return errors.New("hosted zone id must look like Z0123456789ABCDEFGHI")
	}
	if c.DefaultTTL < MinTTL || c.DefaultTTL > MaxTTL {
		return fmt.Errorf("default ttl must be between %d and %d", MinTTL, MaxTTL)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	// Fail closed: a half-configured shared secret would otherwise start up
	// silently unauthenticated, the opposite of what the operator asked for.
	c.AuthHeader = strings.TrimSpace(c.AuthHeader)
	if (c.AuthHeader == "") != (c.AuthToken == "") {
		return errors.New("auth header and auth token must be set together, or neither")
	}
	return nil
}
