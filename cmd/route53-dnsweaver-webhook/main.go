// Command route53-dnsweaver-webhook implements dnsweaver's generic "webhook"
// provider contract (GET /ping, GET /list, POST /create, DELETE /delete,
// PUT /update) backed by AWS Route53.
//
// dnsweaver (https://github.com/maxfield-allison/dnsweaver) watches Docker
// container labels (Traefik, Caddy, nginx-proxy, or its own dnsweaver.* /
// dnsweaver.records.<name>.* labels), extracts hostnames plus optional
// per-record hints, and reconciles them against whichever DNS providers you
// configure. This binary is that provider for Route53, which dnsweaver does
// not ship with out of the box.
//
// Run --help for the full set of flags. Every flag has an equivalent
// environment variable, and settings can also come from a config file.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"

	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/api"
	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/config"
	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/route53"
)

// version is overwritten at link time by GoReleaser and by the Dockerfile's
// VERSION build arg. A binary built with a plain `go build` reports "dev".
var version = "dev"

const (
	// Above the provider's longest per-call budget (a 30s list), so a Route53
	// call already in flight when SIGTERM arrives can finish instead of being
	// abandoned mid-change and reported as a failed exit. Container runtimes
	// need a matching grace period or they send SIGKILL first.
	shutdownTimeout = 35 * time.Second

	// Read/write budgets sit above the provider's per-call timeouts so a slow
	// upstream still yields a response body.
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
)

func main() {
	// Bootstrap logger so configuration failures are reported in the same
	// JSON shape as everything else; run() swaps in the configured level.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if err := run(context.Background(), os.Args[1:]); err != nil {
		if errors.Is(err, config.ErrHelp) {
			return
		}
		if errors.Is(err, config.ErrVersion) {
			fmt.Println(version)
			return
		}
		slog.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	slog.SetDefault(logger)

	provider, err := newProvider(ctx, cfg)
	if err != nil {
		return err
	}

	if !cfg.AuthEnabled() {
		logger.Warn("no shared secret configured; anyone who can reach this port can change DNS records",
			"hint", "set WEBHOOK_AUTH_HEADER and WEBHOOK_AUTH_TOKEN(_FILE)")
	}

	srv, err := api.NewServer(provider, api.Options{
		AuthHeader: cfg.AuthHeader,
		AuthToken:  cfg.AuthToken,
		Logger:     logger,
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           srv.Router(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	return serve(ctx, httpSrv, logger, cfg)
}

func newProvider(ctx context.Context, cfg config.Config) (*route53.Provider, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return route53.New(
		awsr53.NewFromConfig(awsCfg),
		cfg.HostedZoneID,
		cfg.DefaultTTL,
		config.MinTTL,
		config.MaxTTL,
	), nil
}

func serve(ctx context.Context, httpSrv *http.Server, logger *slog.Logger, cfg config.Config) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenErr := make(chan error, 1)
	go func() {
		logger.Info("listening",
			"version", version,
			"addr", cfg.Addr(),
			"zone_id", cfg.HostedZoneID,
			"auth_required", cfg.AuthEnabled())
		listenErr <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-listenErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
