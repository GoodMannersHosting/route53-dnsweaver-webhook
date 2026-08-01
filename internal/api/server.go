// Package api serves dnsweaver's webhook provider contract over HTTP.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/route53"
)

// Provider is the DNS backend the handlers drive.
type Provider interface {
	Ping(ctx context.Context) error
	List(ctx context.Context) ([]route53.Record, error)
	Upsert(ctx context.Context, rec route53.Record) error
	Delete(ctx context.Context, hostname, recordType string) (int, error)
}

// Options configures a Server. Leaving both AuthHeader and AuthToken empty
// disables the shared-secret check; setting only one is an error.
type Options struct {
	AuthHeader string
	AuthToken  string
	Logger     *slog.Logger
}

// Server implements dnsweaver's webhook provider contract.
type Server struct {
	provider    Provider
	log         *slog.Logger
	authHeader  string
	authDigest  [sha256.Size]byte
	authEnabled bool
}

// NewServer wires a Provider up to the webhook contract. Half-configured auth
// is rejected rather than quietly serving an unprotected endpoint. config
// already refuses that combination, so this is about keeping the insecure
// state unrepresentable here too instead of merely unreachable from one
// caller.
func NewServer(p Provider, opts Options) (*Server, error) {
	if (opts.AuthHeader == "") != (opts.AuthToken == "") {
		return nil, errors.New("api: auth header and token must be set together")
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	s := &Server{provider: p, log: log, authHeader: opts.AuthHeader}
	if opts.AuthHeader != "" {
		s.authEnabled = true
		s.authDigest = sha256.Sum256([]byte(opts.AuthToken))
	}
	return s, nil
}

// Router returns the fully wired chi router.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	// Deliberately no middleware.RealIP: it trusts X-Forwarded-For, which any
	// client can set, and this service isn't guaranteed to sit behind a proxy
	// that overwrites it.
	// Logging wraps the panic guard, not the other way round: a panic that
	// unwound past logRequests would skip its trailing log call, losing the
	// access-log line for the one request most worth having one.
	r.Use(s.logRequests)
	r.Use(s.recoverPanics)
	r.Use(s.requireAuth)

	r.Get("/ping", s.handlePing)
	r.Get("/list", s.handleList)
	r.Post("/create", s.handleCreate)
	r.Put("/update", s.handleUpdate)
	r.Delete("/delete", s.handleDelete)

	// chi runs middleware before routing, so these stay behind the auth check
	// and an unauthenticated caller learns nothing about which routes exist.
	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found", "")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "")
	})

	return r
}

// ---- Middleware ----

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized", "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorized compares digests rather than raw tokens so neither the token
// length nor its contents are observable through response timing.
func (s *Server) authorized(r *http.Request) bool {
	if !s.authEnabled {
		return true
	}
	got := sha256.Sum256([]byte(r.Header.Get(s.authHeader)))
	return subtle.ConstantTimeCompare(got[:], s.authDigest[:]) == 1
}

// recoverPanics keeps a panicking handler from killing the connection without
// a reply, and keeps the error body in the shape dnsweaver parses. chi's own
// Recoverer writes a plain-text 500 to os.Stderr instead.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// net/http compares ErrAbortHandler by identity in conn.serve, so
			// a wrapped one wouldn't abort the connection anyway. Matching
			// that exactly keeps the two in agreement.
			//nolint:errorlint // panic values are not wrapped errors
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				s.log.Error("panic serving request",
					"panic", rec,
					"path", r.URL.Path,
					"request_id", middleware.GetReqID(r.Context()))
				// A handler that already sent a status can't be given a clean
				// 500; writing another would only log "superfluous
				// WriteHeader" and append junk to a half-sent body.
				if ww, ok := w.(middleware.WrapResponseWriter); ok && ww.Status() != 0 {
					return
				}
				writeError(w, http.StatusInternalServerError, "internal error", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()))
	})
}

// ---- Handlers ----

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if err := s.provider.Ping(r.Context()); err != nil {
		s.fail(w, r, http.StatusServiceUnavailable, "route53 unreachable", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	records, err := s.provider.List(r.Context())
	if err != nil {
		s.fail(w, r, http.StatusBadGateway, "route53 list failed", err)
		return
	}
	writeJSON(w, http.StatusOK, toResponses(records))
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req RecordRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if err := s.provider.Upsert(r.Context(), req.toDomain()); err != nil {
		s.failChange(w, r, err, req.Hostname)
		return
	}
	s.log.Info("created record", "hostname", req.Hostname, "type", req.Type, "value", req.Value)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var req UpdateRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	// Route53 UPSERT replaces the whole record set, so the old value isn't
	// needed to perform the change - only to log what's changing.
	if err := s.provider.Upsert(r.Context(), req.toDomain()); err != nil {
		s.failChange(w, r, err, req.Hostname)
		return
	}
	s.log.Info("updated record", "hostname", req.Hostname, "type", req.Type,
		"old_value", req.OldValue, "new_value", req.NewValue)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req DeleteRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	deleted, err := s.provider.Delete(r.Context(), req.Hostname, req.Type)
	if err != nil {
		s.failChange(w, r, err, req.Hostname)
		return
	}
	// Deleting a record that isn't there is a success, not a 404: dnsweaver
	// re-issues deletes during reconciliation.
	s.log.Info("deleted record", "hostname", req.Hostname, "type", req.Type, "count", deleted)
	w.WriteHeader(http.StatusOK)
}

// ---- Error handling ----

// failChange separates caller mistakes from upstream failures so a malformed
// request doesn't get blamed on Route53.
func (s *Server) failChange(w http.ResponseWriter, r *http.Request, err error, hostname string) {
	if errors.Is(err, route53.ErrInvalid) {
		writeError(w, http.StatusBadRequest, err.Error(), "")
		return
	}
	// The request is well-formed; the zone just holds something this provider
	// won't overwrite, and retrying the same call won't change that.
	if errors.Is(err, route53.ErrConflict) {
		writeError(w, http.StatusConflict, err.Error(), "")
		return
	}
	s.fail(w, r, http.StatusBadGateway, "route53 change failed", err, "hostname", hostname)
}

// fail logs the upstream error and returns only a generic message. AWS error
// strings carry request IDs, zone IDs and account hints the caller has no
// need for.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string, err error, attrs ...any) {
	s.log.Error(msg, append([]any{
		"error", err,
		"request_id", middleware.GetReqID(r.Context()),
	}, attrs...)...)
	writeError(w, status, msg, "")
}
