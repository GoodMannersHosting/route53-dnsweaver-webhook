package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/route53"
)

// fakeProvider stands in for the Route53 backend.
type fakeProvider struct {
	records []route53.Record
	deleted int

	pingErr   error
	listErr   error
	upsertErr error
	deleteErr error

	upserts       []route53.Record
	deleteCalls   []string
	deletedTypes  []string
	panicOnUpsert bool
}

func (f *fakeProvider) Ping(context.Context) error { return f.pingErr }

func (f *fakeProvider) List(context.Context) ([]route53.Record, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.records == nil {
		return []route53.Record{}, nil
	}
	return f.records, nil
}

func (f *fakeProvider) Upsert(_ context.Context, rec route53.Record) error {
	if f.panicOnUpsert {
		panic("boom")
	}
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.upserts = append(f.upserts, rec)
	return nil
}

func (f *fakeProvider) Delete(_ context.Context, hostname, recordType string) (int, error) {
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	f.deleteCalls = append(f.deleteCalls, hostname)
	f.deletedTypes = append(f.deletedTypes, recordType)
	return f.deleted, nil
}

func testRouter(p Provider, opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s, err := NewServer(p, opts)
	if err != nil {
		// Every caller here passes a valid combination; a failure means the
		// test itself is wrong.
		panic(err)
	}
	return s.Router()
}

func do(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuth(t *testing.T) {
	h := testRouter(&fakeProvider{}, Options{AuthHeader: "X-Webhook-Token", AuthToken: "s3cret"})

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"no header", nil, http.StatusUnauthorized},
		{"wrong token", map[string]string{"X-Webhook-Token": "nope"}, http.StatusUnauthorized},
		{"token prefix", map[string]string{"X-Webhook-Token": "s3cre"}, http.StatusUnauthorized},
		{"correct token", map[string]string{"X-Webhook-Token": "s3cret"}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := do(t, h, http.MethodGet, "/ping", "", tc.headers).Code; got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}

	// chi runs middleware before routing, so unknown paths must not reveal
	// themselves before authenticating.
	if got := do(t, h, http.MethodGet, "/admin", "", nil).Code; got != http.StatusUnauthorized {
		t.Errorf("unknown path status = %d, want 401", got)
	}
}

func TestAuthDisabledWhenUnconfigured(t *testing.T) {
	h := testRouter(&fakeProvider{}, Options{})
	if got := do(t, h, http.MethodGet, "/ping", "", nil).Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}

func TestNotFoundAndMethodNotAllowedAreJSON(t *testing.T) {
	h := testRouter(&fakeProvider{}, Options{})

	cases := []struct {
		name, method, path string
		want               int
	}{
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound},
		{"wrong method", http.MethodPost, "/list", http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, h, tc.method, tc.path, "", nil)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("content-type = %q, want application/json", ct)
			}
			var body ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not the error shape dnsweaver parses: %v", err)
			}
			if body.Code != tc.want {
				t.Errorf("body code = %d, want %d", body.Code, tc.want)
			}
		})
	}
}

func TestUpstreamErrorIsNotLeaked(t *testing.T) {
	p := &fakeProvider{pingErr: errors.New("AccessDenied: arn:aws:iam::123456789012:role/secret is not authorized")}
	rec := do(t, testRouter(p, Options{}), http.MethodGet, "/ping", "", nil)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "123456789012") {
		t.Errorf("response leaked upstream detail: %s", rec.Body.String())
	}
}

func TestPanicIsRecoveredAsJSON(t *testing.T) {
	h := testRouter(&fakeProvider{panicOnUpsert: true}, Options{})
	rec := do(t, h, http.MethodPost, "/create", `{"hostname":"app.example.com","type":"A","value":"203.0.113.10"}`, nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	var body ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("panic response is not JSON: %v", err)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Error("panic detail leaked to the client")
	}
}

func TestNewServerRejectsHalfConfiguredAuth(t *testing.T) {
	// The dangerous half is a header with no token, which used to leave the
	// endpoint open. Both directions are rejected so neither can be reached.
	for name, opts := range map[string]Options{
		"header without token": {AuthHeader: "X-Webhook-Token"},
		"token without header": {AuthToken: "s3cret"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServer(&fakeProvider{}, opts); err == nil {
				t.Error("expected an error rather than a silently unprotected endpoint")
			}
		})
	}
}

func TestPanicIsStillAccessLogged(t *testing.T) {
	// A panic used to unwind past the logging middleware, so the one request
	// most worth a log line was the only one that never got one.
	var logged bytes.Buffer
	h := testRouter(&fakeProvider{panicOnUpsert: true},
		Options{Logger: slog.New(slog.NewJSONHandler(&logged, nil))})

	rec := do(t, h, http.MethodPost, "/create",
		`{"hostname":"app.example.com","type":"A","value":"203.0.113.10"}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(logged.String(), `"msg":"request"`) {
		t.Errorf("no access-log line for the panicking request: %s", logged.String())
	}
	if !strings.Contains(logged.String(), `"status":500`) {
		t.Errorf("access-log line did not record the 500: %s", logged.String())
	}
}

func TestRecoverPanicsLeavesAPartialResponseAlone(t *testing.T) {
	s, err := NewServer(&fakeProvider{}, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Once a status is on the wire a clean 500 is no longer possible, and
	// writing one would only log "superfluous WriteHeader" and tack an error
	// object onto a half-sent body.
	h := s.logRequests(s.recoverPanics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"partial":`))
		panic("boom")
	})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want the 202 already sent", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "internal error") {
		t.Errorf("appended an error body to a partial response: %s", rec.Body)
	}
}

func TestListEmptyReturnsArray(t *testing.T) {
	rec := do(t, testRouter(&fakeProvider{}, Options{}), http.MethodGet, "/list", "", nil)
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body = %q, want []", got)
	}
}

func TestListMapsRecords(t *testing.T) {
	p := &fakeProvider{records: []route53.Record{
		{Hostname: "app.example.com", Type: route53.TypeA, Value: "203.0.113.10", TTL: 300},
		{
			Hostname: "_https._tcp.example.com",
			Type:     route53.TypeSRV,
			Value:    "target.example.com",
			TTL:      60,
			SRV:      &route53.SRV{Priority: 10, Weight: 20, Port: 443},
		},
	}}

	rec := do(t, testRouter(p, Options{}), http.MethodGet, "/list", "", nil)

	var got []RecordResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}
	if got[0].Type != "A" || got[0].Value != "203.0.113.10" {
		t.Errorf("unexpected first record: %+v", got[0])
	}
	if got[1].SRV == nil || got[1].SRV.Port != 443 {
		t.Errorf("SRV data was dropped: %+v", got[1])
	}
}

func TestCreate(t *testing.T) {
	p := &fakeProvider{}
	rec := do(t, testRouter(p, Options{}), http.MethodPost, "/create",
		`{"hostname":"app.example.com","type":"A","value":"203.0.113.10","ttl":120}`, nil)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body)
	}
	if len(p.upserts) != 1 {
		t.Fatalf("got %d upserts, want 1", len(p.upserts))
	}
	want := route53.Record{Hostname: "app.example.com", Type: route53.TypeA, Value: "203.0.113.10", TTL: 120}
	if p.upserts[0] != want {
		t.Errorf("upsert = %+v, want %+v", p.upserts[0], want)
	}
}

func TestCreateSurfacesValidationAs400(t *testing.T) {
	p := &fakeProvider{upsertErr: errors.New("invalid record: value \"nope\" is not an IPv4 address")}
	// Wrap so errors.Is finds the sentinel the same way the real provider does.
	p.upsertErr = errors.Join(route53.ErrInvalid, p.upsertErr)

	rec := do(t, testRouter(p, Options{}), http.MethodPost, "/create",
		`{"hostname":"app.example.com","type":"A","value":"nope"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCreateSurfacesConflictAs409(t *testing.T) {
	// The request is fine; the zone holds an alias the provider won't
	// overwrite. Retrying won't help, so this is neither 400 nor 502.
	p := &fakeProvider{upsertErr: errors.Join(route53.ErrConflict,
		errors.New("app.example.com A is an alias or routing-policy record"))}

	rec := do(t, testRouter(p, Options{}), http.MethodPost, "/create",
		`{"hostname":"app.example.com","type":"A","value":"203.0.113.10"}`, nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409: %s", rec.Code, rec.Body)
	}
}

func TestDeleteSurfacesValidationAs400(t *testing.T) {
	p := &fakeProvider{deleteErr: errors.Join(route53.ErrInvalid,
		errors.New(`invalid record: invalid hostname "bad host"`))}

	rec := do(t, testRouter(p, Options{}), http.MethodDelete, "/delete",
		`{"hostname":"bad host"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUpstreamErrorIsNotLeakedOnAnyRoute(t *testing.T) {
	secret := errors.New("AccessDenied: arn:aws:iam::123456789012:role/secret is not authorized")

	cases := []struct {
		name, method, path, body string
		provider                 *fakeProvider
	}{
		{"list", http.MethodGet, "/list", "", &fakeProvider{listErr: secret}},
		{"create", http.MethodPost, "/create",
			`{"hostname":"app.example.com","type":"A","value":"203.0.113.10"}`,
			&fakeProvider{upsertErr: secret}},
		{"delete", http.MethodDelete, "/delete",
			`{"hostname":"app.example.com"}`, &fakeProvider{deleteErr: secret}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(t, testRouter(tc.provider, Options{}), tc.method, tc.path, tc.body, nil)
			if rec.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "123456789012") {
				t.Errorf("response leaked upstream detail: %s", rec.Body)
			}
		})
	}
}

func TestCreateRejectsMalformedBody(t *testing.T) {
	p := &fakeProvider{}
	rec := do(t, testRouter(p, Options{}), http.MethodPost, "/create", `{"hostname":`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if len(p.upserts) != 0 {
		t.Errorf("provider was called with %+v", p.upserts)
	}
}

func TestCreateRejectsOversizedBody(t *testing.T) {
	body := `{"hostname":"app.example.com","type":"TXT","value":"` + strings.Repeat("a", maxRequestBody) + `"}`
	rec := do(t, testRouter(&fakeProvider{}, Options{}), http.MethodPost, "/create", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestUpdateSendsNewValue(t *testing.T) {
	p := &fakeProvider{}
	body := `{"hostname":"app.example.com","type":"A","old_value":"203.0.113.10","new_value":"203.0.113.11","ttl":120}`
	rec := do(t, testRouter(p, Options{}), http.MethodPut, "/update", body, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if len(p.upserts) != 1 || p.upserts[0].Value != "203.0.113.11" {
		t.Errorf("unexpected upserts: %+v", p.upserts)
	}
}

func TestDelete(t *testing.T) {
	p := &fakeProvider{deleted: 1}
	rec := do(t, testRouter(p, Options{}), http.MethodDelete, "/delete",
		`{"hostname":"app.example.com","type":"A"}`, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body)
	}
	if len(p.deleteCalls) != 1 || p.deleteCalls[0] != "app.example.com" || p.deletedTypes[0] != "A" {
		t.Errorf("unexpected delete calls: %v %v", p.deleteCalls, p.deletedTypes)
	}
}

func TestDeleteMissingRecordIsStillOK(t *testing.T) {
	rec := do(t, testRouter(&fakeProvider{deleted: 0}, Options{}), http.MethodDelete, "/delete",
		`{"hostname":"gone.example.com"}`, nil)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}
