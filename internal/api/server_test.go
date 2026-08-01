package api

import (
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
	return NewServer(p, opts).Router()
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
