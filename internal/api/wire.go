package api

import (
	"encoding/json"
	"net/http"

	"github.com/goodmannershosting/route53-dnsweaver-webhook/internal/route53"
)

// maxRequestBody bounds decoding of untrusted input. dnsweaver's payloads are
// a few hundred bytes.
const maxRequestBody = 64 << 10

// ---- Wire types: must match dnsweaver's providers/webhook contract exactly ----

// RecordRequest is the request body dnsweaver sends for POST /create.
type RecordRequest struct {
	Hostname string   `json:"hostname"`
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	TTL      int      `json:"ttl"`
	SRV      *SRVData `json:"srv,omitempty"`
}

// SRVData carries SRV-specific fields.
type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
}

// DeleteRequest is the request body dnsweaver sends for DELETE /delete.
type DeleteRequest struct {
	Hostname string `json:"hostname"`
	Type     string `json:"type,omitempty"`
}

// UpdateRequest is the request body dnsweaver sends for PUT /update.
type UpdateRequest struct {
	Hostname string   `json:"hostname"`
	Type     string   `json:"type"`
	OldValue string   `json:"old_value"`
	NewValue string   `json:"new_value"`
	TTL      int      `json:"ttl"`
	SRV      *SRVData `json:"srv,omitempty"`
	OldSRV   *SRVData `json:"old_srv,omitempty"`
}

// RecordResponse is a single record as returned by GET /list.
type RecordResponse struct {
	Hostname string   `json:"hostname"`
	Type     string   `json:"type"`
	Value    string   `json:"value"`
	TTL      int      `json:"ttl,omitempty"`
	ID       string   `json:"id,omitempty"`
	SRV      *SRVData `json:"srv,omitempty"`
}

// ErrorResponse is the error body shape dnsweaver knows how to parse.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// ---- Mapping ----

func (s *SRVData) toDomain() *route53.SRV {
	if s == nil {
		return nil
	}
	return &route53.SRV{Priority: s.Priority, Weight: s.Weight, Port: s.Port}
}

func fromDomainSRV(s *route53.SRV) *SRVData {
	if s == nil {
		return nil
	}
	return &SRVData{Priority: s.Priority, Weight: s.Weight, Port: s.Port}
}

func (r RecordRequest) toDomain() route53.Record {
	return route53.Record{
		Hostname: r.Hostname,
		Type:     route53.RecordType(r.Type),
		Value:    r.Value,
		TTL:      r.TTL,
		SRV:      r.SRV.toDomain(),
	}
}

func (r UpdateRequest) toDomain() route53.Record {
	return route53.Record{
		Hostname: r.Hostname,
		Type:     route53.RecordType(r.Type),
		Value:    r.NewValue,
		TTL:      r.TTL,
		SRV:      r.SRV.toDomain(),
	}
}

func toResponses(records []route53.Record) []RecordResponse {
	out := make([]RecordResponse, 0, len(records))
	for _, rec := range records {
		out = append(out, RecordResponse{
			Hostname: rec.Hostname,
			Type:     string(rec.Type),
			Value:    rec.Value,
			TTL:      rec.TTL,
			SRV:      fromDomainSRV(rec.SRV),
		})
	}
	return out
}

// ---- JSON helpers ----

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return json.NewDecoder(r.Body).Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, errMsg, detail string) {
	writeJSON(w, status, ErrorResponse{Error: errMsg, Message: detail, Code: status})
}
