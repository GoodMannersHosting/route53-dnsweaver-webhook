package route53

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// ErrInvalid marks a caller mistake - a malformed hostname, unsupported type,
// bad value or out-of-range TTL - so transport layers can answer 400 rather
// than blaming the upstream.
var ErrInvalid = errors.New("invalid record")

// RecordType is one of the DNS record types this provider manages.
type RecordType string

const (
	TypeA     RecordType = "A"
	TypeAAAA  RecordType = "AAAA"
	TypeCNAME RecordType = "CNAME"
	TypeTXT   RecordType = "TXT"
	TypeSRV   RecordType = "SRV"
)

// SRV carries the fields an SRV record needs beyond its target.
type SRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
}

// Record is a single DNS record in the flat form dnsweaver reconciles.
type Record struct {
	Hostname string
	Type     RecordType
	Value    string
	TTL      int
	SRV      *SRV
}

const (
	maxHostnameLen = 253
	maxLabelLen    = 63
	// maxTXTLen is the DNS character-string limit. Longer values need
	// splitting into several quoted segments, which this provider doesn't do.
	maxTXTLen = 255
)

// Underscores appear in SRV and ACME challenge names; an asterisk is a
// Route53 wildcard.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9_*-]+$`)

// ParseType normalizes and validates a record type name.
func ParseType(s string) (RecordType, error) {
	switch rt := RecordType(strings.ToUpper(strings.TrimSpace(s))); rt {
	case TypeA, TypeAAAA, TypeCNAME, TypeTXT, TypeSRV:
		return rt, nil
	default:
		return "", fmt.Errorf("%w: unsupported record type %q (supported: A, AAAA, CNAME, TXT, SRV)", ErrInvalid, s)
	}
}

// NormalizeFQDN validates a hostname and returns it in the trailing-dot form
// Route53 uses.
func NormalizeFQDN(hostname string) (string, error) {
	h := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	if h == "" {
		return "", fmt.Errorf("%w: hostname is required", ErrInvalid)
	}
	if len(h) > maxHostnameLen {
		return "", fmt.Errorf("%w: hostname must be at most %d characters", ErrInvalid, maxHostnameLen)
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > maxLabelLen || !labelPattern.MatchString(label) {
			return "", fmt.Errorf("%w: invalid hostname %q", ErrInvalid, h)
		}
	}
	return h + ".", nil
}

// resourceRecordSet renders a Record the way Route53 stores it.
func resourceRecordSet(rec Record, minTTL, maxTTL int) (*r53types.ResourceRecordSet, error) {
	fqdn, err := NormalizeFQDN(rec.Hostname)
	if err != nil {
		return nil, err
	}
	rt, err := ParseType(string(rec.Type))
	if err != nil {
		return nil, err
	}
	if rec.TTL < minTTL || rec.TTL > maxTTL {
		return nil, fmt.Errorf("%w: ttl must be between %d and %d", ErrInvalid, minTTL, maxTTL)
	}
	content, err := recordValue(rt, rec.Value, rec.SRV)
	if err != nil {
		return nil, err
	}

	return &r53types.ResourceRecordSet{
		Name:            aws.String(fqdn),
		Type:            r53types.RRType(rt),
		TTL:             aws.Int64(int64(rec.TTL)),
		ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(content)}},
	}, nil
}

// recordValue validates the caller's value and renders it for its type.
func recordValue(rt RecordType, value string, srv *SRV) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: value is required", ErrInvalid)
	}

	switch rt {
	case TypeA:
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() {
			return "", fmt.Errorf("%w: value %q is not an IPv4 address", ErrInvalid, value)
		}
		return addr.String(), nil
	case TypeAAAA:
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is6() || addr.Is4In6() {
			return "", fmt.Errorf("%w: value %q is not an IPv6 address", ErrInvalid, value)
		}
		return addr.String(), nil
	case TypeCNAME:
		if _, err := NormalizeFQDN(value); err != nil {
			return "", fmt.Errorf("invalid cname target: %w", err)
		}
		return value, nil
	case TypeTXT:
		if len(value) > maxTXTLen {
			return "", fmt.Errorf("%w: txt values longer than %d bytes are not supported", ErrInvalid, maxTXTLen)
		}
		return quoteTXT(value), nil
	case TypeSRV:
		if srv == nil {
			return "", fmt.Errorf("%w: srv data is required for SRV records", ErrInvalid)
		}
		target, err := NormalizeFQDN(value)
		if err != nil {
			return "", fmt.Errorf("invalid srv target: %w", err)
		}
		return fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, target), nil
	default:
		return "", fmt.Errorf("%w: unsupported record type %q", ErrInvalid, rt)
	}
}

// toRecords flattens one Route53 record set into the flat records dnsweaver
// expects, one per value.
func toRecords(rs r53types.ResourceRecordSet) []Record {
	if !isManageable(rs) {
		return nil
	}

	hostname := strings.TrimSuffix(unescapeName(aws.ToString(rs.Name)), ".")
	rt := RecordType(rs.Type)
	ttl := int(aws.ToInt64(rs.TTL))

	out := make([]Record, 0, len(rs.ResourceRecords))
	for _, rr := range rs.ResourceRecords {
		rec := Record{
			Hostname: hostname,
			Type:     rt,
			Value:    aws.ToString(rr.Value),
			TTL:      ttl,
		}
		switch rt {
		case TypeTXT:
			rec.Value = unquoteTXT(rec.Value)
		case TypeSRV:
			if target, srv, ok := parseSRV(rec.Value); ok {
				rec.Value, rec.SRV = target, srv
			}
		}
		out = append(out, rec)
	}
	return out
}

func parseSRV(value string) (string, *SRV, bool) {
	parts := strings.Fields(value)
	if len(parts) != 4 {
		return "", nil, false
	}
	nums := make([]uint16, 3)
	for i, p := range parts[:3] {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return "", nil, false
		}
		nums[i] = uint16(n)
	}
	return strings.TrimSuffix(parts[3], "."), &SRV{Priority: nums[0], Weight: nums[1], Port: nums[2]}, true
}

// sameName compares Route53 record names. Route53 lowercases names and
// escapes special characters, so a wildcard record comes back as
// "\052.example.com." rather than "*.example.com.".
func sameName(name, fqdn string) bool {
	return strings.EqualFold(unescapeName(name), fqdn)
}

// unescapeName resolves the \ooo octal escapes Route53 uses for characters
// outside the printable ASCII range it accepts verbatim.
func unescapeName(name string) string {
	if !strings.Contains(name, `\`) {
		return name
	}
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		if name[i] == '\\' && i+3 < len(name) {
			if n, err := strconv.ParseUint(name[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(name[i])
	}
	return b.String()
}

// quoteTXT wraps a TXT value the way Route53 expects, unless the caller
// already supplied a quoted value.
func quoteTXT(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// unquoteTXT reverses quoteTXT, concatenating the segments of a multi-string
// TXT record the way resolvers do.
func unquoteTXT(v string) string {
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v))
	var quoted, escaped bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case escaped:
			b.WriteByte(c)
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case quoted:
			b.WriteByte(c)
		}
	}
	return b.String()
}
