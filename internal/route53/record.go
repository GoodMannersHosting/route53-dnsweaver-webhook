package route53

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// ErrInvalid marks a caller mistake - a malformed hostname, unsupported type,
// bad value or out-of-range TTL - so transport layers can answer 400 rather
// than blaming the upstream.
var ErrInvalid = errors.New("invalid record")

// ErrConflict marks a well-formed request that collides with zone state this
// provider refuses to touch, such as an alias record already sitting at the
// name. The request isn't wrong, so transport layers answer 409 rather than
// 400 or blaming the upstream.
var ErrConflict = errors.New("conflicting record")

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

// Underscores appear in SRV and ACME challenge names. Hyphens are allowed
// inside a label but not at either end. Asterisks are handled separately by
// NormalizeFQDN, because a wildcard is only a wildcard as a whole label.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?$`)

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
	for i, label := range strings.Split(h, ".") {
		// Route53 treats an asterisk as a wildcard only when it is the whole
		// leftmost label. Anywhere else it is stored as the literal character
		// and the record resolves for nothing, so reject it here rather than
		// letting the API accept a name that can never match.
		if label == "*" && i == 0 {
			continue
		}
		if len(label) > maxLabelLen || !labelPattern.MatchString(label) {
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
		// Store the normalized target rather than the raw one, so a CNAME
		// written as "Target.Example.COM" reads back as the same value SRV
		// would have stored for it.
		target, err := NormalizeFQDN(value)
		if err != nil {
			return "", fmt.Errorf("invalid cname target: %w", err)
		}
		return target, nil
	case TypeTXT:
		// Measure the character-string Route53 will actually hold, not the
		// caller's spelling of it: a pre-quoted value carries two extra bytes
		// and an escaped one expands.
		quoted := quoteTXT(value)
		if len(unquoteTXT(quoted)) > maxTXTLen {
			return "", fmt.Errorf("%w: txt values longer than %d bytes are not supported", ErrInvalid, maxTXTLen)
		}
		return quoted, nil
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
			target, srv, ok := parseSRV(rec.Value)
			if !ok {
				// Same rule as isManageable: a value this contract cannot
				// express is hidden rather than handed over as a four-field
				// string that fails validation on the way back.
				continue
			}
			rec.Value, rec.SRV = target, srv
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

// escapeName renders a name the way Route53 stores it: lowercased, with every
// character outside the set it keeps verbatim written as a \ooo octal escape.
// It is the inverse of unescapeName, and running a name through both yields
// the canonical form regardless of which one the caller started from.
func escapeName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, `\%03o`, c)
	}
	return b.String()
}

// nameSortKey renders a name the way Route53 orders record sets: canonically
// escaped with the labels reversed, so www.example.com sorts as
// com.example.www. Comparing these keys is what tells a scan whether it has
// reached the name it wants or already gone past it.
//
// Both halves matter. Escaping keeps a wildcard sorting as Route53 stores it
// (\052, so after digits) rather than as the bare asterisk the caller wrote,
// and the trailing dot changes the order of any name containing a character
// below "." in ASCII.
func nameSortKey(name string) string {
	labels := strings.Split(strings.TrimSuffix(escapeName(unescapeName(name)), "."), ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".") + "."
}

// quoteTXT wraps a TXT value the way Route53 expects. A value that is already
// one well-formed quoted string is passed through so callers can supply the
// stored form; everything else is quoted and escaped, including a value that
// merely happens to begin and end with a quote.
func quoteTXT(v string) string {
	if isQuotedTXT(v) {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// isQuotedTXT reports whether v is exactly one quoted character-string with
// its interior quotes and backslashes escaped. Checking only the outer bytes
// would pass `"a" and "b"` straight through, which Route53 then rejects.
func isQuotedTXT(v string) bool {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return false
	}
	body := v[1 : len(v)-1]
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			// A trailing backslash escapes the closing quote, leaving the
			// string unterminated.
			if i++; i >= len(body) {
				return false
			}
		case '"':
			return false
		}
	}
	return true
}

// txtSegments counts the character-strings in a stored TXT value. Route53
// splits anything over 255 bytes into several quoted strings.
func txtSegments(v string) int {
	var n int
	var quoted, escaped bool
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case escaped:
			escaped = false
		case quoted && c == '\\':
			escaped = true
		case c == '"':
			if !quoted {
				n++
			}
			quoted = !quoted
		}
	}
	return n
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
