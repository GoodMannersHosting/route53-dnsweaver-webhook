package route53

import (
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

const (
	testMinTTL = 1
	testMaxTTL = 2147483647
)

func TestNormalizeFQDN(t *testing.T) {
	valid := map[string]string{
		"app.example.com":   "app.example.com.",
		"app.example.com.":  "app.example.com.",
		" app.example.com ": "app.example.com.",
		"*.example.com":     "*.example.com.",
		"_https._tcp.x.com": "_https._tcp.x.com.",
	}
	for in, want := range valid {
		got, err := NormalizeFQDN(in)
		if err != nil {
			t.Errorf("NormalizeFQDN(%q) unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeFQDN(%q) = %q, want %q", in, got, want)
		}
	}

	invalid := []string{
		"", "   ", "app..example.com", "app example.com", "app/../evil.com", "app\n.example.com",
		// Route53 only treats an asterisk as a wildcard when it is the whole
		// leftmost label. Elsewhere it is stored literally and the record
		// resolves for nothing, so it is a caller mistake, not a 502.
		"prod*.example.com", "*prod.example.com", "a.*.example.com", "app.example.*",
		"-app.example.com", "app-.example.com",
	}
	for _, in := range invalid {
		got, err := NormalizeFQDN(in)
		if err == nil {
			t.Errorf("NormalizeFQDN(%q) = %q, want error", in, got)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("NormalizeFQDN(%q) error should wrap ErrInvalid, got %v", in, err)
		}
	}
}

func TestResourceRecordSet_A(t *testing.T) {
	rrset, err := resourceRecordSet(Record{
		Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10", TTL: 300,
	}, testMinTTL, testMaxTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if aws.ToString(rrset.Name) != "app.example.com." {
		t.Errorf("Name = %q", aws.ToString(rrset.Name))
	}
	if rrset.Type != r53types.RRTypeA {
		t.Errorf("Type = %v", rrset.Type)
	}
	if aws.ToInt64(rrset.TTL) != 300 {
		t.Errorf("TTL = %v", aws.ToInt64(rrset.TTL))
	}
	if len(rrset.ResourceRecords) != 1 || aws.ToString(rrset.ResourceRecords[0].Value) != "203.0.113.10" {
		t.Errorf("unexpected resource records: %+v", rrset.ResourceRecords)
	}
}

func TestResourceRecordSet_RejectsBadValues(t *testing.T) {
	cases := map[string]Record{
		"A with hostname":  {Hostname: "app.example.com", Type: TypeA, Value: "app.example.com", TTL: 300},
		"A with IPv6":      {Hostname: "app.example.com", Type: TypeA, Value: "2001:db8::1", TTL: 300},
		"AAAA with IPv4":   {Hostname: "app.example.com", Type: TypeAAAA, Value: "203.0.113.10", TTL: 300},
		"empty value":      {Hostname: "app.example.com", Type: TypeA, Value: "  ", TTL: 300},
		"unsupported":      {Hostname: "app.example.com", Type: "MX", Value: "10 mail.example.com", TTL: 300},
		"cname junk":       {Hostname: "app.example.com", Type: TypeCNAME, Value: "not a hostname", TTL: 300},
		"ttl too large":    {Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10", TTL: testMaxTTL + 1},
		"srv without data": {Hostname: "_https._tcp.example.com", Type: TypeSRV, Value: "target.example.com", TTL: 300},
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := resourceRecordSet(rec, testMinTTL, testMaxTTL)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("error should wrap ErrInvalid, got %v", err)
			}
		})
	}
}

func TestResourceRecordSet_TXTQuoting(t *testing.T) {
	cases := map[string]string{
		`owner=dnsweaver`:  `"owner=dnsweaver"`,
		`"already-quoted"`: `"already-quoted"`,
		`say "hi"`:         `"say \"hi\""`,
		`back\slash`:       `"back\\slash"`,
	}
	for in, want := range cases {
		rrset, err := resourceRecordSet(Record{
			Hostname: "app.example.com", Type: TypeTXT, Value: in, TTL: 300,
		}, testMinTTL, testMaxTTL)
		if err != nil {
			t.Fatalf("resourceRecordSet(%q): %v", in, err)
		}
		if got := aws.ToString(rrset.ResourceRecords[0].Value); got != want {
			t.Errorf("TXT value for %q = %q, want %q", in, got, want)
		}
	}

	long := make([]byte, maxTXTLen+1)
	for i := range long {
		long[i] = 'a'
	}
	_, err := resourceRecordSet(Record{
		Hostname: "app.example.com", Type: TypeTXT, Value: string(long), TTL: 300,
	}, testMinTTL, testMaxTTL)
	if err == nil {
		t.Error("expected error for oversized TXT value")
	}
}

func TestTXTRoundTrip(t *testing.T) {
	values := []string{
		`owner=dnsweaver`, `say "hi"`, `back\slash`, `spaces and = signs`,
		// Begins and ends with a quote without being one quoted string. The
		// outer bytes alone would pass it through and Route53 would reject it.
		`"a" and "b"`,
	}
	for _, in := range values {
		if got := unquoteTXT(quoteTXT(in)); got != in {
			t.Errorf("round trip of %q = %q", in, got)
		}
	}
	if got := unquoteTXT(`"part-one" "part-two"`); got != "part-onepart-two" {
		t.Errorf("multi-segment TXT = %q", got)
	}
}

func TestIsQuotedTXT(t *testing.T) {
	for _, v := range []string{`""`, `"plain"`, `"say \"hi\""`, `"back\\slash"`} {
		if !isQuotedTXT(v) {
			t.Errorf("isQuotedTXT(%s) = false, want true", v)
		}
	}
	// Each of these looks quoted from the outside but is not a single
	// character-string, so passing it through reaches Route53 malformed.
	for _, v := range []string{``, `"`, `bare`, `"a" and "b"`, `"one" "two"`, `"trailing escape\"`} {
		if isQuotedTXT(v) {
			t.Errorf("isQuotedTXT(%s) = true, want false", v)
		}
	}
}

func TestNameSortKey(t *testing.T) {
	if got := nameSortKey("www.example.com."); got != "com.example.www." {
		t.Errorf("nameSortKey = %q, want the labels reversed", got)
	}

	// Route53 stores a wildcard escaped, and \052 sorts after a digit label
	// even though a bare asterisk sorts before one. Delete depends on this to
	// tell "not reached yet" from "already past it".
	wildcard := nameSortKey("*.example.com.")
	if wildcard != `com.example.\052.` {
		t.Fatalf("wildcard key = %q, want the escaped form", wildcard)
	}
	if got := nameSortKey(`\052.example.com.`); got != wildcard {
		t.Errorf("escaped spelling keyed as %q, want %q", got, wildcard)
	}
	if nameSortKey("0.example.com.") >= wildcard {
		t.Error("a digit label must sort before the escaped wildcard")
	}
	if nameSortKey("a.example.com.") <= wildcard {
		t.Error("a letter label must sort after the escaped wildcard")
	}
	if nameSortKey("APP.example.com.") != nameSortKey("app.example.com.") {
		t.Error("case must not change the key; Route53 stores names lowercased")
	}
}

func TestResourceRecordSet_CNAMENormalizesTarget(t *testing.T) {
	rrset, err := resourceRecordSet(Record{
		Hostname: "www.example.com", Type: TypeCNAME, Value: " target.example.com ", TTL: 300,
	}, testMinTTL, testMaxTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Dot-terminated, matching both what SRV stores and what Route53 hands
	// back on the next list, so a value doesn't change shape on round trip.
	if got := aws.ToString(rrset.ResourceRecords[0].Value); got != "target.example.com." {
		t.Errorf("CNAME value = %q, want the normalized target", got)
	}
}

func TestResourceRecordSet_TXTLimitCountsThePayload(t *testing.T) {
	// The quotes aren't part of the character-string, so a pre-quoted value
	// at exactly the limit has to be accepted rather than measured as 257.
	atLimit := `"` + strings.Repeat("a", maxTXTLen) + `"`
	if _, err := resourceRecordSet(Record{
		Hostname: "app.example.com", Type: TypeTXT, Value: atLimit, TTL: 300,
	}, testMinTTL, testMaxTTL); err != nil {
		t.Errorf("a %d-byte pre-quoted payload should fit: %v", maxTXTLen, err)
	}

	tooLong := `"` + strings.Repeat("a", maxTXTLen+1) + `"`
	if _, err := resourceRecordSet(Record{
		Hostname: "app.example.com", Type: TypeTXT, Value: tooLong, TTL: 300,
	}, testMinTTL, testMaxTTL); err == nil {
		t.Error("a pre-quoted payload over the limit should still be rejected")
	}
}

func TestResourceRecordSet_SRV(t *testing.T) {
	rrset, err := resourceRecordSet(Record{
		Hostname: "_https._tcp.example.com",
		Type:     TypeSRV,
		Value:    "target.example.com",
		TTL:      300,
		SRV:      &SRV{Priority: 10, Weight: 20, Port: 443},
	}, testMinTTL, testMaxTTL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := aws.ToString(rrset.ResourceRecords[0].Value)
	want := "10 20 443 target.example.com."
	if got != want {
		t.Errorf("SRV value = %q, want %q", got, want)
	}
}

func TestToRecords_A(t *testing.T) {
	recs := toRecords(recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10"))
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Hostname != "app.example.com" || rec.Type != TypeA || rec.Value != "203.0.113.10" || rec.TTL != 300 {
		t.Errorf("unexpected record: %+v", rec)
	}
}

func TestToRecords_MultiValue(t *testing.T) {
	rs := r53types.ResourceRecordSet{
		Name: aws.String("app.example.com."),
		Type: r53types.RRTypeA,
		TTL:  aws.Int64(60),
		ResourceRecords: []r53types.ResourceRecord{
			{Value: aws.String("203.0.113.10")},
			{Value: aws.String("203.0.113.11")},
		},
	}
	recs := toRecords(rs)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Value != "203.0.113.10" || recs[1].Value != "203.0.113.11" {
		t.Errorf("unexpected values: %+v", recs)
	}
}

func TestToRecords_UnescapesWildcard(t *testing.T) {
	recs := toRecords(recordSet(`\052.example.com.`, r53types.RRTypeA, "203.0.113.10"))
	if len(recs) != 1 || recs[0].Hostname != "*.example.com" {
		t.Fatalf("unexpected records: %+v", recs)
	}
}

func TestToRecords_Skips(t *testing.T) {
	weighted := recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10")
	weighted.SetIdentifier = aws.String("blue")

	cases := map[string]r53types.ResourceRecordSet{
		"unsupported type": recordSet("example.com.", r53types.RRTypeNs, "ns-1.awsdns.com."),
		"alias target": {
			Name:        aws.String("example.com."),
			Type:        r53types.RRTypeA,
			AliasTarget: &r53types.AliasTarget{DNSName: aws.String("elb.amazonaws.com.")},
		},
		"routing policy": weighted,
		// Route53 splits a value over 255 bytes into several quoted strings,
		// as it does for DKIM keys. Listing concatenates them into a value
		// the single-string writer could never reproduce, so the record would
		// be advertised and then refused on the way back.
		"multi-string txt": recordSet("dkim.example.com.", r53types.RRTypeTxt, `"part-one" "part-two"`),
	}
	for name, rs := range cases {
		if recs := toRecords(rs); len(recs) != 0 {
			t.Errorf("%s: expected to be skipped, got %+v", name, recs)
		}
	}
}

func TestToRecords_TXTUnquotes(t *testing.T) {
	recs := toRecords(recordSet("app.example.com.", r53types.RRTypeTxt, `"owner=dnsweaver"`))
	if len(recs) != 1 || recs[0].Value != "owner=dnsweaver" {
		t.Errorf("unexpected records: %+v", recs)
	}
}

func TestToRecords_SRVParses(t *testing.T) {
	recs := toRecords(recordSet("_https._tcp.example.com.", r53types.RRTypeSrv, "10 20 443 target.example.com."))
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Value != "target.example.com" {
		t.Errorf("Value = %q", rec.Value)
	}
	if rec.SRV == nil || rec.SRV.Priority != 10 || rec.SRV.Weight != 20 || rec.SRV.Port != 443 {
		t.Errorf("SRV = %+v", rec.SRV)
	}
}

func TestToRecords_SkipsMalformedSRV(t *testing.T) {
	// Handing back a four-field string with no SRV data would advertise a
	// record that fails validation the moment anything writes it again.
	for name, value := range map[string]string{
		"non-numeric fields": "not an srv value",
		"missing target":     "10 20 443",
		"port out of range":  "10 20 99999 target.example.com.",
	} {
		t.Run(name, func(t *testing.T) {
			recs := toRecords(recordSet("_https._tcp.example.com.", r53types.RRTypeSrv, value))
			if len(recs) != 0 {
				t.Errorf("expected the record to be skipped, got %+v", recs)
			}
		})
	}
}

func TestParseType(t *testing.T) {
	for _, v := range []string{"A", "AAAA", "CNAME", "TXT", "SRV", "a", "cname"} {
		if _, err := ParseType(v); err != nil {
			t.Errorf("ParseType(%q) unexpected error: %v", v, err)
		}
	}
	for _, v := range []string{"MX", "NS", "", "A;DROP"} {
		if _, err := ParseType(v); err == nil {
			t.Errorf("ParseType(%q) expected error", v)
		}
	}
}

func TestSameName(t *testing.T) {
	cases := []struct {
		name, fqdn string
		want       bool
	}{
		{"app.example.com.", "app.example.com.", true},
		{"APP.example.com.", "app.example.com.", true},
		{`\052.example.com.`, "*.example.com.", true},
		{"other.example.com.", "app.example.com.", false},
	}
	for _, tc := range cases {
		if got := sameName(tc.name, tc.fqdn); got != tc.want {
			t.Errorf("sameName(%q, %q) = %v, want %v", tc.name, tc.fqdn, got, tc.want)
		}
	}
}

func recordSet(name string, rt r53types.RRType, value string) r53types.ResourceRecordSet {
	return r53types.ResourceRecordSet{
		Name:            aws.String(name),
		Type:            rt,
		TTL:             aws.Int64(300),
		ResourceRecords: []r53types.ResourceRecord{{Value: aws.String(value)}},
	}
}
