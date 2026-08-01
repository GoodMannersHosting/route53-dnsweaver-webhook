package route53

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// fakeAPI records what the provider sends and replays canned pages.
type fakeAPI struct {
	pages     []*awsr53.ListResourceRecordSetsOutput
	zoneErr   error
	listErr   error
	changeErr error

	listInputs []*awsr53.ListResourceRecordSetsInput
	changes    []r53types.Change
}

func (f *fakeAPI) GetHostedZone(context.Context, *awsr53.GetHostedZoneInput, ...func(*awsr53.Options)) (*awsr53.GetHostedZoneOutput, error) {
	if f.zoneErr != nil {
		return nil, f.zoneErr
	}
	return &awsr53.GetHostedZoneOutput{}, nil
}

func (f *fakeAPI) ListResourceRecordSets(_ context.Context, in *awsr53.ListResourceRecordSetsInput, _ ...func(*awsr53.Options)) (*awsr53.ListResourceRecordSetsOutput, error) {
	f.listInputs = append(f.listInputs, in)
	if f.listErr != nil {
		return nil, f.listErr
	}
	if len(f.pages) == 0 {
		return &awsr53.ListResourceRecordSetsOutput{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func (f *fakeAPI) ChangeResourceRecordSets(_ context.Context, in *awsr53.ChangeResourceRecordSetsInput, _ ...func(*awsr53.Options)) (*awsr53.ChangeResourceRecordSetsOutput, error) {
	if f.changeErr != nil {
		return nil, f.changeErr
	}
	f.changes = append(f.changes, in.ChangeBatch.Changes...)
	return &awsr53.ChangeResourceRecordSetsOutput{}, nil
}

func newTestProvider(f *fakeAPI) *Provider {
	return New(f, "Z0123456789ABCDEFGHI", 300, testMinTTL, testMaxTTL)
}

func TestProviderPing(t *testing.T) {
	if err := newTestProvider(&fakeAPI{}).Ping(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := errors.New("boom")
	if err := newTestProvider(&fakeAPI{zoneErr: want}).Ping(context.Background()); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestProviderListEmpty(t *testing.T) {
	records, err := newTestProvider(&fakeAPI{}).List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if records == nil {
		t.Error("List returned a nil slice; callers serialize this as JSON null")
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
}

func TestProviderListPaginates(t *testing.T) {
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{
		{
			ResourceRecordSets:   []r53types.ResourceRecordSet{recordSet("a.example.com.", r53types.RRTypeA, "203.0.113.10")},
			IsTruncated:          true,
			NextRecordName:       aws.String("b.example.com."),
			NextRecordType:       r53types.RRTypeA,
			NextRecordIdentifier: aws.String("blue"),
		},
		{
			ResourceRecordSets: []r53types.ResourceRecordSet{recordSet("b.example.com.", r53types.RRTypeA, "203.0.113.11")},
		},
	}}

	records, err := newTestProvider(f).List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if len(f.listInputs) != 2 {
		t.Fatalf("got %d list calls, want 2", len(f.listInputs))
	}
	if aws.ToString(f.listInputs[1].StartRecordIdentifier) != "blue" {
		t.Error("second page did not carry StartRecordIdentifier, which can loop forever")
	}
}

func TestProviderUpsertAppliesDefaultTTL(t *testing.T) {
	f := &fakeAPI{}
	p := New(f, "Z0123456789ABCDEFGHI", 60, testMinTTL, testMaxTTL)

	err := p.Upsert(context.Background(), Record{Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(f.changes))
	}
	if f.changes[0].Action != r53types.ChangeActionUpsert {
		t.Errorf("action = %v, want UPSERT", f.changes[0].Action)
	}
	if got := aws.ToInt64(f.changes[0].ResourceRecordSet.TTL); got != 60 {
		t.Errorf("ttl = %d, want the provider default of 60", got)
	}
}

func TestProviderUpsertValidates(t *testing.T) {
	f := &fakeAPI{}
	err := newTestProvider(f).Upsert(context.Background(), Record{
		Hostname: "app.example.com", Type: TypeA, Value: "not-an-ip", TTL: 300,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	if len(f.changes) != 0 {
		t.Errorf("route53 was called with %+v", f.changes)
	}
}

func TestProviderDeleteByType(t *testing.T) {
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{
			recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10"),
			recordSet("app.example.com.", r53types.RRTypeTxt, `"owner=dnsweaver"`),
			recordSet("other.example.com.", r53types.RRTypeA, "203.0.113.99"),
		},
	}}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "app.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if f.changes[0].ResourceRecordSet.Type != r53types.RRTypeA {
		t.Errorf("deleted the wrong type: %v", f.changes[0].ResourceRecordSet.Type)
	}
}

func TestProviderDeleteAllTypesAtName(t *testing.T) {
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{
			recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10"),
			recordSet("app.example.com.", r53types.RRTypeTxt, `"owner=dnsweaver"`),
		},
	}}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "app.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
}

func TestProviderDeleteSkipsAliasAndRoutingRecords(t *testing.T) {
	alias := r53types.ResourceRecordSet{
		Name:        aws.String("app.example.com."),
		Type:        r53types.RRTypeA,
		AliasTarget: &r53types.AliasTarget{DNSName: aws.String("elb.amazonaws.com.")},
	}
	weighted := recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10")
	weighted.SetIdentifier = aws.String("blue")

	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{alias, weighted},
	}}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "app.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 || len(f.changes) != 0 {
		t.Errorf("deleted records it cannot safely manage: %+v", f.changes)
	}
}

func TestProviderDeleteMissingRecordIsIdempotent(t *testing.T) {
	f := &fakeAPI{}
	deleted, err := newTestProvider(f).Delete(context.Background(), "gone.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 || len(f.changes) != 0 {
		t.Errorf("unexpected changes: %+v", f.changes)
	}
}

func TestProviderDeleteValidates(t *testing.T) {
	for _, tc := range []struct{ hostname, recordType string }{
		{"", "A"},
		{"app.example.com", "MX"},
	} {
		_, err := newTestProvider(&fakeAPI{}).Delete(context.Background(), tc.hostname, tc.recordType)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Delete(%q, %q) error = %v, want ErrInvalid", tc.hostname, tc.recordType, err)
		}
	}
}

func TestProviderUpsertRefusesUnmanageableTarget(t *testing.T) {
	alias := r53types.ResourceRecordSet{
		Name:        aws.String("app.example.com."),
		Type:        r53types.RRTypeA,
		AliasTarget: &r53types.AliasTarget{DNSName: aws.String("elb.amazonaws.com.")},
	}
	weighted := recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.99")
	weighted.SetIdentifier = aws.String("blue")

	// List hides both of these, so dnsweaver sees no record and asks for one
	// to be created. An unguarded UPSERT would replace them.
	for name, existing := range map[string]r53types.ResourceRecordSet{
		"alias":          alias,
		"routing policy": weighted,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
				ResourceRecordSets: []r53types.ResourceRecordSet{existing},
			}}}
			err := newTestProvider(f).Upsert(context.Background(), Record{
				Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10", TTL: 300,
			})
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("error = %v, want ErrConflict", err)
			}
			if len(f.changes) != 0 {
				t.Errorf("overwrote a record it cannot represent: %+v", f.changes)
			}
		})
	}
}

func TestProviderUpsertIgnoresOtherTypesAtTheSameName(t *testing.T) {
	// Route53 keys record sets on name and type, so an unmanaged MX sitting
	// at the same hostname is not in the way of an A record.
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{
			recordSet("app.example.com.", r53types.RRTypeMx, "10 mail.example.com."),
		},
	}}}

	err := newTestProvider(f).Upsert(context.Background(), Record{
		Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10", TTL: 300,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.changes) != 1 {
		t.Errorf("got %d changes, want 1", len(f.changes))
	}
}

func TestProviderDeleteSubmitsTheStoredRecordSet(t *testing.T) {
	// Route53 rejects a DELETE that doesn't repeat the existing record set
	// exactly, so the change has to echo back what the list returned rather
	// than a set rebuilt from the caller's hostname and type.
	stored := r53types.ResourceRecordSet{
		Name: aws.String(`\052.example.com.`),
		Type: r53types.RRTypeA,
		TTL:  aws.Int64(77),
		ResourceRecords: []r53types.ResourceRecord{
			{Value: aws.String("203.0.113.10")},
			{Value: aws.String("203.0.113.11")},
		},
	}
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{stored},
	}}}

	if _, err := newTestProvider(f).Delete(context.Background(), "*.example.com", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(f.changes))
	}

	got := f.changes[0].ResourceRecordSet
	if aws.ToString(got.Name) != `\052.example.com.` {
		t.Errorf("Name = %q, want Route53's escaped form", aws.ToString(got.Name))
	}
	if aws.ToInt64(got.TTL) != 77 {
		t.Errorf("TTL = %d, want the stored 77", aws.ToInt64(got.TTL))
	}
	if len(got.ResourceRecords) != 2 ||
		aws.ToString(got.ResourceRecords[0].Value) != "203.0.113.10" ||
		aws.ToString(got.ResourceRecords[1].Value) != "203.0.113.11" {
		t.Errorf("values = %+v, want both stored values", got.ResourceRecords)
	}
}

func TestProviderDeleteScansPastAnEarlyCursor(t *testing.T) {
	// Route53 sorts by reversed labels over the escaped name, so a digit
	// label sorts before \052 and the cursor can land ahead of a wildcard.
	// Stopping at the first name that doesn't match would report the record
	// as absent and turn a failed delete into a silent success.
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{
			recordSet("0.example.com.", r53types.RRTypeA, "203.0.113.1"),
			recordSet(`\052.example.com.`, r53types.RRTypeA, "203.0.113.10"),
		},
	}}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "*.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if aws.ToString(f.changes[0].ResourceRecordSet.Name) != `\052.example.com.` {
		t.Errorf("deleted the wrong record: %+v", f.changes[0].ResourceRecordSet)
	}
}

func TestProviderDeleteStopsOnceItPassesTheName(t *testing.T) {
	// The mirror of the case above: a name sorting after the target means the
	// record genuinely isn't there, and the scan must not page on through the
	// rest of the zone looking for it.
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{
			recordSet("zz.example.com.", r53types.RRTypeA, "203.0.113.9"),
		},
		IsTruncated:    true,
		NextRecordName: aws.String("zzz.example.com."),
	}}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "app.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0", deleted)
	}
	if len(f.listInputs) != 1 {
		t.Errorf("made %d list calls, want 1", len(f.listInputs))
	}
}

func TestProviderDeleteLowercasesTheCursor(t *testing.T) {
	// Route53 stores names lowercased, and uppercase ASCII sorts before
	// lowercase, so an uppercase cursor lands before the target.
	f := &fakeAPI{}
	if _, err := newTestProvider(f).Delete(context.Background(), "APP.Example.COM", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := aws.ToString(f.listInputs[0].StartRecordName); got != "app.example.com." {
		t.Errorf("StartRecordName = %q, want it lowercased", got)
	}
}

func TestProviderDeletePaginatesWithinOneName(t *testing.T) {
	f := &fakeAPI{pages: []*awsr53.ListResourceRecordSetsOutput{
		{
			ResourceRecordSets:   []r53types.ResourceRecordSet{recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10")},
			IsTruncated:          true,
			NextRecordName:       aws.String("app.example.com."),
			NextRecordType:       r53types.RRTypeTxt,
			NextRecordIdentifier: aws.String("next"),
		},
		{
			ResourceRecordSets: []r53types.ResourceRecordSet{recordSet("app.example.com.", r53types.RRTypeTxt, `"owner=dnsweaver"`)},
		},
	}}

	deleted, err := newTestProvider(f).Delete(context.Background(), "app.example.com", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want both types", deleted)
	}
	if len(f.listInputs) != 2 {
		t.Fatalf("made %d list calls, want 2", len(f.listInputs))
	}
	if aws.ToString(f.listInputs[1].StartRecordIdentifier) != "next" {
		t.Error("second page did not carry StartRecordIdentifier, which can loop forever")
	}
}

func TestProviderSurfacesUpstreamErrors(t *testing.T) {
	boom := errors.New("boom")
	rec := Record{Hostname: "app.example.com", Type: TypeA, Value: "203.0.113.10", TTL: 300}
	onePage := []*awsr53.ListResourceRecordSetsOutput{{
		ResourceRecordSets: []r53types.ResourceRecordSet{recordSet("app.example.com.", r53types.RRTypeA, "203.0.113.10")},
	}}

	cases := map[string]struct {
		api  *fakeAPI
		call func(*Provider) error
	}{
		"list": {&fakeAPI{listErr: boom}, func(p *Provider) error {
			_, err := p.List(context.Background())
			return err
		}},
		"upsert lookup": {&fakeAPI{listErr: boom}, func(p *Provider) error {
			return p.Upsert(context.Background(), rec)
		}},
		"upsert change": {&fakeAPI{changeErr: boom}, func(p *Provider) error {
			return p.Upsert(context.Background(), rec)
		}},
		"delete lookup": {&fakeAPI{listErr: boom}, func(p *Provider) error {
			_, err := p.Delete(context.Background(), "app.example.com", "")
			return err
		}},
		"delete change": {&fakeAPI{changeErr: boom, pages: onePage}, func(p *Provider) error {
			_, err := p.Delete(context.Background(), "app.example.com", "")
			return err
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.call(newTestProvider(tc.api))
			if !errors.Is(err, boom) {
				t.Fatalf("error = %v, want it to wrap the upstream failure", err)
			}
			// Misclassifying these would answer 400 or 409 instead of 502 and
			// blame the caller for an AWS outage.
			if errors.Is(err, ErrInvalid) || errors.Is(err, ErrConflict) {
				t.Error("upstream failure was reported as a caller error")
			}
		})
	}
}
