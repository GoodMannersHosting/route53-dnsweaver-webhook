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
