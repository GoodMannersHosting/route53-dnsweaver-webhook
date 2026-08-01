// Package route53 applies dnsweaver's desired DNS state to an AWS Route53
// hosted zone.
package route53

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsr53 "github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// API is the slice of *route53.Client this provider uses, so callers can be
// exercised without AWS credentials.
type API interface {
	GetHostedZone(context.Context, *awsr53.GetHostedZoneInput, ...func(*awsr53.Options)) (*awsr53.GetHostedZoneOutput, error)
	ListResourceRecordSets(context.Context, *awsr53.ListResourceRecordSetsInput, ...func(*awsr53.Options)) (*awsr53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(context.Context, *awsr53.ChangeResourceRecordSetsInput, ...func(*awsr53.Options)) (*awsr53.ChangeResourceRecordSetsOutput, error)
}

// Per-operation budgets. Callers should keep their write timeout above these
// so a slow upstream still produces a response body.
const (
	pingTimeout   = 10 * time.Second
	changeTimeout = 20 * time.Second
	listTimeout   = 30 * time.Second

	// namePageSize is how many record sets to pull when inspecting a single
	// name. Route53 stores at most a handful of types per name.
	namePageSize = 20
)

// Provider reads and writes records in one hosted zone.
type Provider struct {
	client     API
	zoneID     string
	defaultTTL int
	minTTL     int
	maxTTL     int
}

// New returns a Provider bound to a single hosted zone. defaultTTL is applied
// to records that arrive without one.
func New(client API, zoneID string, defaultTTL, minTTL, maxTTL int) *Provider {
	return &Provider{
		client:     client,
		zoneID:     zoneID,
		defaultTTL: defaultTTL,
		minTTL:     minTTL,
		maxTTL:     maxTTL,
	}
}

// Ping confirms the hosted zone is reachable with the current credentials.
func (p *Provider) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	_, err := p.client.GetHostedZone(ctx, &awsr53.GetHostedZoneInput{Id: aws.String(p.zoneID)})
	return err
}

// List returns every manageable record in the zone, one entry per value.
func (p *Provider) List(ctx context.Context) ([]Record, error) {
	ctx, cancel := context.WithTimeout(ctx, listTimeout)
	defer cancel()

	records := []Record{}
	in := &awsr53.ListResourceRecordSetsInput{HostedZoneId: aws.String(p.zoneID)}
	for {
		resp, err := p.client.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, rs := range resp.ResourceRecordSets {
			records = append(records, toRecords(rs)...)
		}
		if !resp.IsTruncated {
			return records, nil
		}
		// StartRecordIdentifier matters: without it, a zone containing
		// routing-policy records pages over the same records forever.
		in.StartRecordName = resp.NextRecordName
		in.StartRecordType = resp.NextRecordType
		in.StartRecordIdentifier = resp.NextRecordIdentifier
	}
}

// Upsert creates or replaces a record set. UPSERT rather than CREATE keeps
// dnsweaver's startup reconciliation idempotent instead of erroring on
// "record already exists".
func (p *Provider) Upsert(ctx context.Context, rec Record) error {
	if rec.TTL <= 0 {
		rec.TTL = p.defaultTTL
	}
	rrset, err := resourceRecordSet(rec, p.minTTL, p.maxTTL)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, changeTimeout)
	defer cancel()

	return p.applyChanges(ctx, []r53types.Change{{
		Action:            r53types.ChangeActionUpsert,
		ResourceRecordSet: rrset,
	}})
}

// Delete removes every manageable record at hostname, optionally narrowed to
// one type, and reports how many record sets it removed. Deleting a record
// that isn't there is not an error.
func (p *Provider) Delete(ctx context.Context, hostname, recordType string) (int, error) {
	fqdn, err := NormalizeFQDN(hostname)
	if err != nil {
		return 0, err
	}
	var wanted RecordType
	if strings.TrimSpace(recordType) != "" {
		if wanted, err = ParseType(recordType); err != nil {
			return 0, err
		}
	}

	ctx, cancel := context.WithTimeout(ctx, changeTimeout)
	defer cancel()

	// Route53 requires a DELETE change to repeat the existing record set
	// (name, type, ttl and values) exactly, so look it up first rather than
	// trusting whatever the caller sent.
	existing, err := p.recordSetsAtName(ctx, fqdn)
	if err != nil {
		return 0, err
	}

	changes := make([]r53types.Change, 0, len(existing))
	for i := range existing {
		if wanted != "" && RecordType(existing[i].Type) != wanted {
			continue
		}
		changes = append(changes, r53types.Change{
			Action:            r53types.ChangeActionDelete,
			ResourceRecordSet: &existing[i],
		})
	}
	if len(changes) == 0 {
		return 0, nil
	}
	if err := p.applyChanges(ctx, changes); err != nil {
		return 0, err
	}
	return len(changes), nil
}

func (p *Provider) applyChanges(ctx context.Context, changes []r53types.Change) error {
	_, err := p.client.ChangeResourceRecordSets(ctx, &awsr53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(p.zoneID),
		ChangeBatch:  &r53types.ChangeBatch{Changes: changes},
	})
	return err
}

// recordSetsAtName returns every manageable record set stored under fqdn.
// Route53 lists record sets in sorted order, so everything sharing a name is
// contiguous and the scan can stop as soon as the name changes.
func (p *Provider) recordSetsAtName(ctx context.Context, fqdn string) ([]r53types.ResourceRecordSet, error) {
	in := &awsr53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(p.zoneID),
		StartRecordName: aws.String(fqdn),
		MaxItems:        aws.Int32(namePageSize),
	}

	var found []r53types.ResourceRecordSet
	for {
		resp, err := p.client.ListResourceRecordSets(ctx, in)
		if err != nil {
			return nil, err
		}
		for _, rs := range resp.ResourceRecordSets {
			if !sameName(aws.ToString(rs.Name), fqdn) {
				return found, nil
			}
			if isManageable(rs) {
				found = append(found, rs)
			}
		}
		if !resp.IsTruncated || !sameName(aws.ToString(resp.NextRecordName), fqdn) {
			return found, nil
		}
		in.StartRecordName = resp.NextRecordName
		in.StartRecordType = resp.NextRecordType
		in.StartRecordIdentifier = resp.NextRecordIdentifier
	}
}

// isManageable reports whether a record set can be round-tripped through the
// flat hostname/type/value contract. Alias targets, routing-policy records
// (weighted, latency, geolocation, failover) and traffic-policy instances
// carry configuration that contract cannot express, so exposing them would
// invite dnsweaver to "correct" them into a plain record and destroy it.
func isManageable(rs r53types.ResourceRecordSet) bool {
	if rs.AliasTarget != nil || rs.SetIdentifier != nil || rs.TrafficPolicyInstanceId != nil {
		return false
	}
	if len(rs.ResourceRecords) == 0 {
		return false
	}
	switch RecordType(rs.Type) {
	case TypeA, TypeAAAA, TypeCNAME, TypeTXT, TypeSRV:
		return true
	default:
		// NS, SOA, MX, CAA and friends are deliberately invisible.
		return false
	}
}
