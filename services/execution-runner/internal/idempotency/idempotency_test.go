package idempotency

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validScope() Scope {
	return Scope{OwnerID: "owner-1", ClientID: "client-1", RouteID: "submit-code"}
}

func validRecord() Record {
	return Record{
		Scope:                     validScope(),
		KeyDigest:                 strings.Repeat("a", 64),
		RequestDigest:             strings.Repeat("b", 64),
		AttemptID:                 "attempt-1",
		ClaimedAtUTC:              time.Date(2026, time.November, 11, 8, 0, 0, 0, time.UTC),
		ResponseDescriptorVersion: 1,
		ResponseDescriptorDigest:  strings.Repeat("c", 64),
		ResponseDescriptorAvailable: true,
	}
}

func TestDigestKeyPersistsOnlyCanonicalDigest(t *testing.T) {
	t.Parallel()
	digest, err := DigestKey("client-request-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		t.Fatalf("key digest = %q, want lowercase 64-character SHA-256", digest)
	}
	if _, err := DigestKey("   "); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("blank key error = %v, want ErrInvalidRecord", err)
	}
}

func TestNewClaimMustNotContainResponseOrTombstone(t *testing.T) {
	t.Parallel()
	record := validRecord()
	record.ResponseDescriptorAvailable = false
	record.ResponseDescriptorVersion = 0
	record.ResponseDescriptorDigest = ""
	if err := record.ValidateNewClaim(); err != nil {
		t.Fatalf("valid initial claim rejected: %v", err)
	}
	record.ResponseDescriptorAvailable = true
	record.ResponseDescriptorVersion = 1
	record.ResponseDescriptorDigest = strings.Repeat("c", 64)
	if err := record.ValidateNewClaim(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("preloaded response descriptor error = %v, want ErrInvalidRecord", err)
	}
}

func TestResolveExistingReturnsReplayForSameScopedKeyAndRequest(t *testing.T) {
	t.Parallel()
	record := validRecord()
	disposition, resolved, err := ResolveExisting(record, validScope(), record.KeyDigest, record.RequestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != DispositionReplay || resolved.AttemptID != record.AttemptID {
		t.Fatalf("resolution = %s for attempt %s, want REPLAY for %s", disposition, resolved.AttemptID, record.AttemptID)
	}
}

func TestResolveExistingConflictsForDifferentRequestDigest(t *testing.T) {
	t.Parallel()
	record := validRecord()
	disposition, resolved, err := ResolveExisting(record, validScope(), record.KeyDigest, strings.Repeat("d", 64))
	if !errors.Is(err, ErrKeyConflict) || disposition != DispositionConflict || resolved.AttemptID != record.AttemptID {
		t.Fatalf("resolution = %s, attempt = %s, error = %v; want conflict retaining original attempt", disposition, resolved.AttemptID, err)
	}
}

func TestResolveExistingIsolatedByScope(t *testing.T) {
	t.Parallel()
	record := validRecord()
	scope := validScope()
	scope.OwnerID = "owner-2"
	if _, _, err := ResolveExisting(record, scope, record.KeyDigest, record.RequestDigest); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("cross-scope lookup error = %v, want ErrInvalidRecord", err)
	}
}

func TestResolveExistingPendingClaimRecoversAfterLostAcknowledgement(t *testing.T) {
	t.Parallel()
	record := validRecord()
	record.ResponseDescriptorAvailable = false
	record.ResponseDescriptorVersion = 0
	record.ResponseDescriptorDigest = ""
	disposition, resolved, err := ResolveExisting(record, validScope(), record.KeyDigest, record.RequestDigest)
	if !errors.Is(err, ErrReplayPending) || disposition != DispositionPending || resolved.AttemptID != record.AttemptID {
		t.Fatalf("pending resolution = %s, attempt = %s, error = %v", disposition, resolved.AttemptID, err)
	}
}

func TestResolveExistingTombstonePreventsKeyReuseAfterPruning(t *testing.T) {
	t.Parallel()
	record := validRecord()
	record.ResponseDescriptorAvailable = false
	record.ResponseDescriptorPrunedAtUTC = time.Date(2026, time.November, 12, 8, 0, 0, 0, time.UTC)
	disposition, resolved, err := ResolveExisting(record, validScope(), record.KeyDigest, record.RequestDigest)
	if !errors.Is(err, ErrResponsePruned) || disposition != DispositionTombstone || resolved.AttemptID != record.AttemptID {
		t.Fatalf("tombstone resolution = %s, attempt = %s, error = %v", disposition, resolved.AttemptID, err)
	}
	if _, _, err := ResolveExisting(record, validScope(), record.KeyDigest, strings.Repeat("d", 64)); !errors.Is(err, ErrKeyConflict) {
		t.Fatalf("different request against tombstone error = %v, want ErrKeyConflict", err)
	}
}

func TestRecordRejectsPartialOrContradictoryDescriptor(t *testing.T) {
	t.Parallel()
	record := validRecord()
	record.ResponseDescriptorDigest = ""
	if err := record.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("missing descriptor digest error = %v", err)
	}
	record = validRecord()
	record.ResponseDescriptorPrunedAtUTC = time.Date(2026, time.November, 12, 8, 0, 0, 0, time.UTC)
	if err := record.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("available and pruned descriptor error = %v", err)
	}
}

func TestPruneResponseCommandRequiresExactCASAndUTC(t *testing.T) {
	t.Parallel()
	command := PruneResponseCommand{
		Scope:                     validScope(),
		KeyDigest:                 strings.Repeat("a", 64),
		ExpectedRequestDigest:     strings.Repeat("b", 64),
		ExpectedDescriptorVersion: 1,
		ExpectedDescriptorDigest:  strings.Repeat("c", 64),
		PrunedAtUTC:               time.Date(2026, time.November, 12, 8, 0, 0, 0, time.UTC),
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid prune command rejected: %v", err)
	}
	command.ExpectedDescriptorVersion = 0
	if err := command.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("missing descriptor version error = %v", err)
	}
}

func TestCommitResponseDescriptorRequiresExactClaimIdentity(t *testing.T) {
	t.Parallel()
	command := CommitResponseDescriptorCommand{
		Scope:                 validScope(),
		KeyDigest:             strings.Repeat("a", 64),
		ExpectedRequestDigest: strings.Repeat("b", 64),
		AttemptID:             "attempt-1",
		DescriptorVersion:     1,
		DescriptorDigest:      strings.Repeat("c", 64),
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid response descriptor command rejected: %v", err)
	}
	command.DescriptorVersion = 0
	if err := command.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("missing descriptor version error = %v, want ErrInvalidRecord", err)
	}
}
