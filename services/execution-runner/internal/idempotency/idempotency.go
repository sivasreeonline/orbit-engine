package idempotency

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidRecord  = errors.New("invalid idempotency record")
	ErrKeyConflict    = errors.New("idempotency key reused with a different request")
	ErrReplayPending  = errors.New("idempotency claim exists but terminal response is not yet available")
	ErrResponsePruned = errors.New("idempotency response was pruned; key remains tombstoned")
)

// ValidateNewClaim ensures a newly inserted claim cannot arrive with a
// fabricated terminal response descriptor or a pre-existing tombstone.
func (record Record) ValidateNewClaim() error {
	if err := record.Validate(); err != nil {
		return err
	}
	if record.ResponseDescriptorAvailable || record.ResponseDescriptorVersion != 0 ||
		record.ResponseDescriptorDigest != "" || !record.ResponseDescriptorPrunedAtUTC.IsZero() {
		return fmt.Errorf("%w: new claims must begin without a response descriptor or tombstone", ErrInvalidRecord)
	}
	return nil
}

type Disposition string

const (
	DispositionCreated   Disposition = "CREATED"
	DispositionReplay    Disposition = "REPLAY"
	DispositionConflict  Disposition = "CONFLICT"
	DispositionPending   Disposition = "PENDING"
	DispositionTombstone Disposition = "TOMBSTONE"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$`)

// DigestKey converts a caller-supplied opaque key to the only representation
// persisted by the journal. The raw key must not be logged or stored.
func DigestKey(key string) (string, error) {
	if len(key) == 0 || len(key) > 256 || strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("%w: idempotency key must contain 1..256 non-whitespace bytes", ErrInvalidRecord)
	}
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:]), nil
}

type Scope struct {
	OwnerID  string
	ClientID string
	RouteID  string
}

func (scope Scope) Validate() error {
	if !identifierPattern.MatchString(scope.OwnerID) ||
		!identifierPattern.MatchString(scope.ClientID) ||
		!identifierPattern.MatchString(scope.RouteID) {
		return fmt.Errorf("%w: owner, client, and route scope are required", ErrInvalidRecord)
	}
	return nil
}

type Record struct {
	Scope                         Scope
	KeyDigest                     string
	RequestDigest                 string
	AttemptID                     string
	ClaimedAtUTC                  time.Time
	ResponseDescriptorVersion     uint64
	ResponseDescriptorDigest      string
	ResponseDescriptorAvailable   bool
	ResponseDescriptorPrunedAtUTC time.Time
}

func (record Record) Validate() error {
	if err := record.Scope.Validate(); err != nil {
		return err
	}
	if !validDigest(record.KeyDigest) || !validDigest(record.RequestDigest) ||
		!identifierPattern.MatchString(record.AttemptID) ||
		record.ClaimedAtUTC.IsZero() || record.ClaimedAtUTC.Location() != time.UTC {
		return fmt.Errorf("%w: key/request digest, attempt identity, or claim timestamp is invalid", ErrInvalidRecord)
	}
	if record.ResponseDescriptorAvailable {
		if record.ResponseDescriptorVersion == 0 || !validDigest(record.ResponseDescriptorDigest) ||
			!record.ResponseDescriptorPrunedAtUTC.IsZero() {
			return fmt.Errorf("%w: available response descriptor must have version/digest and cannot be pruned", ErrInvalidRecord)
		}
	} else if record.ResponseDescriptorPrunedAtUTC.IsZero() {
		if record.ResponseDescriptorVersion != 0 || record.ResponseDescriptorDigest != "" {
			return fmt.Errorf("%w: incomplete response descriptor metadata", ErrInvalidRecord)
		}
	} else if record.ResponseDescriptorPrunedAtUTC.Location() != time.UTC ||
		record.ResponseDescriptorVersion == 0 || !validDigest(record.ResponseDescriptorDigest) {
		return fmt.Errorf("%w: tombstone must preserve descriptor version/digest and UTC prune time", ErrInvalidRecord)
	}
	return nil
}

// ResolveExisting never creates a new claim. It classifies an already persisted
// scoped key so a lost acknowledgement cannot create a duplicate attempt.
func ResolveExisting(existing Record, scope Scope, keyDigest, requestDigest string) (Disposition, Record, error) {
	if err := existing.Validate(); err != nil {
		return "", Record{}, err
	}
	if err := scope.Validate(); err != nil {
		return "", Record{}, err
	}
	if !validDigest(keyDigest) || !validDigest(requestDigest) {
		return "", Record{}, fmt.Errorf("%w: lookup digests must be lowercase SHA-256", ErrInvalidRecord)
	}
	if existing.Scope != scope || existing.KeyDigest != keyDigest {
		return "", Record{}, fmt.Errorf("%w: lookup scope/key does not identify this record", ErrInvalidRecord)
	}
	if existing.RequestDigest != requestDigest {
		return DispositionConflict, existing, ErrKeyConflict
	}
	if !existing.ResponseDescriptorPrunedAtUTC.IsZero() {
		return DispositionTombstone, existing, ErrResponsePruned
	}
	if !existing.ResponseDescriptorAvailable {
		return DispositionPending, existing, ErrReplayPending
	}
	return DispositionReplay, existing, nil
}

type CommitResponseDescriptorCommand struct {
	Scope                 Scope
	KeyDigest             string
	ExpectedRequestDigest string
	AttemptID             string
	DescriptorVersion     uint64
	DescriptorDigest      string
}

// Validate binds a terminal response descriptor to the exact original scoped
// claim. The adapter must execute this as a compare-and-set in the same durable
// transaction as terminal-result commitment.
func (command CommitResponseDescriptorCommand) Validate() error {
	if err := command.Scope.Validate(); err != nil {
		return err
	}
	if !validDigest(command.KeyDigest) || !validDigest(command.ExpectedRequestDigest) ||
		!identifierPattern.MatchString(command.AttemptID) || command.DescriptorVersion == 0 ||
		!validDigest(command.DescriptorDigest) {
		return fmt.Errorf("%w: response descriptor command identity/version/digest is incomplete", ErrInvalidRecord)
	}
	return nil
}

type PruneResponseCommand struct {
	Scope                     Scope
	KeyDigest                 string
	ExpectedRequestDigest     string
	ExpectedDescriptorVersion uint64
	ExpectedDescriptorDigest  string
	PrunedAtUTC               time.Time
}

func (command PruneResponseCommand) Validate() error {
	if err := command.Scope.Validate(); err != nil {
		return err
	}
	if !validDigest(command.KeyDigest) || !validDigest(command.ExpectedRequestDigest) ||
		!validDigest(command.ExpectedDescriptorDigest) || command.ExpectedDescriptorVersion == 0 ||
		command.PrunedAtUTC.IsZero() || command.PrunedAtUTC.Location() != time.UTC {
		return fmt.Errorf("%w: prune command requires scoped key, exact descriptor CAS, and UTC timestamp", ErrInvalidRecord)
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
