package journal

import (
	"fmt"
	"strings"
)

// QualificationCategory groups backend-specific fault tests that every durable
// journal adapter must implement. This catalog is a requirement, not an
// executable fault injector or evidence that any adapter has passed.
type QualificationCategory string

const (
	QualificationConcurrency QualificationCategory = "CONCURRENCY"
	QualificationAtomicity   QualificationCategory = "ATOMICITY"
	QualificationCrash       QualificationCategory = "PROCESS_CRASH"
	QualificationAck         QualificationCategory = "ACKNOWLEDGEMENT"
	QualificationStorage     QualificationCategory = "STORAGE_FAULT"
	QualificationCorruption  QualificationCategory = "CORRUPTION"
	QualificationRecovery    QualificationCategory = "RECOVERY"
	QualificationBackup     QualificationCategory = "BACKUP_RESTORE"
	QualificationDurability  QualificationCategory = "POWER_LOSS_DURABILITY"
)

// QualificationScenario is a stable, reviewable acceptance criterion. Evidence
// references must identify raw test output and the adapter/configuration under
// test; a narrative assertion alone is insufficient.
type QualificationScenario struct {
	ID               string
	Category         QualificationCategory
	FaultPoint       string
	RequiredInvariant string
	RequiredEvidence string
}

// RequiredQualificationScenarios is backend-neutral. A selected adapter must
// map every scenario to a reproducible test and retain its evidence.
var RequiredQualificationScenarios = []QualificationScenario{
	{ "JQ-CON-001", QualificationConcurrency, "Two concurrent claims use the same scope/key and same request digest", "Exactly one attempt is created; the loser resolves to the winner's original attempt and never reports CREATED", "Race-test output plus persisted claim/attempt row snapshot" },
	{ "JQ-CON-002", QualificationConcurrency, "Two concurrent claims use the same scope/key and different request digests", "Exactly one claim/attempt pair survives; the other caller receives CONFLICT; no second attempt exists", "Race-test output plus persisted claim/attempt row snapshot" },
	{ "JQ-CON-003", QualificationConcurrency, "Same key digest is used in different owner/client/route scopes", "Claims remain isolated by the complete scope tuple", "Concurrent test output plus scoped record snapshot" },
	{ "JQ-ATM-001", QualificationAtomicity, "Attempt insert fails after the scoped-key claim insert was attempted", "Neither claim nor attempt is committed", "Injected-failure output plus before/after durable state snapshot" },
	{ "JQ-ATM-002", QualificationAtomicity, "Terminal-result insert succeeds but response-descriptor attachment fails", "Terminal result, descriptor, and terminal state all roll back together", "Injected-failure output plus transaction state snapshot" },
	{ "JQ-ATM-003", QualificationAtomicity, "Terminal result and descriptor are staged but terminal compare-and-set fails", "No partial terminal result or replayable descriptor remains", "Injected-failure output plus transaction state snapshot" },
	{ "JQ-CRS-001", QualificationCrash, "Process terminates before claim transaction begins", "No claim or attempt is visible after restart", "Crash harness trace plus post-restart state snapshot" },
	{ "JQ-CRS-002", QualificationCrash, "Process terminates after claim write but before attempt write", "Atomic transaction recovery exposes neither record", "Crash harness trace plus post-restart state snapshot" },
	{ "JQ-CRS-003", QualificationCrash, "Process terminates after attempt write but before transaction commit", "Atomic transaction recovery exposes neither record", "Crash harness trace plus post-restart state snapshot" },
	{ "JQ-CRS-004", QualificationCrash, "Process terminates after durable commit but before caller acknowledgement", "Recovery discovers the original claim and attempt; it does not create a replacement", "Crash harness trace plus recovered record identity" },
	{ "JQ-ACK-001", QualificationAck, "Commit succeeds but acknowledgement is deliberately lost", "Caller treats outcome as unknown and resolves by authoritative read before any retry", "Fault-injection trace plus read/retry decision log" },
	{ "JQ-ACK-002", QualificationAck, "Commit acknowledgement and subsequent read are both temporarily unavailable", "Caller remains fail-closed; no duplicate attempt or external dispatch occurs", "Fault-injection trace plus side-effect counter and recovery log" },
	{ "JQ-STO-001", QualificationStorage, "Storage reports disk full during transaction write", "No partial transaction is acknowledged; service fails closed", "Storage fault trace plus durable state snapshot" },
	{ "JQ-STO-002", QualificationStorage, "Short write or write error occurs during journal/WAL output", "No incomplete commit is acknowledged; restart detects and safely recovers or fails closed", "Fault-injection trace plus restart integrity report" },
	{ "JQ-STO-003", QualificationStorage, "Required sync/fsync operation returns an error", "Commit is not acknowledged as durable", "Sync fault trace plus acknowledgement trace" },
	{ "JQ-STO-004", QualificationStorage, "Checkpoint/WAL flush fails or storage becomes read-only", "No stronger durability claim is made; writes stop or fail closed", "Checkpoint/read-only fault trace plus service state" },
	{ "JQ-COR-001", QualificationCorruption, "Journal page, WAL segment, or equivalent storage unit is torn or checksum-invalid", "Corruption is surfaced distinctly; no silent repair, fabricated absence, or workload dispatch occurs", "Corruption fixture plus integrity/recovery output" },
	{ "JQ-COR-002", QualificationCorruption, "Immutable claim, attempt, terminal, or tombstone record is missing or inconsistent", "Invariant violation is detected and recovery fails closed", "Mutated-store fixture plus invariant failure output" },
	{ "JQ-REC-001", QualificationRecovery, "Recovery encounters an operation or claim with uncertain commit outcome", "Recovery preserves identity and requires authoritative reconciliation; it never assumes rollback", "Recovery trace plus operation/attempt identity audit" },
	{ "JQ-REC-002", QualificationRecovery, "Recovery encounters an unreadable or partially available journal", "No new attempt or external side effect is permitted until integrity is established", "Recovery trace plus side-effect counter" },
	{ "JQ-BKP-001", QualificationBackup, "Consistent backup is taken while journal transactions are active", "Backup represents one consistent transaction boundary and passes integrity verification on restore", "Backup manifest, consistency proof, and restore test output" },
	{ "JQ-BKP-002", QualificationBackup, "Backup is restored after response pruning", "Scoped-key tombstones and key reservations survive restore; keys are not recycled", "Before/after tombstone inventory and restore test output" },
	{ "JQ-BKP-003", QualificationBackup, "Backup is restored onto a replacement host incarnation", "Restored journal identity is not treated as host-fencing proof; external fencing and epoch qualification remain independently required", "Restore trace plus host-incarnation/fencing evidence references" },
	{ "JQ-DUR-001", QualificationDurability, "Power is lost immediately after a commit acknowledgement", "Every acknowledged commit survives according to the explicitly declared durability profile, or the profile is rejected", "Power-cut harness trace, storage configuration, and post-boot integrity report" },
	{ "JQ-DUR-002", QualificationDurability, "Power is lost during commit and sync barriers", "Recovery yields a valid pre-commit or post-commit state, never a partially committed logical transaction", "Power-cut matrix plus post-boot transaction invariant report" },
}

// ValidateQualificationCatalog checks completeness and stable identity. It
// deliberately does not certify execution, evidence authenticity, or durability.
func ValidateQualificationCatalog(scenarios []QualificationScenario) error {
	if len(scenarios) == 0 {
		return fmt.Errorf("%w: qualification catalog is empty", ErrCorrupt)
	}
	requiredCategories := map[QualificationCategory]bool{
		QualificationConcurrency: false,
		QualificationAtomicity: false,
		QualificationCrash: false,
		QualificationAck: false,
		QualificationStorage: false,
		QualificationCorruption: false,
		QualificationRecovery: false,
		QualificationBackup: false,
		QualificationDurability: false,
	}
	seen := make(map[string]bool, len(scenarios))
	for _, scenario := range scenarios {
		if strings.TrimSpace(scenario.ID) == "" || seen[scenario.ID] {
			return fmt.Errorf("%w: qualification scenario ID is blank or duplicated: %q", ErrCorrupt, scenario.ID)
		}
		seen[scenario.ID] = true
		if _, ok := requiredCategories[scenario.Category]; !ok {
			return fmt.Errorf("%w: unknown qualification category %q", ErrCorrupt, scenario.Category)
		}
		if strings.TrimSpace(scenario.FaultPoint) == "" ||
			strings.TrimSpace(scenario.RequiredInvariant) == "" ||
			strings.TrimSpace(scenario.RequiredEvidence) == "" {
			return fmt.Errorf("%w: scenario %s lacks fault point, invariant, or evidence requirement", ErrCorrupt, scenario.ID)
		}
		requiredCategories[scenario.Category] = true
	}
	for category, present := range requiredCategories {
		if !present {
			return fmt.Errorf("%w: qualification category %s is not represented", ErrCorrupt, category)
		}
	}
	return nil
}
