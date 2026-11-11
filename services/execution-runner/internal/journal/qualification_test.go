package journal

import (
	"errors"
	"testing"
)

func TestRequiredQualificationCatalogIsComplete(t *testing.T) {
	t.Parallel()
	if err := ValidateQualificationCatalog(RequiredQualificationScenarios); err != nil {
		t.Fatalf("required qualification catalog is invalid: %v", err)
	}
	if len(RequiredQualificationScenarios) < 20 {
		t.Fatalf("catalog has %d scenarios; want at least 20", len(RequiredQualificationScenarios))
	}
}

func TestValidateQualificationCatalogRejectsDuplicateIdentity(t *testing.T) {
	t.Parallel()
	scenarios := append([]QualificationScenario(nil), RequiredQualificationScenarios...)
	scenarios[1].ID = scenarios[0].ID
	if err := ValidateQualificationCatalog(scenarios); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("duplicate ID error = %v, want ErrCorrupt", err)
	}
}

func TestValidateQualificationCatalogRequiresAllCategories(t *testing.T) {
	t.Parallel()
	scenarios := append([]QualificationScenario(nil), RequiredQualificationScenarios...)
	filtered := make([]QualificationScenario, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario.Category != QualificationDurability {
			filtered = append(filtered, scenario)
		}
	}
	if err := ValidateQualificationCatalog(filtered); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing category error = %v, want ErrCorrupt", err)
	}
}

func TestValidateQualificationCatalogRequiresEvidenceContract(t *testing.T) {
	t.Parallel()
	scenarios := append([]QualificationScenario(nil), RequiredQualificationScenarios...)
	scenarios[0].RequiredEvidence = " "
	if err := ValidateQualificationCatalog(scenarios); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing evidence error = %v, want ErrCorrupt", err)
	}
}
