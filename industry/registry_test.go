package industry

import (
	"context"
	"testing"
)

// stubFilter is a minimal IndustryFilter for registry tests.
type stubFilter struct {
	id       string
	priority int
}

func (s *stubFilter) ID() string    { return s.id }
func (s *stubFilter) Priority() int { return s.priority }
func (s *stubFilter) Filter(_ context.Context, _ FilterRequest) (FilterDecision, error) {
	return FilterDecision{Allowed: true}, nil
}

// ─── Registry tests ───────────────────────────────────────────────────────────

func TestRegistry_GlobalFilters_ReturnedForUnknownTenant(t *testing.T) {
	r := NewRegistry()
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	r.RegisterFilter(&stubFilter{"pci", 130})

	filters := r.FiltersForTenant("unknown-tenant")
	if len(filters) != 2 {
		t.Fatalf("expected 2 global filters, got %d", len(filters))
	}
}

func TestRegistry_PriorityOrder_Ascending(t *testing.T) {
	r := NewRegistry()
	// Register in reverse priority order to ensure sorting works.
	r.RegisterFilter(&stubFilter{"pci", 130})
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	r.RegisterFilter(&stubFilter{"gdpr", 110})

	filters := r.FiltersForTenant("any")
	want := []string{"hipaa", "gdpr", "pci"}
	for i, f := range filters {
		if f.ID() != want[i] {
			t.Errorf("filters[%d].ID()=%q, want %q", i, f.ID(), want[i])
		}
	}
}

func TestRegistry_TenantOverride_NarrowsFilters(t *testing.T) {
	r := NewRegistry()
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	r.RegisterFilter(&stubFilter{"gdpr", 110})
	r.RegisterFilter(&stubFilter{"pci", 130})

	// Tenant only wants hipaa and pci.
	r.SetTenantFilters("tenant-a", []string{"hipaa", "pci"})

	filters := r.FiltersForTenant("tenant-a")
	if len(filters) != 2 {
		t.Fatalf("expected 2 filters for tenant-a, got %d", len(filters))
	}
	ids := []string{filters[0].ID(), filters[1].ID()}
	if ids[0] != "hipaa" || ids[1] != "pci" {
		t.Errorf("unexpected filter IDs: %v", ids)
	}
}

func TestRegistry_TenantOverride_EmptySlice_OptsOut(t *testing.T) {
	r := NewRegistry()
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	r.SetTenantFilters("opted-out", []string{})

	filters := r.FiltersForTenant("opted-out")
	if len(filters) != 0 {
		t.Errorf("expected 0 filters for opted-out tenant, got %d", len(filters))
	}
}

func TestRegistry_TenantOverride_UnknownFilterID_Skipped(t *testing.T) {
	r := NewRegistry()
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	// Override references a filter ID not registered globally.
	r.SetTenantFilters("t2", []string{"hipaa", "nonexistent"})

	filters := r.FiltersForTenant("t2")
	if len(filters) != 1 || filters[0].ID() != "hipaa" {
		t.Errorf("expected only hipaa, got %v", filters)
	}
}

func TestRegistry_EmptyRegistry_ReturnsNilForAnyTenant(t *testing.T) {
	r := NewRegistry()
	filters := r.FiltersForTenant("anything")
	if len(filters) != 0 {
		t.Errorf("expected empty slice, got %d", len(filters))
	}
}

func TestRegistry_MultipleTenants_Isolated(t *testing.T) {
	r := NewRegistry()
	r.RegisterFilter(&stubFilter{"hipaa", 100})
	r.RegisterFilter(&stubFilter{"gdpr", 110})
	r.RegisterFilter(&stubFilter{"itar", 120})

	r.SetTenantFilters("healthcare", []string{"hipaa"})
	r.SetTenantFilters("finance", []string{"gdpr", "itar"})

	hc := r.FiltersForTenant("healthcare")
	fn := r.FiltersForTenant("finance")

	if len(hc) != 1 || hc[0].ID() != "hipaa" {
		t.Errorf("healthcare: unexpected filters: %v", hc)
	}
	if len(fn) != 2 {
		t.Errorf("finance: expected 2 filters, got %d", len(fn))
	}
}
