package industry

import "sort"

// Registry maps tenants to their configured blocking filters.
// Global filters apply to all tenants unless a tenant override is set.
type Registry struct {
	filters        []IndustryFilter    // ordered by Priority ascending
	tenantOverride map[string][]string // tenantID → ordered list of filter IDs
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{tenantOverride: make(map[string][]string)}
}

// RegisterFilter adds f to the global filter list and re-sorts by Priority.
func (r *Registry) RegisterFilter(f IndustryFilter) {
	r.filters = append(r.filters, f)
	sort.Slice(r.filters, func(i, j int) bool {
		return r.filters[i].Priority() < r.filters[j].Priority()
	})
}

// SetTenantFilters limits which filter IDs run for tenantID.
// An empty ids slice means the tenant has opted out of all industry filters.
func (r *Registry) SetTenantFilters(tenantID string, ids []string) {
	r.tenantOverride[tenantID] = ids
}

// FiltersForTenant returns the ordered blocking filters that apply to tenantID.
// If no override is configured, the global filter list is returned.
// If an override exists but is empty, nil is returned (tenant opted out).
func (r *Registry) FiltersForTenant(tenantID string) []IndustryFilter {
	override, hasOverride := r.tenantOverride[tenantID]
	if !hasOverride {
		return r.filters
	}
	if len(override) == 0 {
		return nil
	}
	byID := make(map[string]IndustryFilter, len(r.filters))
	for _, f := range r.filters {
		byID[f.ID()] = f
	}
	out := make([]IndustryFilter, 0, len(override))
	for _, id := range override {
		if f, ok := byID[id]; ok {
			out = append(out, f)
		}
	}
	return out
}
