package output_test

import (
	"testing"

	"github.com/zafrem/bastion-sentinel/types"
	"github.com/zafrem/bastion-sentinel/validators/output"
)

func TestPermission_FullAccess_AlwaysPassed(t *testing.T) {
	c := output.NewPermissionChecker()
	user := types.UserContext{AccessLevel: "full"}
	result := c.Check("Customer Kim purchased $5,000 worth of products.", user)
	if result.BoundaryViolated {
		t.Error("full access user should never have boundary violation")
	}
}

func TestPermission_NoAccessLevel_AlwaysPassed(t *testing.T) {
	c := output.NewPermissionChecker()
	result := c.Check("anything", types.UserContext{})
	if result.BoundaryViolated {
		t.Error("empty access level treated as full access")
	}
}

func TestPermission_KAnonymized_SpecificAmount_Violation(t *testing.T) {
	c := output.NewPermissionChecker()
	user := types.UserContext{AccessLevel: "k_anonymized"}
	// Response contains specific currency amounts — full-access content
	result := c.Check("Customer purchased $5,000 worth of items.", user)
	if !result.BoundaryViolated {
		t.Error("expected boundary violation: k_anonymized user with specific amounts")
	}
	if result.Status != "VIOLATION_PREVENTED" {
		t.Errorf("expected VIOLATION_PREVENTED, got %s", result.Status)
	}
}

func TestPermission_Aggregated_SpecificKRWAmount_Violation(t *testing.T) {
	c := output.NewPermissionChecker()
	user := types.UserContext{AccessLevel: "aggregated"}
	result := c.Check("고객이 5,000,000원 구매했습니다.", user)
	if !result.BoundaryViolated {
		t.Error("expected boundary violation for aggregated user with specific won amount")
	}
}

func TestPermission_KAnonymized_RangeOnly_Passed(t *testing.T) {
	c := output.NewPermissionChecker()
	user := types.UserContext{AccessLevel: "k_anonymized"}
	// Response uses ranges, no specific amounts
	result := c.Check("Customers in this segment typically spend between the mid-range.", user)
	if result.BoundaryViolated {
		t.Errorf("expected no violation for range-based response, got violation")
	}
}

func TestPermission_AccessLevels_InResult(t *testing.T) {
	c := output.NewPermissionChecker()
	user := types.UserContext{AccessLevel: "k_anonymized"}
	result := c.Check("Purchased $10,000 worth.", user)
	if result.UserAccessLevel != "k_anonymized" {
		t.Errorf("expected UserAccessLevel k_anonymized, got %s", result.UserAccessLevel)
	}
}
