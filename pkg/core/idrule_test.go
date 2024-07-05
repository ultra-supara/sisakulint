package core

import (
	"testing"

	"github.com/ultra-supara/sisakulint/src/ast"
)

// TestIDRule tests the IDRule function.
func TestIDRule(t *testing.T) {
	want := &RuleID{
		BaseRule: BaseRule{
			RuleName: "id",
			RuleDesc: "Checks for duplication and naming convention of job/step IDs",
		},
		seen: make(map[string]*ast.Position),
	}
	got := IDRule()
	if got.RuleName != want.RuleName || got.RuleDesc != want.RuleDesc {
		t.Errorf("IDRule() = %v, want %v", got, want)
	}
}

// TestRuleID_VisitJobPre tests the VisitJobPre method.
func TestRuleID_VisitJobPre(t *testing.T) {
	// Setup mock Job object
	mockJob := &ast.Job{
		ID: &ast.String{Value: "valid_job_id"},
	}

	rule := IDRule()
	err := rule.VisitJobPre(mockJob)
	if err != nil {
		t.Errorf("VisitJobPre() error = %v, wantErr %v", err, false)
	}

	// Additional test cases...
}

// TestRuleID_VisitJobPost tests the VisitJobPost method.
func TestRuleID_VisitJobPost(t *testing.T) {
	// Setup mock Job object
	mockJob := &ast.Job{
		ID: &ast.String{Value: "valid_job_id"},
	}

	rule := IDRule()
	err := rule.VisitJobPost(mockJob)
	if err != nil {
		t.Errorf("VisitJobPost() error = %v, wantErr %v", err, false)
	}

	// Additional test cases...
}

// TestRuleID_VisitStep tests the VisitStep method.
func TestRuleID_VisitStep(t *testing.T) {
	// Setup mock Step object
	mockStep := &ast.Step{
		ID: &ast.String{Value: "valid_step_id"},
	}

	rule := IDRule()
	err := rule.VisitStep(mockStep)
	if err != nil {
		t.Errorf("VisitStep() error = %v, wantErr %v", err, false)
	}

	// Additional test cases...
}

// TestRuleID_validateConvention tests the validateConvention method.
func TestRuleID_validateConvention(t *testing.T) {
	// Setup mock String object
	mockString := &ast.String{Value: "valid_id"}

	rule := IDRule()
	rule.validateConvention(mockString, "job")

	// Check if the rule's error function was called correctly
	// You need to implement a way to check if the error function was called, perhaps by mocking it.

	// Additional test cases...
}

// Additional test functions and cases as necessary...
