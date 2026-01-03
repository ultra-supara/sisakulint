package core

import (
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestNewCachePoisoningRule(t *testing.T) {
	rule := NewCachePoisoningRule()

	if rule.RuleName != "cache-poisoning" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "cache-poisoning")
	}
	if rule.RuleDesc == "" {
		t.Error("RuleDesc should not be empty")
	}
}

func TestIsUnsafeTrigger(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		want      bool
	}{
		{"issue_comment is unsafe", "issue_comment", true},
		{"pull_request_target is unsafe", "pull_request_target", true},
		{"workflow_run is unsafe", "workflow_run", true},
		{"push is safe", "push", false},
		{"pull_request is safe", "pull_request", false},
		{"schedule is safe", "schedule", false},
		{"empty is safe", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnsafeTrigger(tt.eventName)
			if got != tt.want {
				t.Errorf("isUnsafeTrigger(%q) = %v, want %v", tt.eventName, got, tt.want)
			}
		})
	}
}

func TestIsUnsafeCheckoutRef(t *testing.T) {
	tests := []struct {
		name     string
		refValue string
		want     bool
	}{
		{
			name:     "github.head_ref is unsafe",
			refValue: "${{ github.head_ref }}",
			want:     true,
		},
		{
			name:     "github.event.pull_request.head.sha is unsafe",
			refValue: "${{ github.event.pull_request.head.sha }}",
			want:     true,
		},
		{
			name:     "github.event.pull_request.head.ref is unsafe",
			refValue: "${{ github.event.pull_request.head.ref }}",
			want:     true,
		},
		{
			name:     "refs/pull merge ref is unsafe",
			refValue: "refs/pull/${{ github.event.number }}/merge",
			want:     true,
		},
		{
			name:     "empty is safe",
			refValue: "",
			want:     false,
		},
		{
			name:     "main branch is safe",
			refValue: "main",
			want:     false,
		},
		{
			name:     "github.ref is safe",
			refValue: "${{ github.ref }}",
			want:     false,
		},
		{
			name:     "github.sha is safe",
			refValue: "${{ github.sha }}",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnsafeCheckoutRef(tt.refValue)
			if got != tt.want {
				t.Errorf("isUnsafeCheckoutRef(%q) = %v, want %v", tt.refValue, got, tt.want)
			}
		})
	}
}

func TestIsCacheAction(t *testing.T) {
	tests := []struct {
		name   string
		uses   string
		inputs map[string]*ast.Input
		want   bool
	}{
		{
			name:   "actions/cache is cache action",
			uses:   "actions/cache@v3",
			inputs: nil,
			want:   true,
		},
		{
			name:   "actions/cache without version is cache action",
			uses:   "actions/cache",
			inputs: nil,
			want:   true,
		},
		{
			name: "actions/setup-node with cache: npm",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "npm"}},
			},
			want: true,
		},
		{
			name: "actions/setup-python with cache: pip",
			uses: "actions/setup-python@v5",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "pip"}},
			},
			want: true,
		},
		{
			name: "actions/setup-go with cache: true",
			uses: "actions/setup-go@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "true"}},
			},
			want: true,
		},
		{
			name: "actions/setup-node without cache",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"node-version": {Value: &ast.String{Value: "18"}},
			},
			want: false,
		},
		{
			name: "actions/setup-node with cache: false",
			uses: "actions/setup-node@v4",
			inputs: map[string]*ast.Input{
				"cache": {Value: &ast.String{Value: "false"}},
			},
			want: false,
		},
		{
			name:   "other action is not cache action",
			uses:   "actions/checkout@v4",
			inputs: nil,
			want:   false,
		},
		{
			name:   "empty uses",
			uses:   "",
			inputs: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCacheAction(tt.uses, tt.inputs)
			if got != tt.want {
				t.Errorf("isCacheAction(%q, %v) = %v, want %v", tt.uses, tt.inputs, got, tt.want)
			}
		})
	}
}

func TestCachePoisoningRule_VisitWorkflowPre(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
			&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
		},
	}

	err := rule.VisitWorkflowPre(workflow)
	if err != nil {
		t.Errorf("VisitWorkflowPre() error = %v", err)
	}

	if len(rule.unsafeTriggers) != 1 {
		t.Errorf("unsafeTriggers length = %d, want 1", len(rule.unsafeTriggers))
	}
	if rule.unsafeTriggers[0] != "pull_request_target" {
		t.Errorf("unsafeTriggers[0] = %q, want %q", rule.unsafeTriggers[0], "pull_request_target")
	}
}

func TestCachePoisoningRule_DetectsVulnerableWorkflow(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with pull_request_target trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	// Simulate job start
	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Simulate checkout with unsafe ref
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	// Simulate cache action
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(errors))
	}

	if errors[0].LineNumber != 15 {
		t.Errorf("Error line = %d, want 15", errors[0].LineNumber)
	}
}

func TestCachePoisoningRule_NoErrorWithSafeTrigger(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with safe trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors with safe trigger, got %d", len(errors))
	}
}

func TestCachePoisoningRule_NoErrorWithoutUnsafeCheckout(t *testing.T) {
	rule := NewCachePoisoningRule()

	// Simulate workflow with unsafe trigger but no unsafe checkout
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	// Checkout without ref (default behavior - safe)
	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors without unsafe checkout, got %d", len(errors))
	}
}

func TestCachePoisoningRule_DetectsSetupNodeWithCache(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "issue_comment"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	job := &ast.Job{}
	_ = rule.VisitJobPre(job)

	checkoutStep := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.event.pull_request.head.sha }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep)

	setupNodeStep := &ast.Step{
		Pos: &ast.Position{Line: 15, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/setup-node@v4"},
			Inputs: map[string]*ast.Input{
				"node-version": {Value: &ast.String{Value: "18"}},
				"cache":        {Value: &ast.String{Value: "npm"}},
			},
		},
	}
	_ = rule.VisitStep(setupNodeStep)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for setup-node with cache, got %d", len(errors))
	}
}

func TestCachePoisoningRule_JobIsolation(t *testing.T) {
	rule := NewCachePoisoningRule()

	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
		},
	}
	_ = rule.VisitWorkflowPre(workflow)

	// First job with unsafe checkout
	job1 := &ast.Job{}
	_ = rule.VisitJobPre(job1)

	checkoutStep1 := &ast.Step{
		Pos: &ast.Position{Line: 10, Col: 1},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {Value: &ast.String{Value: "${{ github.head_ref }}"}},
			},
		},
	}
	_ = rule.VisitStep(checkoutStep1)
	_ = rule.VisitJobPost(job1)

	// Second job should have clean state
	job2 := &ast.Job{}
	_ = rule.VisitJobPre(job2)

	// Cache without unsafe checkout in this job
	cacheStep := &ast.Step{
		Pos: &ast.Position{Line: 30, Col: 1},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/cache@v3"},
			Inputs: map[string]*ast.Input{},
		},
	}
	_ = rule.VisitStep(cacheStep)

	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors due to job isolation, got %d", len(errors))
	}
}
