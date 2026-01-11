package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestImproperAccessControlRule(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "Safe: pull_request_target with labeled type and sha ref",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [labeled]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with opened type only and sha ref",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with synchronize but sha ref (not mutable ref)",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: pull_request_target with synchronize and mutable head.ref",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
		{
			name: "Vulnerable: pull_request_target with synchronize and github.head_ref",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
		{
			name: "Vulnerable: mutable ref without label condition",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
		{
			name: "Safe: pull_request (not pull_request_target)",
			yaml: `
name: Test
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: pull_request_target without types (implicit synchronize)",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
		{
			name: "Vulnerable: pull_request_target without types with label condition",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
		{
			name: "Safe: pull_request_target without types but with sha ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with synchronize but no checkout",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
		{
			name: "Safe: checkout without ref (default is safe)",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "Safe: checkout with literal ref",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
`,
			wantErr: false,
		},
		{
			name: "Multiple vulnerable checkouts",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'approved')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			wantErr: true,
			errMsg:  "improper access control",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewImproperAccessControlRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check errors
			ruleErrs := rule.Errors()
			if tt.wantErr {
				if len(ruleErrs) == 0 {
					t.Errorf("Expected error but got none")
				} else {
					// Verify error message contains expected text
					found := false
					for _, err := range ruleErrs {
						if tt.errMsg != "" && containsString(err.Description, tt.errMsg) {
							found = true
							break
						}
					}
					if !found && tt.errMsg != "" {
						t.Errorf("Expected error message to contain %q, but got: %v", tt.errMsg, ruleErrs[0].Description)
					}
				}
			} else {
				if len(ruleErrs) > 0 {
					t.Errorf("Unexpected error: %v", ruleErrs[0].Description)
				}
			}
		})
	}
}

func TestImproperAccessControlAutoFixer(t *testing.T) {
	tests := []struct {
		name           string
		yaml           string
		expectAutoFix  bool
		autoFixerCount int
	}{
		{
			name: "Auto-fixer added for vulnerable pattern",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectAutoFix:  true,
			autoFixerCount: 1,
		},
		{
			name: "No auto-fixer for safe pattern",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [labeled]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			expectAutoFix:  false,
			autoFixerCount: 0,
		},
		{
			name: "Multiple auto-fixers for multiple vulnerable checkouts",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			expectAutoFix:  true,
			autoFixerCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewImproperAccessControlRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check auto-fixer count
			autoFixerCount := len(rule.AutoFixers())
			if autoFixerCount != tt.autoFixerCount {
				t.Errorf("Expected %d auto-fixer(s), but got %d", tt.autoFixerCount, autoFixerCount)
			}

			if tt.expectAutoFix && autoFixerCount == 0 {
				t.Error("Expected auto-fixer to be added, but none was added")
			}

			if !tt.expectAutoFix && autoFixerCount > 0 {
				t.Errorf("Expected no auto-fixer, but %d was added", autoFixerCount)
			}
		})
	}
}

func TestImproperAccessControlFixStep(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectedRef string
		expectError bool
	}{
		{
			name: "Fix head.ref to head.sha",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`,
			expectedRef: "${{ github.event.pull_request.head.sha }}",
			expectError: false,
		},
		{
			name: "Fix github.head_ref to head.sha",
			yaml: `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
`,
			expectedRef: "${{ github.event.pull_request.head.sha }}",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the workflow
			workflow, errs := Parse([]byte(tt.yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewImproperAccessControlRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow to detect issues and add auto-fixers
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Get auto-fixers
			autoFixers := rule.AutoFixers()
			if len(autoFixers) == 0 {
				t.Fatal("No auto-fixer was added")
			}

			// Apply the fix
			if err := autoFixers[0].Fix(); err != nil {
				if !tt.expectError {
					t.Errorf("FixStep() unexpected error = %v", err)
				}
				return
			}

			if tt.expectError {
				t.Error("Expected error but got none")
				return
			}

			// Verify the fix was applied
			var foundJob *ast.Job
			for _, job := range workflow.Jobs {
				foundJob = job
				break
			}
			if foundJob == nil {
				t.Fatal("No job found in workflow")
			}

			if len(foundJob.Steps) == 0 {
				t.Fatal("No steps found in job")
			}

			step := foundJob.Steps[0]
			action, ok := step.Exec.(*ast.ExecAction)
			if !ok {
				t.Fatal("Step is not an ExecAction")
			}

			refInput, exists := action.Inputs["ref"]
			if !exists {
				t.Fatal("No ref input found")
			}

			if refInput.Value.Value != tt.expectedRef {
				t.Errorf("Expected ref to be %q, but got %q", tt.expectedRef, refInput.Value.Value)
			}
		})
	}
}

func TestImproperAccessControlFixWebhookEventTypes(t *testing.T) {
	yaml := `
name: Test
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`

	// Parse the workflow
	workflow, errs := Parse([]byte(yaml))
	if len(errs) > 0 {
		t.Fatalf("Failed to parse workflow: %v", errs)
	}

	// Create rule instance
	rule := NewImproperAccessControlRule()

	// Create visitor and add rule
	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)

	// Visit the workflow to detect issues
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("Failed to visit tree: %v", err)
	}

	// Get auto-fixers
	autoFixers := rule.AutoFixers()
	if len(autoFixers) == 0 {
		t.Fatal("No auto-fixer was added")
	}

	// Apply the fix
	if err := autoFixers[0].Fix(); err != nil {
		t.Fatalf("FixStep() unexpected error = %v", err)
	}

	// Verify the webhook event types were fixed
	var webhookEvent *ast.WebhookEvent
	for _, event := range workflow.On {
		if we, ok := event.(*ast.WebhookEvent); ok && we.EventName() == "pull_request_target" {
			webhookEvent = we
			break
		}
	}

	if webhookEvent == nil {
		t.Fatal("No webhook event found")
	}

	// Check that 'synchronize' was replaced with 'labeled'
	hasSynchronize := false
	hasLabeled := false
	for _, eventType := range webhookEvent.Types {
		if eventType.Value == "synchronize" {
			hasSynchronize = true
		}
		if eventType.Value == "labeled" {
			hasLabeled = true
		}
	}

	if hasSynchronize {
		t.Error("Expected 'synchronize' to be removed/replaced, but it still exists")
	}

	if !hasLabeled {
		t.Error("Expected 'labeled' to be added, but it was not found")
	}
}

func TestImproperAccessControlFixWebhookEventTypesUnspecified(t *testing.T) {
	// Test case: types is not specified (implicit synchronize)
	yaml := `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: contains(github.event.pull_request.labels.*.name, 'safe to test')
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`

	// Parse the workflow
	workflow, errs := Parse([]byte(yaml))
	if len(errs) > 0 {
		t.Fatalf("Failed to parse workflow: %v", errs)
	}

	// Create rule instance
	rule := NewImproperAccessControlRule()

	// Create visitor and add rule
	visitor := NewSyntaxTreeVisitor()
	visitor.AddVisitor(rule)

	// Visit the workflow to detect issues
	if err := visitor.VisitTree(workflow); err != nil {
		t.Fatalf("Failed to visit tree: %v", err)
	}

	// Verify that an error was detected
	ruleErrs := rule.Errors()
	if len(ruleErrs) == 0 {
		t.Fatal("Expected error for types-unspecified pull_request_target but got none")
	}

	// Get auto-fixers
	autoFixers := rule.AutoFixers()
	if len(autoFixers) == 0 {
		t.Fatal("No auto-fixer was added")
	}

	// Apply the fix
	if err := autoFixers[0].Fix(); err != nil {
		t.Fatalf("FixStep() unexpected error = %v", err)
	}

	// Verify the webhook event types were fixed
	var webhookEvent *ast.WebhookEvent
	for _, event := range workflow.On {
		if we, ok := event.(*ast.WebhookEvent); ok && we.EventName() == "pull_request_target" {
			webhookEvent = we
			break
		}
	}

	if webhookEvent == nil {
		t.Fatal("No webhook event found")
	}

	// Check that 'labeled' was added (since types was empty, it should now have 'labeled')
	if len(webhookEvent.Types) == 0 {
		t.Error("Expected types to be populated with 'labeled', but types is still empty")
	}

	hasLabeled := false
	for _, eventType := range webhookEvent.Types {
		if eventType.Value == "labeled" {
			hasLabeled = true
			break
		}
	}

	if !hasLabeled {
		t.Error("Expected 'labeled' to be added when types was unspecified, but it was not found")
	}
}

func TestImproperAccessControlRuleDetectsLabelPatterns(t *testing.T) {
	labelPatterns := []string{
		"contains(github.event.pull_request.labels.*.name, 'approved')",
		"github.event.pull_request.labels",
		"github.event.label.name == 'safe'",
	}

	for _, pattern := range labelPatterns {
		t.Run(pattern, func(t *testing.T) {
			yaml := `
name: Test
on:
  pull_request_target:
    types: [synchronize]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: ` + pattern + `
        with:
          ref: ${{ github.event.pull_request.head.ref }}
`
			// Parse the workflow
			workflow, errs := Parse([]byte(yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewImproperAccessControlRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check that error was found (label-based condition + mutable ref + synchronize)
			ruleErrs := rule.Errors()
			if len(ruleErrs) == 0 {
				t.Errorf("Expected error for label pattern %q but got none", pattern)
			}
		})
	}
}
