package core

import (
	"testing"
)

func TestUntrustedCheckoutRule(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
		errMsg  string
	}{
		{
			name: "Safe: pull_request trigger with checkout",
			yaml: `
name: Test
on: pull_request
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
			name: "Safe: pull_request_target without checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with checkout of base branch",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with checkout without ref",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "Safe: pull_request_target with literal ref",
			yaml: `
name: Test
on: pull_request_target
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
			name: "Vulnerable: pull_request_target with PR HEAD SHA",
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
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: pull_request_target with PR HEAD ref",
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
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: issue_comment with PR checkout",
			yaml: `
name: Test
on: issue_comment
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Vulnerable: workflow_run with PR checkout",
			yaml: `
name: Test
on: workflow_run
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Multiple triggers with only safe ones",
			yaml: `
name: Test
on: [push, pull_request]
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
			name: "Vulnerable: Multiple triggers including dangerous one",
			yaml: `
name: Test
on: [push, pull_request_target]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Multiple jobs, no dangerous checkouts",
			yaml: `
name: Test
on: pull_request_target
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  job2:
    runs-on: ubuntu-latest
    steps:
      - run: echo "hello"
`,
			wantErr: false,
		},
		{
			name: "Vulnerable: Multiple jobs, one with dangerous checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  job1:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  job2:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			wantErr: true,
			errMsg:  "checking out untrusted code from pull request",
		},
		{
			name: "Safe: Using other actions, not checkout",
			yaml: `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: '18'
`,
			wantErr: false,
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
			rule := NewUntrustedCheckoutRule()

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

func TestUntrustedCheckoutDetectsAllDangerousTriggers(t *testing.T) {
	dangerousTriggers := []string{
		"pull_request_target",
		"issue_comment",
		"workflow_run",
	}

	for _, trigger := range dangerousTriggers {
		t.Run(trigger, func(t *testing.T) {
			yaml := `
name: Test
on: ` + trigger + `
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
			// Parse the workflow
			workflow, errs := Parse([]byte(yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check that error was found
			ruleErrs := rule.Errors()
			if len(ruleErrs) == 0 {
				t.Errorf("Expected error for dangerous trigger %q but got none", trigger)
			}
		})
	}
}

func TestUntrustedCheckoutDetectsAllDangerousRefPatterns(t *testing.T) {
	dangerousRefs := []struct {
		ref  string
		desc string
	}{
		{
			ref:  "${{ github.event.pull_request.head.sha }}",
			desc: "PR HEAD SHA",
		},
		{
			ref:  "${{ github.event.pull_request.head.ref }}",
			desc: "PR HEAD ref",
		},
	}

	for _, refCase := range dangerousRefs {
		t.Run(refCase.desc, func(t *testing.T) {
			yaml := `
name: Test
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ` + refCase.ref + `
`
			// Parse the workflow
			workflow, errs := Parse([]byte(yaml))
			if len(errs) > 0 {
				t.Fatalf("Failed to parse workflow: %v", errs)
			}

			// Create rule instance
			rule := NewUntrustedCheckoutRule()

			// Create visitor and add rule
			visitor := NewSyntaxTreeVisitor()
			visitor.AddVisitor(rule)

			// Visit the workflow
			if err := visitor.VisitTree(workflow); err != nil {
				t.Fatalf("Failed to visit tree: %v", err)
			}

			// Check that error was found
			ruleErrs := rule.Errors()
			if len(ruleErrs) == 0 {
				t.Errorf("Expected error for dangerous ref pattern %q but got none", refCase.ref)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
