package core

import (
	"strings"
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestIssueInjectionRule(t *testing.T) {
	tests := []struct {
		name string
		want *IssueInjection
	}{
		{
			name: "Create IssueInjection rule",
			want: &IssueInjection{
				BaseRule: BaseRule{
					RuleName: "issue-injection",
					RuleDesc: "This rule checks for issue injection in the source code",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IssueInjectionRule()
			if got.RuleName != tt.want.RuleName || got.RuleDesc != tt.want.RuleDesc {
				t.Errorf("IssueInjectionRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssueInjection_VisitJobPre(t *testing.T) {
	tests := []struct {
		name          string
		job           *ast.Job
		expectError   bool
		errorContains string
	}{
		{
			name: "Detects direct expression usage in run step",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo ${{ github.event.issue.title }}",
								Literal: false,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Detects expression in multiline run step",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "#!/bin/bash\necho ${{ github.event.pull_request.title }}\necho done",
								Literal: true,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Detects expression at start of line",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "${{ github.event.comment.body }}",
								Literal: false,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Detects multiple expressions in same line",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo ${{ github.actor }} and ${{ github.event.sender.login }}",
								Literal: false,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Detects expression spanning multiple lines",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos: &ast.Position{Line: 5, Col: 10},
								Value: `echo ${{\n  github.event.issue.body\n}}`,
								Literal: true,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Safe case: No expression in run step",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo Hello World",
								Literal: false,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Safe case: Using environment variable instead",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo $ISSUE_TITLE",
								Literal: false,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Safe case: Expression-like string in comment",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "# This comment mentions ${{ but no closing",
								Literal: false,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Safe case: No run step (uses action)",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecAction{
							Uses: &ast.String{
								Pos:   &ast.Position{Line: 5, Col: 10},
								Value: "actions/checkout@v2",
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Safe case: Empty run step",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "",
								Literal: false,
							},
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Edge case: Only opening braces",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo ${{",
								Literal: false,
							},
						},
					},
				},
			},
			expectError: false, // No closing braces means invalid expression, caught by parser
		},
		{
			name: "Edge case: Opening braces with no closing in multiline",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo ${{\necho done",
								Literal: true,
							},
						},
					},
				},
			},
			expectError: false, // No closing braces means invalid expression
		},
		{
			name: "Multiple steps with mixed expressions",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 5, Col: 10},
								Value:   "echo safe",
								Literal: false,
							},
						},
					},
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 8, Col: 10},
								Value:   "echo ${{ github.event.issue.title }}",
								Literal: false,
							},
						},
					},
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 11, Col: 10},
								Value:   "echo another safe",
								Literal: false,
							},
						},
					},
				},
			},
			expectError:   true,
			errorContains: "Direct use of ${{ ... }} in run steps",
		},
		{
			name: "Nil Exec in step",
			job: &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: nil,
					},
				},
			},
			expectError: false,
		},
		{
			name: "Empty steps array",
			job: &ast.Job{
				ID:    &ast.String{Value: "test_job"},
				Steps: []*ast.Step{},
			},
			expectError: false,
		},
		{
			name: "Nil steps array",
			job: &ast.Job{
				ID:    &ast.String{Value: "test_job"},
				Steps: nil,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := IssueInjectionRule()
			initialErrorCount := len(rule.Errors())

			err := rule.VisitJobPre(tt.job)

			// The method should never return an error
			if err != nil {
				t.Errorf("IssueInjection.VisitJobPre() unexpected error = %v", err)
			}

			finalErrorCount := len(rule.Errors())
			hasError := finalErrorCount > initialErrorCount

			if hasError != tt.expectError {
				t.Errorf("IssueInjection.VisitJobPre() error detection = %v, want %v", hasError, tt.expectError)
				if hasError {
					t.Logf("Errors detected: %v", rule.Errors())
				}
			}

			if tt.expectError && hasError && tt.errorContains != "" {
				found := false
				for _, e := range rule.Errors()[initialErrorCount:] {
					if strings.Contains(e.Description, tt.errorContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("IssueInjection.VisitJobPre() error message does not contain %q, got errors: %v",
						tt.errorContains, rule.Errors()[initialErrorCount:])
				}
			}
		})
	}
}

func TestIssueInjection_RealWorldScenarios(t *testing.T) {
	tests := []struct {
		name          string
		runScript     string
		expectError   bool
		description   string
	}{
		{
			name: "Vulnerable: Issue title injection",
			runScript: `
				title="${{ github.event.issue.title }}"
				echo "Issue title: $title"
			`,
			expectError: true,
			description: "Direct use of issue title can allow command injection",
		},
		{
			name: "Vulnerable: PR body injection",
			runScript: `
				curl -X POST https://api.example.com \
					-d "body=${{ github.event.pull_request.body }}"
			`,
			expectError: true,
			description: "Direct use of PR body in curl command",
		},
		{
			name: "Vulnerable: Comment injection",
			runScript: `
				comment="${{ github.event.comment.body }}"
				./process_comment.sh "$comment"
			`,
			expectError: true,
			description: "Direct use of comment body in script",
		},
		{
			name: "Safe: Using environment variables",
			runScript: `
				echo "Issue title: $ISSUE_TITLE"
				./process.sh "$ISSUE_TITLE"
			`,
			expectError: false,
			description: "Safe pattern using environment variables",
		},
		{
			name: "Safe: No user input",
			runScript: `
				echo "Running tests"
				npm test
				npm run build
			`,
			expectError: false,
			description: "No user input involved",
		},
		{
			name: "Vulnerable: Actor name injection",
			runScript: `
				echo "Triggered by ${{ github.actor }}"
			`,
			expectError: true,
			description: "Direct use of actor name can be exploited",
		},
		{
			name: "Safe: Hard-coded values only",
			runScript: `
				VERSION="1.0.0"
				echo "Version: $VERSION"
			`,
			expectError: false,
			description: "Only hard-coded values",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := IssueInjectionRule()
			job := &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 10, Col: 5},
								Value:   tt.runScript,
								Literal: true,
							},
						},
					},
				},
			}

			initialErrorCount := len(rule.Errors())
			err := rule.VisitJobPre(job)

			if err != nil {
				t.Errorf("IssueInjection.VisitJobPre() unexpected error = %v", err)
			}

			finalErrorCount := len(rule.Errors())
			hasError := finalErrorCount > initialErrorCount

			if hasError != tt.expectError {
				t.Errorf("%s: error detection = %v, want %v", tt.description, hasError, tt.expectError)
				if hasError {
					for _, e := range rule.Errors()[initialErrorCount:] {
						t.Logf("Error: %s at line %d", e.Description, e.LineNumber)
					}
				}
			}
		})
	}
}

func TestIssueInjection_MultilineExpressions(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		literal     bool
		expectError bool
		description string
	}{
		{
			name: "Multiline expression with closing on different line",
			runScript: `echo ${{
  github.event.issue.title
}}`,
			literal:     true,
			expectError: true,
			description: "Expression spans multiple lines",
		},
		{
			name: "Multiline with complex expression",
			runScript: `data=${{
  toJSON(github.event.issue)
}}
echo "$data"`,
			literal:     true,
			expectError: true,
			description: "Complex JSON expression across lines",
		},
		{
			name: "Multiple single-line expressions in multiline script",
			runScript: `echo ${{ github.actor }}
echo ${{ github.event.issue.title }}
echo done`,
			literal:     true,
			expectError: true,
			description: "Multiple expressions in different lines",
		},
		{
			name: "No closing braces across multiple lines",
			runScript: `echo ${{
  github.event.issue.title
echo done`,
			literal:     true,
			expectError: false,
			description: "Invalid expression without closing braces",
		},
		{
			name: "Safe multiline script",
			runScript: `#!/bin/bash
echo "Starting process"
npm install
npm test
echo "Done"`,
			literal:     true,
			expectError: false,
			description: "Safe multiline script without expressions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := IssueInjectionRule()
			job := &ast.Job{
				ID: &ast.String{Value: "test_job"},
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Pos:     &ast.Position{Line: 10, Col: 5},
								Value:   tt.runScript,
								Literal: tt.literal,
							},
						},
					},
				},
			}

			initialErrorCount := len(rule.Errors())
			err := rule.VisitJobPre(job)

			if err != nil {
				t.Errorf("IssueInjection.VisitJobPre() unexpected error = %v", err)
			}

			finalErrorCount := len(rule.Errors())
			hasError := finalErrorCount > initialErrorCount

			if hasError != tt.expectError {
				t.Errorf("%s: error detection = %v, want %v", tt.description, hasError, tt.expectError)
			}
		})
	}
}
