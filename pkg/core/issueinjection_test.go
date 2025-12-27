package core

import (
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestIssueInjectionRule(t *testing.T) {
	rule := IssueInjectionRule()
	if rule.RuleName != "issue-injection" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "issue-injection")
	}
}

func TestIssueInjection_VisitJobPre(t *testing.T) {
	tests := []struct {
		name       string
		job        *ast.Job
		wantErrors int
		desc       string
	}{
		{
			name: "unsafe: direct use of untrusted input (single line)",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{ github.event.pull_request.title }}"`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 1,
			desc:       "Single line untrusted input should be detected",
		},
		{
			name: "unsafe: direct use of untrusted input (multiline expression)",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{
  github.event.pull_request.title
}}"`,
								Pos: &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 1,
			desc:       "Multiline expression with untrusted input should be detected",
		},
		{
			name: "safe: using environment variable",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Env: &ast.Env{
							Vars: map[string]*ast.EnvVar{
								"TITLE": {
									Name: &ast.String{Value: "TITLE"},
									Value: &ast.String{
										Value: "${{ github.event.pull_request.title }}",
										Pos:   &ast.Position{Line: 1, Col: 1},
									},
								},
							},
						},
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "$TITLE"`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 0,
			desc:       "Using env variable should be safe",
		},
		{
			name: "safe: trusted input (github.sha)",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{ github.sha }}"`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 0,
			desc:       "Trusted input like github.sha should not trigger error",
		},
		{
			name: "unsafe: multiple untrusted inputs in multiline script",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{ github.event.pull_request.title }}"
echo "${{ github.event.pull_request.body }}"`,
								Pos: &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 2,
			desc:       "Multiple untrusted inputs should all be detected",
		},
		{
			name: "unsafe: multiline expression with fallback",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo "${{
  github.event.pull_request.title ||
  github.event.issue.title
}}"`,
								Pos: &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 1,
			desc:       "Multiline expression with fallback should be detected",
		},
		{
			name: "safe: no run step (uses action)",
			job: &ast.Job{
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
			wantErrors: 0,
			desc:       "Action step should not be checked",
		},
		{
			name: "safe: empty steps array",
			job: &ast.Job{
				Steps: []*ast.Step{},
			},
			wantErrors: 0,
			desc:       "Empty steps should not cause error",
		},
		{
			name: "safe: nil steps array",
			job: &ast.Job{
				Steps: nil,
			},
			wantErrors: 0,
			desc:       "Nil steps should not cause error",
		},
		{
			name: "edge case: only opening braces",
			job: &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: `echo ${{`,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			},
			wantErrors: 0,
			desc:       "Invalid expression without closing braces should not cause error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := IssueInjectionRule()
			err := rule.VisitJobPre(tt.job)
			if err != nil {
				t.Fatalf("VisitJobPre() returned error: %v", err)
			}

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s\nVisitJobPre() got %d errors, want %d errors\nErrors: %v",
					tt.desc, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestIssueInjection_extractAndParseExpressions(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		desc      string
	}{
		{
			name:      "single expression",
			input:     `echo "${{ github.event.pull_request.title }}"`,
			wantCount: 1,
			desc:      "Should extract single expression",
		},
		{
			name:      "multiple expressions",
			input:     `echo "${{ github.sha }}" and "${{ github.ref }}"`,
			wantCount: 2,
			desc:      "Should extract multiple expressions",
		},
		{
			name: "multiline expression",
			input: `echo "${{
  github.event.pull_request.title
}}"`,
			wantCount: 1,
			desc:      "Should extract multiline expression",
		},
		{
			name: "multiline script with single-line expressions",
			input: `echo "${{ github.sha }}"
echo "${{ github.ref }}"`,
			wantCount: 2,
			desc:      "Should extract expressions from multiline script",
		},
		{
			name: "complex multiline expression",
			input: `echo "${{
  github.event.pull_request.title ||
  github.event.issue.title ||
  'default'
}}"`,
			wantCount: 1,
			desc:      "Should extract complex multiline expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := IssueInjectionRule()
			runStr := &ast.String{
				Value: tt.input,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}

			exprs := rule.extractAndParseExpressions(runStr)
			gotCount := len(exprs)

			if gotCount != tt.wantCount {
				t.Errorf("%s\nextractAndParseExpressions() got %d expressions, want %d\nInput: %q",
					tt.desc, gotCount, tt.wantCount, tt.input)
			}
		})
	}
}
