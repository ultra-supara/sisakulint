package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestEnvPathInjectionCriticalRule(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()
	if rule.RuleName != "envpath-injection-critical" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "envpath-injection-critical")
	}
}

func TestEnvPathInjectionCritical_PrivilegedTriggers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		trigger     string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "pull_request_target + GITHUB_PATH",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect PATH injection in privileged trigger",
		},
		{
			name:        "issue_comment + GITHUB_PATH",
			trigger:     "issue_comment",
			runScript:   `echo "${{ github.event.comment.body }}" >> $GITHUB_PATH`,
			wantErrors:  1,
			description: "Should detect PATH injection in issue_comment",
		},
		{
			name:        "workflow_run + GITHUB_PATH with head_commit",
			trigger:     "workflow_run",
			runScript:   `echo "${{ github.event.head_commit.message }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect PATH injection in workflow_run",
		},
		{
			name:        "pull_request (not privileged)",
			trigger:     "pull_request",
			runScript:   `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for non-privileged trigger",
		},
		{
			name:    "multiple GITHUB_PATH writes",
			trigger: "pull_request_target",
			runScript: `echo "${{ github.event.pull_request.title }}" >> "$GITHUB_PATH"
echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  2,
			description: "Should detect both PATH injections",
		},
		{
			name:        "safe with trusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "/usr/local/bin" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for hardcoded path",
		},
		{
			name:        "safe with github.workspace",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.workspace }}/bin" >> "$GITHUB_PATH"`,
			wantErrors:  0,
			description: "Should not detect for trusted github.workspace",
		},
		{
			name:        "extracted path from untrusted input",
			trigger:     "pull_request_target",
			runScript:   `echo "${{ github.event.comment.body }}" >> "$GITHUB_PATH"`,
			wantErrors:  1,
			description: "Should detect untrusted input even in complex patterns",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := EnvPathInjectionCriticalRule()

			// Create workflow with specified trigger
			workflow := &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: tt.trigger},
					},
				},
			}

			// Create job with GITHUB_PATH write
			job := &ast.Job{
				Steps: []*ast.Step{
					{
						Exec: &ast.ExecRun{
							Run: &ast.String{
								Value: tt.runScript,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			// Visit workflow first
			err := rule.VisitWorkflowPre(workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre() returned error: %v", err)
			}

			// Then visit job
			err = rule.VisitJobPre(job)
			if err != nil {
				t.Fatalf("VisitJobPre() returned error: %v", err)
			}

			gotErrors := len(rule.Errors())

			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d", tt.description, gotErrors, tt.wantErrors)
				for _, err := range rule.Errors() {
					t.Logf("  error: %s", err.Description)
				}
			}
		})
	}
}

func TestEnvPathInjectionCritical_AutoFix(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("expected errors but got none")
	}

	// Get the step
	step := job.Steps[0]

	// Apply fix
	err := rule.FixStep(step)
	if err != nil {
		t.Fatalf("FixStep() returned error: %v", err)
	}

	// Verify the fix
	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		t.Fatal("run script is nil")
	}

	// Check that the expression was sanitized with realpath
	if !strings.Contains(run.Run.Value, `realpath`) {
		t.Errorf("expected sanitization with realpath, got: %s", run.Run.Value)
	}

	// Check that env var was added
	if step.Env == nil || len(step.Env.Vars) == 0 {
		t.Error("expected env vars to be added")
	}
}

func TestEnvPathInjectionCritical_ErrorMessage(t *testing.T) {
	t.Parallel()
	rule := EnvPathInjectionCriticalRule()

	// Create workflow with privileged trigger
	workflow := &ast.Workflow{
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "pull_request_target"},
			},
		},
	}

	// Create job with vulnerable GITHUB_PATH write
	job := &ast.Job{
		Steps: []*ast.Step{
			{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: `echo "${{ github.event.pull_request.body }}" >> "$GITHUB_PATH"`,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	// Visit workflow and job
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(job)

	errors := rule.Errors()
	if len(errors) == 0 {
		t.Fatal("expected errors but got none")
	}

	// Check error message contains key information
	errMsg := errors[0].Description
	if !strings.Contains(errMsg, "PATH injection (critical)") {
		t.Errorf("error message should contain 'PATH injection (critical)', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "github.event.pull_request.body") {
		t.Errorf("error message should contain the untrusted path, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "GITHUB_PATH") {
		t.Errorf("error message should mention GITHUB_PATH, got: %s", errMsg)
	}
}
