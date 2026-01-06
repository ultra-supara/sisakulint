package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestNewSecretExposureRule(t *testing.T) {
	rule := NewSecretExposureRule()
	if rule.RuleName != "secret-exposure" {
		t.Errorf("RuleName = %q, want %q", rule.RuleName, "secret-exposure")
	}
	if !strings.Contains(rule.RuleDesc, "excessive secret exposure") {
		t.Errorf("RuleDesc should contain 'excessive secret exposure', got %q", rule.RuleDesc)
	}
}

func TestSecretExposure_ToJSONSecrets(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in env",
			envValue:    "${{ toJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect toJSON(secrets)",
		},
		{
			name:        "TOJSON(secrets) uppercase",
			envValue:    "${{ TOJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect TOJSON(secrets) (case-insensitive)",
		},
		{
			name:        "ToJson(secrets) mixed case",
			envValue:    "${{ ToJson(secrets) }}",
			wantErrors:  1,
			description: "Should detect ToJson(secrets) (case-insensitive)",
		},
		{
			name:        "toJSON(github.event)",
			envValue:    "${{ toJSON(github.event) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with other variables",
		},
		{
			name:        "toJSON(matrix)",
			envValue:    "${{ toJSON(matrix) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with matrix",
		},
		{
			name:        "toJSON(needs)",
			envValue:    "${{ toJSON(needs) }}",
			wantErrors:  0,
			description: "Should not detect toJSON with needs",
		},
		{
			name:        "specific secret",
			envValue:    "${{ secrets.MY_SECRET }}",
			wantErrors:  0,
			description: "Should not detect specific secret access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"all_secrets": {
							Name: &ast.String{Value: "ALL_SECRETS"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestSecretExposure_DynamicAccess(t *testing.T) {
	tests := []struct {
		name        string
		envValue    string
		wantErrors  int
		description string
	}{
		{
			name:        "secrets[format(...)]",
			envValue:    "${{ secrets[format('GH_PAT_%s', matrix.env)] }}",
			wantErrors:  1,
			description: "Should detect secrets with format() index",
		},
		{
			name:        "secrets['literal']",
			envValue:    "${{ secrets['MY_SECRET'] }}",
			wantErrors:  1,
			description: "Should detect secrets with string literal index",
		},
		{
			name:        "secrets[variable]",
			envValue:    "${{ secrets[secret_name] }}",
			wantErrors:  1,
			description: "Should detect secrets with variable index",
		},
		{
			name:        "secrets[matrix.env]",
			envValue:    "${{ secrets[matrix.env] }}",
			wantErrors:  1,
			description: "Should detect secrets with object property index",
		},
		{
			name:        "secrets.MY_SECRET (dot notation)",
			envValue:    "${{ secrets.MY_SECRET }}",
			wantErrors:  0,
			description: "Should not detect dot notation access",
		},
		{
			name:        "env[variable]",
			envValue:    "${{ env[var_name] }}",
			wantErrors:  0,
			description: "Should not detect dynamic access on other variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"my_token": {
							Name: &ast.String{Value: "MY_TOKEN"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestSecretExposure_ActionInputs(t *testing.T) {
	tests := []struct {
		name        string
		inputValue  string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in action input",
			inputValue:  "${{ toJSON(secrets) }}",
			wantErrors:  1,
			description: "Should detect toJSON(secrets) in action inputs",
		},
		{
			name:        "secrets[format(...)] in action input",
			inputValue:  "${{ secrets[format('KEY_%s', matrix.env)] }}",
			wantErrors:  1,
			description: "Should detect dynamic secret access in action inputs",
		},
		{
			name:        "specific secret in action input",
			inputValue:  "${{ secrets.GITHUB_TOKEN }}",
			wantErrors:  0,
			description: "Should not detect specific secret in action inputs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "some/action@v1"},
					Inputs: map[string]*ast.Input{
						"token": {
							Name: &ast.String{Value: "token"},
							Value: &ast.String{
								Value: tt.inputValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestSecretExposure_RunScript(t *testing.T) {
	tests := []struct {
		name        string
		runScript   string
		wantErrors  int
		description string
	}{
		{
			name:        "toJSON(secrets) in run script",
			runScript:   `echo "${{ toJSON(secrets) }}"`,
			wantErrors:  1,
			description: "Should detect toJSON(secrets) in run scripts",
		},
		{
			name:        "specific secret in run script",
			runScript:   `echo "${{ secrets.MY_SECRET }}"`,
			wantErrors:  0,
			description: "Should not detect specific secret in run scripts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: tt.runScript,
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			rule.VisitJobPre(job)

			gotErrors := len(rule.Errors())
			if gotErrors != tt.wantErrors {
				t.Errorf("%s: got %d errors, want %d errors. Errors: %v",
					tt.description, gotErrors, tt.wantErrors, rule.Errors())
			}
		})
	}
}

func TestSecretExposure_WorkflowLevelEnv(t *testing.T) {
	rule := NewSecretExposureRule()

	workflow := &ast.Workflow{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"all_secrets": {
					Name: &ast.String{Value: "ALL_SECRETS"},
					Value: &ast.String{
						Value: "${{ toJSON(secrets) }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	rule.VisitWorkflowPre(workflow)

	gotErrors := len(rule.Errors())
	if gotErrors != 1 {
		t.Errorf("Expected 1 error for toJSON(secrets) at workflow level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_JobLevelEnv(t *testing.T) {
	rule := NewSecretExposureRule()

	job := &ast.Job{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"all_secrets": {
					Name: &ast.String{Value: "ALL_SECRETS"},
					Value: &ast.String{
						Value: "${{ toJSON(secrets) }}",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
		Steps: []*ast.Step{},
	}

	rule.VisitJobPre(job)

	gotErrors := len(rule.Errors())
	if gotErrors != 1 {
		t.Errorf("Expected 1 error for toJSON(secrets) at job level, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_MultipleExpressions(t *testing.T) {
	rule := NewSecretExposureRule()

	step := &ast.Step{
		Env: &ast.Env{
			Vars: map[string]*ast.EnvVar{
				"multi": {
					Name: &ast.String{Value: "MULTI"},
					Value: &ast.String{
						Value: "prefix ${{ toJSON(secrets) }} middle ${{ secrets['KEY'] }} suffix",
						Pos:   &ast.Position{Line: 1, Col: 1},
					},
				},
			},
		},
	}

	job := &ast.Job{Steps: []*ast.Step{step}}
	rule.VisitJobPre(job)

	gotErrors := len(rule.Errors())
	if gotErrors != 2 {
		t.Errorf("Expected 2 errors for multiple exposures, got %d. Errors: %v",
			gotErrors, rule.Errors())
	}
}

func TestSecretExposure_ErrorMessages(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		expectedSubstr string
		description    string
	}{
		{
			name:           "toJSON error message",
			envValue:       "${{ toJSON(secrets) }}",
			expectedSubstr: "toJSON(secrets) exposes all repository and organization secrets",
			description:    "Error message should explain toJSON risk",
		},
		{
			name:           "dynamic access error message",
			envValue:       "${{ secrets[format('KEY_%s', env.name)] }}",
			expectedSubstr: "dynamically constructs the secret name",
			description:    "Error message should explain dynamic construction risk",
		},
		{
			name:           "bracket notation error message",
			envValue:       "${{ secrets['MY_KEY'] }}",
			expectedSubstr: "bracket notation",
			description:    "Error message should mention bracket notation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewSecretExposureRule()

			step := &ast.Step{
				Env: &ast.Env{
					Vars: map[string]*ast.EnvVar{
						"test": {
							Name: &ast.String{Value: "TEST"},
							Value: &ast.String{
								Value: tt.envValue,
								Pos:   &ast.Position{Line: 1, Col: 1},
							},
						},
					},
				},
			}

			job := &ast.Job{Steps: []*ast.Step{step}}
			rule.VisitJobPre(job)

			errors := rule.Errors()
			if len(errors) == 0 {
				t.Fatalf("%s: Expected at least one error", tt.description)
			}

			found := false
			for _, err := range errors {
				if strings.Contains(err.Description, tt.expectedSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: Expected error message to contain %q, got %v",
					tt.description, tt.expectedSubstr, errors)
			}
		})
	}
}
