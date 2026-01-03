package core

import (
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// TestArtifactPoisoningRule tests the ArtifactPoisoningRule constructor function.
func TestArtifactPoisoningRule(t *testing.T) {
	rule := ArtifactPoisoningRule()

	if rule.RuleName != "artifact-poisoning-critical" {
		t.Errorf("Expected RuleName to be 'artifact-poisoning-critical', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects unsafe artifact downloads that may allow artifact poisoning attacks. Artifacts should be extracted to a temporary folder to prevent overwriting existing files and should be treated as untrusted content."
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

func TestArtifactPoisoning_VisitStep(t *testing.T) {
	tests := []struct {
		name       string
		step       *ast.Step
		wantErrors int
	}{
		{
			name: "download-artifact without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with nil inputs - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: nil,
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with empty path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: ""},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with safe path - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ runner.temp }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact v3 without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v3"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "non-download-artifact action - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/checkout@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "upload-artifact action - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "upload"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/upload-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "run step - no error",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecRun{
					Run: &ast.String{Value: "echo test"},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 0,
		},
		{
			name: "download-artifact with commit SHA without path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@6b208ae046db98c579e8a3aa621ab581ff575935"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
		{
			name: "download-artifact with name input but no path - should error",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"name": {
							Name:  &ast.String{Value: "name"},
							Value: &ast.String{Value: "my-artifact"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("VisitStep() got %d errors, want %d errors", len(errors), tt.wantErrors)
				for i, e := range errors {
					t.Logf("Error %d: %s", i, e.Description)
				}
			}
		})
	}
}

func TestArtifactPoisoning_FixStep(t *testing.T) {
	tests := []struct {
		name       string
		step       *ast.Step
		wantPath   string
		wantError  bool
	}{
		{
			name: "fix step without inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: nil,
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with empty inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
		{
			name: "fix step with existing inputs",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"name": {
							Name:  &ast.String{Value: "name"},
							Value: &ast.String{Value: "my-artifact"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantPath:  "${{ runner.temp }}/artifacts",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()
			err := rule.FixStep(tt.step)

			if (err != nil) != tt.wantError {
				t.Errorf("FixStep() error = %v, wantError %v", err, tt.wantError)
				return
			}

			action := tt.step.Exec.(*ast.ExecAction)
			if action.Inputs == nil {
				t.Fatal("FixStep() did not initialize Inputs map")
			}

			pathInput, ok := action.Inputs["path"]
			if !ok {
				t.Fatal("FixStep() did not add path input")
			}

			if pathInput.Value.Value != tt.wantPath {
				t.Errorf("FixStep() path = %v, want %v", pathInput.Value.Value, tt.wantPath)
			}

			if pathInput.Name.Value != "path" {
				t.Errorf("FixStep() path name = %v, want 'path'", pathInput.Name.Value)
			}
		})
	}
}

func TestArtifactPoisoning_Integration(t *testing.T) {
	tests := []struct {
		name           string
		step           *ast.Step
		wantErrors     int
		wantAutoFixers int
	}{
		{
			name: "unsafe download creates error and autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses:   &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     1,
			wantAutoFixers: 1,
		},
		{
			name: "safe download creates no error or autofixer",
			step: &ast.Step{
				ID: &ast.String{Value: "download"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{Value: "actions/download-artifact@v4"},
					Inputs: map[string]*ast.Input{
						"path": {
							Name:  &ast.String{Value: "path"},
							Value: &ast.String{Value: "${{ runner.temp }}/artifacts"},
						},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantErrors:     0,
			wantAutoFixers: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ArtifactPoisoningRule()
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() unexpected error: %v", err)
			}

			errors := rule.Errors()
			if len(errors) != tt.wantErrors {
				t.Errorf("VisitStep() got %d errors, want %d errors", len(errors), tt.wantErrors)
			}

			autoFixers := rule.AutoFixers()
			if len(autoFixers) != tt.wantAutoFixers {
				t.Errorf("VisitStep() got %d autofixers, want %d autofixers", len(autoFixers), tt.wantAutoFixers)
			}

			// If we have autofixers, apply them and verify
			if len(autoFixers) > 0 {
				for _, fixer := range autoFixers {
					if err := fixer.Fix(); err != nil {
						t.Errorf("AutoFixer.Fix() error = %v", err)
					}
				}

				// Verify the fix was applied
				action := tt.step.Exec.(*ast.ExecAction)
				if action.Inputs["path"] == nil {
					t.Error("AutoFixer did not add path input")
				} else if action.Inputs["path"].Value.Value != "${{ runner.temp }}/artifacts" {
					t.Errorf("AutoFixer path = %v, want '${{ runner.temp }}/artifacts'", action.Inputs["path"].Value.Value)
				}
			}
		})
	}
}
