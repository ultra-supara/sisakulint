package core

import (
	"reflect"
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestDeprecatedCommandsRule(t *testing.T) {
	tests := []struct {
		name string
		want *RuleDeprecatedCommands
	}{
		{
			name: "Test case 1",
			want: &RuleDeprecatedCommands{
				BaseRule: BaseRule{
					RuleName: "deprecated-commands",
					RuleDesc: "Checks for deprecated \"set-output\", \"save-state\", \"set-env\", and \"add-path\" commands at \"run:\"",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeprecatedCommandsRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DeprecatedCommandsRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleDeprecatedCommands_VisitStep(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		step *ast.Step
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Test case 1",
			fields: fields{
				BaseRule: BaseRule{
					RuleName: "deprecated-commands",
					RuleDesc: "Checks for deprecated \"set-output\", \"save-state\", \"set-env\", and \"add-path\" commands at \"run:\"",
				},
			},
			args: args{
				step: &ast.Step{
					Pos: &ast.Position{Line: 1, Col: 1},
					Exec: &ast.ExecRun{
						Run: &ast.String{
							Pos: &ast.Position{Line: 1, Col: 1},
							Value: "::set-output name=test::value",
						},
					},
				},
			},
			wantErr: false, // Note: This rule doesn't return an error, it just adds errors to the rule's error list
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &RuleDeprecatedCommands{
				BaseRule: tt.fields.BaseRule,
			}
			// First, make sure the rule has no errors initially
			initialErrorCount := len(rule.Errors())
			
			// Run the VisitStep method
			err := rule.VisitStep(tt.args.step)
			
			// Verify the error return value matches expectation 
			if (err != nil) != tt.wantErr {
				t.Errorf("RuleDeprecatedCommands.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
			
			// Also verify that an error was added to the rule's error list
			if len(rule.Errors()) <= initialErrorCount {
				t.Errorf("RuleDeprecatedCommands.VisitStep() failed to add error to rule's error list for deprecated command")
			}
		})
	}
}
