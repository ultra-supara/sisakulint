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
					Exec: &ast.ExecRun{
						Run: &ast.String{
							Value: "::set-output name=test::value",
						},
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &RuleDeprecatedCommands{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitStep(tt.args.step); (err != nil) != tt.wantErr {
				t.Errorf("RuleDeprecatedCommands.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
