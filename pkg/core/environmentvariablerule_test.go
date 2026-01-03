package core

import (
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestEnvironmentVariableRule(t *testing.T) {
	tests := []struct {
		name string
		want *EnvironmentVariableChecker
	}{
		{
			name: "Test case 1",
			want: &EnvironmentVariableChecker{
				BaseRule: BaseRule{
					RuleName: "env-var",
					RuleDesc: "Checks for environment variables configuration at \"env:\"",
				},
			},
		},
		// Add more test cases here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EnvironmentVariableRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EnvironmentVariableRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEnvironmentVariableChecker_VisitStep(t *testing.T) {
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
				BaseRule: BaseRule{},
			},
			args: args{
				step: &ast.Step{},
			},
			wantErr: false,
		},
		// Add more test cases here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &EnvironmentVariableChecker{
				BaseRule: tt.fields.BaseRule,
			}
			if err := checker.VisitStep(tt.args.step); (err != nil) != tt.wantErr {
				t.Errorf("EnvironmentVariableChecker.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnvironmentVariableChecker_VisitJobPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		job *ast.Job
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
				BaseRule: BaseRule{},
			},
			args: args{
				job: &ast.Job{},
			},
			wantErr: false,
		},
		// Add more test cases here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &EnvironmentVariableChecker{
				BaseRule: tt.fields.BaseRule,
			}
			if err := checker.VisitJobPre(tt.args.job); (err != nil) != tt.wantErr {
				t.Errorf("EnvironmentVariableChecker.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnvironmentVariableChecker_VisitWorkflowPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		workflow *ast.Workflow
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
				BaseRule: BaseRule{},
			},
			args: args{
				workflow: &ast.Workflow{},
			},
			wantErr: false,
		},
		// Add more test cases here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &EnvironmentVariableChecker{
				BaseRule: tt.fields.BaseRule,
			}
			if err := checker.VisitWorkflowPre(tt.args.workflow); (err != nil) != tt.wantErr {
				t.Errorf("EnvironmentVariableChecker.VisitWorkflowPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnvironmentVariableChecker_validateEnvironmentVariables(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		env *ast.Env
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test case 1",
			fields: fields{
				BaseRule: BaseRule{},
			},
			args: args{
				env: &ast.Env{},
			},
		},
		// Add more test cases here
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &EnvironmentVariableChecker{
				BaseRule: tt.fields.BaseRule,
			}
			checker.validateEnvironmentVariables(tt.args.env)
		})
	}
}
