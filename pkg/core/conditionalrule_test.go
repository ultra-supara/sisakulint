package core

import (
	"reflect"
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestNewConditionalRule(t *testing.T) {
	tests := []struct {
		name string
		want *ConditionalRule
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewConditionalRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConditionalRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConditionalRule_VisitStep(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Step
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitStep(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_VisitJobPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Job
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_VisitJobPost(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Job
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPost(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitJobPost() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_checkcond(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.String
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			rule.checkcond(tt.args.n)
		})
	}
}
