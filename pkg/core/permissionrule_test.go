package core

import (
	"reflect"
	"testing"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

func TestPermissionsRule(t *testing.T) {
	tests := []struct {
		name string
		want *PermissionRule
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PermissionsRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PermissionsRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionRule_VisitJobPre(t *testing.T) {
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
		//todo:
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("PermissionRule.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionRule_VisitWorkflowPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Workflow
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		//todo:
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitWorkflowPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("PermissionRule.VisitWorkflowPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionRule_checkPermissions(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		p *ast.Permissions
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
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			rule.checkPermissions(tt.args.p)
		})
	}
}
