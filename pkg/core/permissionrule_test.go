package core

import (
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
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

func TestPermissionRule_ValidScopes(t *testing.T) {
	// Test that all valid permission scopes are recognized
	validScopes := []string{
		"actions",
		"attestations",
		"checks",
		"contents",
		"deployments",
		"discussions",
		"id-token",
		"issues",
		"models",
		"packages",
		"pages",
		"pull-requests",
		"repository-projects",
		"security-events",
		"statuses",
	}

	for _, scope := range validScopes {
		t.Run(scope, func(t *testing.T) {
			rule := PermissionsRule()
			permissions := &ast.Permissions{
				Scopes: map[string]*ast.PermissionScope{
					scope: {
						Name:  &ast.String{Value: scope, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: "read", Pos: &ast.Position{Line: 1, Col: 10}},
					},
				},
			}
			rule.checkPermissions(permissions)
			if len(rule.Errors()) > 0 {
				t.Errorf("scope %q should be valid, but got error: %v", scope, rule.Errors()[0])
			}
		})
	}
}

func TestPermissionRule_InvalidScope(t *testing.T) {
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		Scopes: map[string]*ast.PermissionScope{
			"invalid-scope": {
				Name:  &ast.String{Value: "invalid-scope", Pos: &ast.Position{Line: 1, Col: 1}},
				Value: &ast.String{Value: "read", Pos: &ast.Position{Line: 1, Col: 20}},
			},
		},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("expected error for invalid scope, but got none")
	}
}

func TestPermissionRule_ReadAllPermission(t *testing.T) {
	// Test that read-all is accepted as valid
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "read-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) > 0 {
		t.Errorf("read-all should be valid, but got error: %v", rule.Errors()[0])
	}
}

func TestPermissionRule_WriteAllPermission(t *testing.T) {
	// Test that write-all generates a warning
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "write-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("write-all should generate a warning, but got none")
	}
}

func TestPermissionRule_InvalidAllPermission(t *testing.T) {
	// Test that invalid all-scope permission generates an error
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "invalid-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("invalid-all should generate an error, but got none")
	}
}
