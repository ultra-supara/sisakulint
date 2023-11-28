package core

import (
	"github.com/ultra-supara/sisakulint/src/ast"
	"github.com/ultra-supara/sisakulint/src/expressions"
)

var allPermissionScopes = map[string]struct{}{
	"actions":             {},
	"checks":              {},
	"contents":            {},
	"deployments":         {},
	"id-token":            {},
	"issues":              {},
	"discussions":         {},
	"packages":            {},
	"pages":               {},
	"pull-requests":       {},
	"repository-projects": {},
	"security-events":     {},
	"statuses":            {},
}

// RulePermissions is a rule checker to check permission configurations in a workflow.
//* https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
type PermissionRule struct {
	BaseRule
}

// PermissionsRuleは新しいPermissionRuleのインスタンスを作成します。
func PermissionsRule() *PermissionRule {
	return &PermissionRule{
		BaseRule: BaseRule{
			RuleName: "permissions",
			RuleDesc: "Checks for permissions configuration in \"permissions:\". Permission names and permission scopes are checked",
		},
	}
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *PermissionRule) VisitJobPre(n *ast.Job) error {
	rule.checkPermissions(n.Permissions)
	return nil
}

// VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
func (rule *PermissionRule) VisitWorkflowPre(n *ast.Workflow) error {
	rule.checkPermissions(n.Permissions)
	return nil
}

func (rule *PermissionRule) checkPermissions(p *ast.Permissions) {
	if p == nil {
		return
	}

	if p.All != nil {
		switch p.All.Value {
		case "write-all", "read-all":
			rule.Errorf(p.All.Pos, "write-all is widedly scoped for all the scopes. use \"write\" or \"read\" for each scope", p.All.Value)
		default:
			rule.Errorf(p.All.Pos, "%q is invalid for permission for all the scopes. available values are \"read-all\" and \"write-all\"", p.All.Value)
		}
		return
	}

	for _, p := range p.Scopes {
		n := p.Name.Value // Permission names are case-sensitive
		if _, ok := allPermissionScopes[n]; !ok {
			ss := make([]string, 0, len(allPermissionScopes))
			for s := range allPermissionScopes {
				ss = append(ss, s)
			}
			rule.Errorf(p.Name.Pos, "unknown permission scope %q. all available permission scopes are %s", n, expressions.SortedQuotes(ss))
		}
		switch p.Value.Value {
		case "read", "write", "none":
			// OK
		default:
			rule.Errorf(p.Value.Pos, "%q is invalid for permission of scope %q. available values are \"read\", \"write\" or \"none\"", p.Value.Value, n)
		}
	}
}
