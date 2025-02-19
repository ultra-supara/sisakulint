package core

import (
	"fmt"
	"regexp"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

type CredentialRule struct {
	BaseRule
}

var isExpr = regexp.MustCompile(`^\$\{.+\}$`)

func CredentialsRule() *CredentialRule {
	return &CredentialRule{
		BaseRule: BaseRule{
			RuleName: "credentials",
			RuleDesc: "This rule checks for credentials in the source code",
		},
	}
}

func (rule *CredentialRule) VisitJobPre(node *ast.Job) error {
	if node.Container != nil {
		rule.checkCredentials("\"Container\" section", node.Container)
	}
	for _, s := range node.Services {
		rule.checkCredentials(fmt.Sprintf("\"Service\" section for service %s", s.Name.Value), s.Container)
	}
	return nil
}

func (rule *CredentialRule) checkCredentials(where string, node *ast.Container) {
	if node.Credentials.Password != nil && !isExpr.MatchString(node.Credentials.Password.Value) {
		rule.Errorf(node.Credentials.Password.Pos, "Password found in %s, do not paste password direct hardcode", where)
		rule.AddAutoFixer(NewFuncFixer(rule.RuleName, func() error {
			return rule.FixCredentials(node.Credentials)
		}))
	}
}

func (rule *CredentialRule) FixCredentials(node *ast.Credentials) error {
	// remove password from container
	for i := 0; i < len(node.BaseNode.Content); i += 2 {
		if node.BaseNode.Content[i].Value == "password" {
			node.BaseNode.Content = append(node.BaseNode.Content[:i], node.BaseNode.Content[i+2:]...)
			break
		}
	}
	return nil
}
