package core

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/ultra-supara/sisakulint/src/ast"
)

type CredentialRule struct {
	BaseRule
	regoQuery rego.PreparedEvalQuery
}

//go:embed credential.rego
var credentialRego string

func CredentialsRule() *CredentialRule {
	query := mustPrepareRegoQuery("data.core.check_credentials", "credential.rego", credentialRego)

	return &CredentialRule{
		BaseRule: BaseRule{
			RuleName: "credentials",
			RuleDesc: "This rule checks for credentials in the source code",
		},
		regoQuery: query,
	}
}

func (rule *CredentialRule) VisitJobPre(node *ast.Job) error {
	if node.Container != nil {
		rule.checkCredentialsWithRego("\"Container\" section", node.Container)
	}
	for _, s := range node.Services {
		err := rule.checkCredentialsWithRego(fmt.Sprintf("\"Service\" section for service %s", s.Name.Value), s.Container)
		if err != nil {
			return err
		}
	}
	return nil
}

func (rule *CredentialRule) checkCredentialsWithRego(where string, node *ast.Container) error {
	containerData := map[string]interface{}{
		"credentials": map[string]interface{}{
			"username": node.Credentials.Username.Value,
			"password": node.Credentials.Password.Value,
		},
	}

	input := map[string]interface{}{
		"jobs": map[string]interface{}{
			"test": map[string]interface{}{
				"container": containerData,
			},
		},
	}

	results, err := rule.regoQuery.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		rule.Errorf(nil, "Failed to evaluate policy: %v", err)
		return err
	}

	reportRegoError(rule, node.Credentials.Password.Pos, where, results)
	return nil
}
