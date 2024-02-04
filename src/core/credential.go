package core

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/open-policy-agent/opa/rego"
	"github.com/ultra-supara/sisakulint/src/ast"
)

type CredentialRule struct {
	BaseRule
	regoQuery rego.PreparedEvalQuery
}

//go:embed credential.rego
var credentialRego string

func prepareRegoQuery(queryString string) (rego.PreparedEvalQuery, error) {
	r := rego.New(
		rego.Query(queryString),
		rego.Module("credential.rego", string(credentialRego)),
	)

	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("failed to prepare Rego query: %v", err)
	}

	return query, nil
}

func CredentialsRule() *CredentialRule {
	query, err := prepareRegoQuery("data.core.check_credentials")
	if err != nil {
		log.Fatalf("Error preparing Rego query: %v", err)
	}

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

	for _, result := range results {
		for _, violation := range result.Expressions[0].Value.([]interface{}) {
			v := violation.(map[string]interface{})
			message := v["message"].(string)
			rule.Errorf(
				node.Credentials.Password.Pos,
				"%s: %s",
				where,
				message,
			)
		}
	}
	return nil
}
