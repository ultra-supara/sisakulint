package core

import (
	"context"
	"log"

	"github.com/open-policy-agent/opa/rego"
	"github.com/ultra-supara/sisakulint/src/ast"
)

func mustPrepareRegoQuery(queryString, fileName, module string) rego.PreparedEvalQuery {
	r := rego.New(
		rego.Query(queryString),
		rego.Module(fileName, string(credentialRego)),
	)

	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("failed to prepare Rego query: %v", err)
	}

	return query
}

type ErrorReporter interface {
	Errorf(*ast.Position, string, ...interface{})
}

func reportRegoError(rule ErrorReporter, pos *ast.Position, where string, results rego.ResultSet) {
	for _, result := range results {
		for _, violation := range result.Expressions[0].Value.([]interface{}) {
			v := violation.(map[string]interface{})
			message := v["message"].(string)
			rule.Errorf(
				pos,
				"%s: %s",
				where,
				message,
			)
		}
	}
}
