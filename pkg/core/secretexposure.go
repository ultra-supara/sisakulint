package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// SecretExposureRule detects excessive secrets exposure patterns in GitHub Actions workflows.
// This rule identifies two dangerous patterns:
// 1. toJSON(secrets) - exposes all secrets at once
// 2. secrets[dynamic-access] - dynamically accessing secrets via index notation
//
// See: https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/
type SecretExposureRule struct {
	BaseRule
}

// NewSecretExposureRule creates a new SecretExposureRule
func NewSecretExposureRule() *SecretExposureRule {
	return &SecretExposureRule{
		BaseRule: BaseRule{
			RuleName: "secret-exposure",
			RuleDesc: "Detects excessive secret exposure patterns like toJSON(secrets) or secrets[dynamic-access]. See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
		},
	}
}

// VisitJobPre visits each job and checks for excessive secret exposure
func (rule *SecretExposureRule) VisitJobPre(node *ast.Job) error {
	// Check job-level env
	if node.Env != nil {
		rule.checkEnv(node.Env)
	}

	// Check each step
	for _, step := range node.Steps {
		rule.checkStep(step)
	}

	return nil
}

// VisitWorkflowPre checks workflow-level env
func (rule *SecretExposureRule) VisitWorkflowPre(node *ast.Workflow) error {
	if node.Env != nil {
		rule.checkEnv(node.Env)
	}
	return nil
}

// checkStep checks a single step for secret exposure patterns
func (rule *SecretExposureRule) checkStep(step *ast.Step) {
	// Check step-level env
	if step.Env != nil {
		rule.checkEnv(step.Env)
	}

	if step.Exec == nil {
		return
	}

	switch exec := step.Exec.(type) {
	case *ast.ExecRun:
		// Check run: script (although secrets in run scripts are less common)
		if exec.Run != nil {
			rule.checkString(exec.Run)
		}
	case *ast.ExecAction:
		// Check action inputs (with:)
		for _, input := range exec.Inputs {
			if input != nil && input.Value != nil {
				rule.checkString(input.Value)
			}
		}
	}
}

// checkEnv checks environment variables for secret exposure
func (rule *SecretExposureRule) checkEnv(env *ast.Env) {
	if env.Expression != nil {
		rule.checkString(env.Expression)
	}

	for _, envVar := range env.Vars {
		if envVar.Value != nil {
			rule.checkString(envVar.Value)
		}
	}
}

// checkString extracts and checks expressions within a string
func (rule *SecretExposureRule) checkString(str *ast.String) {
	if str == nil {
		return
	}

	exprs := rule.extractAndParseExpressions(str)
	for _, expr := range exprs {
		rule.checkExpressionForSecretExposure(expr)
	}
}

// extractAndParseExpressions extracts all ${{ }} expressions from a string and parses them
func (rule *SecretExposureRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpression
	offset := 0

	for {
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}
			if str.Literal {
				pos.Line++
			}

			result = append(result, parsedExpression{
				raw:  exprContent,
				node: expr,
				pos:  pos,
			})
		}

		offset = start + endIdx + 2
	}

	return result
}

// parseExpression parses a single expression string into an AST node
func (rule *SecretExposureRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkExpressionForSecretExposure checks if an expression contains secret exposure patterns
func (rule *SecretExposureRule) checkExpressionForSecretExposure(expr parsedExpression) {
	expressions.VisitExprNode(expr.node, func(node, parent expressions.ExprNode, entering bool) {
		if !entering {
			return
		}

		switch n := node.(type) {
		case *expressions.FuncCallNode:
			// Check for toJSON(secrets)
			rule.checkToJSONSecretsCall(n, expr)

		case *expressions.IndexAccessNode:
			// Check for secrets[...] dynamic access
			rule.checkSecretsDynamicAccess(n, expr)
		}
	})
}

// checkToJSONSecretsCall checks if a function call is toJSON(secrets)
func (rule *SecretExposureRule) checkToJSONSecretsCall(funcCall *expressions.FuncCallNode, expr parsedExpression) {
	// Function names are case-insensitive and normalized to lowercase
	if strings.ToLower(funcCall.Callee) != "tojson" {
		return
	}

	if len(funcCall.Args) != 1 {
		return
	}

	// Check if the argument is the 'secrets' variable
	varNode, ok := funcCall.Args[0].(*expressions.VariableNode)
	if !ok {
		return
	}

	// Variable names are normalized to lowercase
	if varNode.Name != "secrets" {
		return
	}

	rule.Errorf(
		expr.pos,
		"excessive secrets exposure: toJSON(secrets) exposes all repository and organization secrets at once. "+
			"Use specific secret references like secrets.MY_SECRET instead. "+
			"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
	)
}

// checkSecretsDynamicAccess checks if secrets are accessed dynamically via index notation
func (rule *SecretExposureRule) checkSecretsDynamicAccess(indexAccess *expressions.IndexAccessNode, expr parsedExpression) {
	// Check if the operand is the 'secrets' variable
	varNode, ok := indexAccess.Operand.(*expressions.VariableNode)
	if !ok {
		return
	}

	if varNode.Name != "secrets" {
		return
	}

	// Determine the type of dynamic access
	switch indexExpr := indexAccess.Index.(type) {
	case *expressions.StringNode:
		// secrets['literal'] - still problematic as it bypasses static analysis
		// However, this is less severe. Use secrets.literal instead.
		// Note: Due to tokenizer behavior, we extract the string from expr.raw
		secretName := extractSecretNameFromBracket(expr.raw)
		rule.Errorf(
			expr.pos,
			"excessive secrets exposure: secrets['%s'] uses bracket notation for secret access. "+
				"Use dot notation like secrets.%s for better security analysis. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
			secretName, normalizeSecretName(secretName),
		)
	case *expressions.FuncCallNode:
		// secrets[format(...)] - dynamic construction
		rule.Errorf(
			expr.pos,
			"excessive secrets exposure: secrets[%s(...)] dynamically constructs the secret name. "+
				"This pattern exposes more secrets than necessary and makes security auditing difficult. "+
				"Use conditional logic with explicit secret references instead. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
			indexExpr.Callee,
		)
	case *expressions.VariableNode:
		// secrets[variable] - dynamic lookup
		rule.Errorf(
			expr.pos,
			"excessive secrets exposure: secrets[%s] uses a variable to access secrets dynamically. "+
				"This pattern exposes more secrets than necessary. "+
				"Use conditional logic with explicit secret references instead. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
			indexExpr.Name,
		)
	case *expressions.ObjectDerefNode:
		// secrets[matrix.env] or similar - dynamic lookup via object property
		rule.Errorf(
			expr.pos,
			"excessive secrets exposure: secrets[%s] uses dynamic property access to select secrets. "+
				"This pattern exposes more secrets than necessary. "+
				"Use conditional logic with explicit secret references instead. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
			expr.raw[strings.Index(expr.raw, "[")+1:strings.LastIndex(expr.raw, "]")],
		)
	default:
		// Any other dynamic access pattern
		rule.Errorf(
			expr.pos,
			"excessive secrets exposure: secrets[...] uses dynamic access to select secrets. "+
				"This pattern exposes more secrets than necessary. "+
				"Use explicit secret references like secrets.MY_SECRET instead. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/",
		)
	}
}

// normalizeSecretName normalizes a secret name for use in dot notation
// E.g., "MY-SECRET" -> "MY_SECRET" (though GitHub allows hyphens in secret names)
func normalizeSecretName(name string) string {
	// Remove quotes if present
	name = strings.Trim(name, "'\"")
	// Replace hyphens with underscores for suggestion (though original should work)
	return strings.ReplaceAll(name, "-", "_")
}

// extractSecretNameFromBracket extracts the secret name from a secrets['NAME'] expression
// This is needed because the tokenizer has a bug where StringNode.Value contains more than just the string literal
func extractSecretNameFromBracket(exprRaw string) string {
	// Look for secrets['...'] or secrets["..."] pattern
	startSingle := strings.Index(exprRaw, "secrets['")
	startDouble := strings.Index(exprRaw, `secrets["`)

	var start int
	var quote byte
	if startSingle != -1 && (startDouble == -1 || startSingle < startDouble) {
		start = startSingle + len("secrets['")
		quote = '\''
	} else if startDouble != -1 {
		start = startDouble + len(`secrets["`)
		quote = '"'
	} else {
		// Fallback: try to find anything between [ and ]
		bracketStart := strings.Index(exprRaw, "[")
		bracketEnd := strings.Index(exprRaw, "]")
		if bracketStart != -1 && bracketEnd > bracketStart {
			return strings.Trim(exprRaw[bracketStart+1:bracketEnd], "'\"")
		}
		return exprRaw
	}

	// Find the closing quote
	end := strings.IndexByte(exprRaw[start:], quote)
	if end == -1 {
		return exprRaw[start:]
	}
	return exprRaw[start : start+end]
}
