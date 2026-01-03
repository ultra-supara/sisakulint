package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

type IssueInjection struct {
	BaseRule
}

func IssueInjectionRule() *IssueInjection {
	return &IssueInjection{
		BaseRule: BaseRule{
			RuleName: "issue-injection",
			RuleDesc: "Checks for potentially dangerous direct use of untrusted input in run scripts. Using intermediate environment variables is recommended for security.",
		},
	}
}

// parsedExpression represents a parsed expression with its position and AST node
type parsedExpression struct {
	raw  string             // Original expression content (e.g., "github.event.pull_request.title")
	node expressions.ExprNode // Parsed AST node
	pos  *ast.Position      // Position in source
}

func (rule *IssueInjection) VisitJobPre(node *ast.Job) error {
	for _, s := range node.Steps {
		if s.Exec == nil || s.Exec.Kind() != ast.ExecKindRun {
			continue
		}

		run := s.Exec.(*ast.ExecRun)

		// 1. Extract and parse all expressions from run
		exprs := rule.extractAndParseExpressions(run.Run)

		// 2. Check each expression for untrusted input
		for _, expr := range exprs {
			untrustedPaths := rule.checkUntrustedInput(expr)
			if len(untrustedPaths) > 0 {
				// 3. Check if the expression is safely used via env variable
				if !rule.isDefinedInEnv(expr, s.Env) {
					// 4. Report only dangerous patterns
					rule.Errorf(
						expr.pos,
						"\"%s\" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
					)
				}
			}
		}
	}
	return nil
}

// extractAndParseExpressions extracts all expressions from run script and parses them
func (rule *IssueInjection) extractAndParseExpressions(runStr *ast.String) []parsedExpression {
	if runStr == nil {
		return nil
	}

	value := runStr.Value
	var result []parsedExpression
	offset := 0

	for {
		// Find next expression start in the entire string (supports multiline)
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		// Find closing }} in the entire string (supports multiline)
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		// Extract expression content (between ${{ and }})
		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		// Parse the expression
		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			// Calculate position (count newlines before this expression)
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: runStr.Pos.Line + lineIdx,
				Col:  runStr.Pos.Col + col,
			}
			if runStr.Literal {
				pos.Line += 1
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
func (rule *IssueInjection) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	// The tokenizer expects the expression to end with }}
	// so we append it if not present
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input using ExprSemanticsChecker
func (rule *IssueInjection) checkUntrustedInput(expr parsedExpression) []string {
	// Use ExprSemanticsChecker with untrusted input checking enabled
	checker := expressions.NewExprSemanticsChecker(true, nil)

	// Check the expression
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		// Extract untrusted path from error message
		// Error message format: "\"<path>\" is potentially untrusted..."
		msg := err.Message
		// Check if this is an untrusted input error
		if strings.Contains(msg, "potentially untrusted") {
			if idx := strings.Index(msg, "\""); idx != -1 {
				endIdx := strings.Index(msg[idx+1:], "\"")
				if endIdx != -1 {
					path := msg[idx+1 : idx+1+endIdx]
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// isDefinedInEnv checks if the expression is defined in the step's env section
func (rule *IssueInjection) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
	if env == nil {
		return false
	}

	normalizedExpr := normalizeExpression(expr.raw)

	// Check env.Vars (env: { VAR: value } format)
	if env.Vars != nil {
		for _, envVar := range env.Vars {
			if envVar.Value != nil && envVar.Value.ContainsExpression() {
				// Extract and normalize expressions from env variable value
				envExprs := extractExpressionsFromString(envVar.Value.Value)
				for _, envExpr := range envExprs {
					if normalizeExpression(envExpr) == normalizedExpr {
						return true
					}
				}
			}
		}
	}

	// Check env.Expression (env: ${{ ... }} format)
	if env.Expression != nil && env.Expression.ContainsExpression() {
		envExprs := extractExpressionsFromString(env.Expression.Value)
		for _, envExpr := range envExprs {
			if normalizeExpression(envExpr) == normalizedExpr {
				return true
			}
		}
	}

	return false
}

// extractExpressionsFromString extracts expression contents from a string containing ${{ }}
func extractExpressionsFromString(s string) []string {
	var results []string
	offset := 0

	for {
		idx := strings.Index(s[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx + 3 // Skip "${{"
		endIdx := strings.Index(s[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := strings.TrimSpace(s[start : start+endIdx])
		results = append(results, exprContent)

		offset = start + endIdx + 2
	}

	return results
}

// normalizeExpression normalizes an expression by removing extra whitespace
func normalizeExpression(expr string) string {
	// Remove all whitespace and normalize
	return strings.Join(strings.Fields(strings.TrimSpace(expr)), " ")
}
