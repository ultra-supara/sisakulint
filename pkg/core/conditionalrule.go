package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

type ConditionalRule struct {
	BaseRule
}

// ConditionalRule は 新しいConditionalRuleを作ります
func NewConditionalRule() *ConditionalRule {
	return &ConditionalRule{
		BaseRule: BaseRule{
			RuleName: "cond",
			RuleDesc: "chaecks if a condition is true/false",
		},
	}
}

// VisitStep is callback when visiting Step node.
func (rule *ConditionalRule) VisitStep(n *ast.Step) error {
	rule.checkcond(n.If)
	return nil
}

// VisitJobPre is called before visiting a job children
func (rule *ConditionalRule) VisitJobPre(n *ast.Job) error {
	rule.checkcond(n.If)
	return nil
}

// VisitJobPost is called after visiting a job children
func (rule *ConditionalRule) VisitJobPost(n *ast.Job) error {
	return nil
}

// checkcond checks if a condition is true/false
func (rule *ConditionalRule) checkcond(n *ast.String) {
	if n == nil {
		return
	}
	if !n.ContainsExpression() {
		return
	}

	// Skip if condition contains multiple ${{ }} blocks (e.g., "${{ a }} == ${{ b }}")
	// These are valid comparison expressions that can evaluate to true or false
	if strings.Count(n.Value, "${{") > 1 {
		return
	}

	// Skip if condition is a single ${{ }} block covering the entire condition
	// This is a valid expression (e.g., "${{ github.event_name == 'push' }}")
	if strings.HasPrefix(n.Value, "${{") && strings.HasSuffix(n.Value, "}}") && strings.Count(n.Value, "${{") == 1 {
		return
	}

	// Skip if there are operators outside ${{ }} blocks (e.g., "${{ steps.foo.outputs.result }} == 'success'")
	// Remove all ${{ ... }} blocks and check if remaining text contains meaningful operators
	remaining := removeExpressionBlocks(n.Value)
	if containsOperator(remaining) {
		return
	}

	// Report error for invalid conditions that will always evaluate to true
	rule.Errorf(
		n.Pos,
		"The condition '%s' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions.",
		n.Value,
	)
}

// removeExpressionBlocks removes all ${{ ... }} blocks from the string
func removeExpressionBlocks(s string) string {
	result := s
	for {
		start := strings.Index(result, "${{")
		if start == -1 {
			break
		}
		end := strings.Index(result[start:], "}}")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+2:]
	}
	return result
}

// containsOperator checks if the string contains meaningful operators
func containsOperator(s string) bool {
	operators := []string{"==", "!=", ">=", "<=", ">", "<", "&&", "||", "!"}
	for _, op := range operators {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}
