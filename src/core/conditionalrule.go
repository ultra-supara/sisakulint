package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/src/ast"
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

//VisitJobPre is called before visiting a job children
func (rule *ConditionalRule) VisitJobPre(n *ast.Job) error {
	rule.checkcond(n.If)
	return nil
}

//VisitJobPost is called after visiting a job children
func (rule *ConditionalRule) VisitJobPost(n *ast.Job) error {
	return nil
}

//checkcond checks if a condition is true/false
func (rule *ConditionalRule) checkcond(n *ast.String) {
	if n == nil {
		return
	}
	if !n.ContainsExpression() {
	return
	}
	// checknumber of ${{ }} for conditions like ${{ flase }} or ${{ true }} , which are evaluated to true!
	if strings.HasPrefix(n.Value, "${{") && strings.HasSuffix(n.Value, "}}") && strings.Count(n.Value, "${{") == 1 {
		return
	}
	// rule
	rule.Errorf(
    	n.Pos,
    	"The condition '%s' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions.",
    	n.Value,
    )
}
