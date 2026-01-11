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
	if rule.checkcond(n.If) {
		rule.AddAutoFixer(NewStepFixer(n, rule))
	}
	return nil
}

// VisitJobPre is called before visiting a job children
func (rule *ConditionalRule) VisitJobPre(n *ast.Job) error {
	if rule.checkcond(n.If) {
		rule.AddAutoFixer(NewJobFixer(n, rule))
	}
	return nil
}

// VisitJobPost is called after visiting a job children
func (rule *ConditionalRule) VisitJobPost(n *ast.Job) error {
	return nil
}

// checkcond checks if a condition is true/false
// Returns true if there's an issue that needs fixing
func (rule *ConditionalRule) checkcond(n *ast.String) bool {
	if n == nil {
		return false
	}
	if !n.ContainsExpression() {
		return false
	}
	// checknumber of ${{ }} for conditions like ${{ flase }} or ${{ true }} , which are evaluated to true!
	if strings.HasPrefix(n.Value, "${{") && strings.HasSuffix(n.Value, "}}") && strings.Count(n.Value, "${{") == 1 {
		return false
	}
	// rule
	rule.Errorf(
		n.Pos,
		"The condition '%s' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions.",
		n.Value,
	)
	return true
}

// RuleNames returns the rule name for the fixer interface
func (rule *ConditionalRule) RuleNames() string {
	return rule.RuleName
}

// stripExpressionWrappers removes ${{ }} wrappers from a condition string
func stripExpressionWrappers(value string) string {
	// Remove all ${{ }} wrappers, keeping the content
	result := strings.Replace(value, "${{", "", -1)
	result = strings.Replace(result, "}}", "", -1)
	return strings.TrimSpace(result)
}

// FixStep fixes the condition in a step
func (rule *ConditionalRule) FixStep(step *ast.Step) error {
	if step.If != nil && step.If.ContainsExpression() {
		step.If.BaseNode.Value = stripExpressionWrappers(step.If.Value)
	}
	return nil
}

// FixJob fixes the condition in a job
func (rule *ConditionalRule) FixJob(job *ast.Job) error {
	if job.If != nil && job.If.ContainsExpression() {
		job.If.BaseNode.Value = stripExpressionWrappers(job.If.Value)
	}
	return nil
}
