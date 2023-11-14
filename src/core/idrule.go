//TODO: rule!

package core

import (
	"regexp"
	"strings"

	"github.com/ultra-supara/sisakulint/src/ast"
)

var jobIDPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

// RuleID is a rule to check step IDs in workflow.
type RuleID struct {
	BaseRule
	seen map[string]*ast.Position
}

// IDRule creates a new RuleID instance.
func IDRule() *RuleID {
	return &RuleID{
		BaseRule: BaseRule{
			RuleName: "id",
			RuleDesc: "Checks for duplication and naming convention of job/step IDs",
		},
	}
}

// VisitJobPre is callback when visiting Job node before visiting its children.
func (rule *RuleID) VisitJobPre(n *ast.Job) error {
	rule.seen = map[string]*ast.Position{}

	rule.validateConvention(n.ID, "job")
	for _, j := range n.Needs {
		rule.validateConvention(j, "job")
	}

	return nil
}

// VisitJobPost is callback when visiting Job node after visiting its children.
func (rule *RuleID) VisitJobPost(n *ast.Job) error {
	rule.seen = nil
	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *RuleID) VisitStep(n *ast.Step) error {
	if n.ID == nil {
		return nil
	}

	rule.validateConvention(n.ID, "step")

	id := strings.ToLower(n.ID.Value)
	if prev, ok := rule.seen[id]; ok {
		rule.Errorf(
    		n.ID.Pos,
    		"Step ID %q is a duplicate. It was previously defined at %s. Step IDs must be unique within a job. Please note that step IDs are case-insensitive, so ensure that the step ID is distinct from the previous occurrence.",
    		n.ID.Value,
    		prev.String(),
		)

		return nil
	}
	rule.seen[id] = n.ID.Pos
	return nil
}

func (rule *RuleID) validateConvention(id *ast.String, what string) {
	if id == nil || id.Value == "" || id.ContainsExpression() || jobIDPattern.MatchString(id.Value) {
		return
	}
	rule.Errorf(
    	id.Pos,
    	"Invalid %s ID %q. %s IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'.",
    	what,
    	id.Value,
    	what,
	)
}
