package core

import (
	"github.com/ultra-supara/sisakulint/src/ast"
)

type TimeoutMinutesRule struct {
	BaseRule
}

func TimeoutMinuteRule() *TimeoutMinutesRule {
	return &TimeoutMinutesRule{
		BaseRule: BaseRule{
			RuleName: "missing-timeout-minutes",
			RuleDesc: "This rule checks missing timeout-minutes in job level.",
		},
	}
}

func (rule *TimeoutMinutesRule) VisitJobPre(node *ast.Job) error {
	if node.TimeoutMinutes == nil {
		rule.Errorf(node.Pos,
			"timeout-minutes is not set for job %s; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details.",
			node.ID.Value)
	}
	return nil
}
