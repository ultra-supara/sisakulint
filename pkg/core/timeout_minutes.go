package core

import (
	"github.com/ultra-supara/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
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
		rule.AddAutoFixer(NewJobFixer(node, rule))
	}
	return nil
}

func (rule *TimeoutMinutesRule) VisitStep(node *ast.Step) error {
	if node.TimeoutMinutes == nil {
		rule.Errorf(node.Pos,
			"timeout-minutes is not set for step %s; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsnameidtimeout-minutes for more details.",
			node.String())
		rule.AddAutoFixer(NewStepFixer(node, rule))
	}
	return nil
}

func (rule *TimeoutMinutesRule) FixStep(node *ast.Step) error {
	// best effort to add timeout-minutes before run or uses
	for i := 0; i < len(node.BaseNode.Content); i += 2 {
		if node.BaseNode.Content[i].Value == "run" || node.BaseNode.Content[i].Value == "uses" {
			node.BaseNode.Content = append(node.BaseNode.Content[:i], append([]*yaml.Node{
				{
					Kind:  yaml.ScalarNode,
					Value: "timeout-minutes",
				},
				{
					Kind:  yaml.ScalarNode,
					Value: "5",
				},
			}, node.BaseNode.Content[i:]...)...)
			break
		}
	}
	return nil
}

func (rule *TimeoutMinutesRule) FixJob(node *ast.Job) error {
	// best effort to add timeout-minutes before steps or runs-on
	for i := 0; i < len(node.BaseNode.Content); i += 2 {
		if node.BaseNode.Content[i].Value == "steps" || node.BaseNode.Content[i].Value == "runs-on" {
			node.BaseNode.Content = append(node.BaseNode.Content[:i], append([]*yaml.Node{
				{
					Kind:  yaml.ScalarNode,
					Value: "timeout-minutes",
				},
				{
					Kind:  yaml.ScalarNode,
					Value: "5",
				},
			}, node.BaseNode.Content[i:]...)...)
			break
		}
	}
	return nil
}
