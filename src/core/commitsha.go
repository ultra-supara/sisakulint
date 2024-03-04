package core

import (
	"regexp"

	"github.com/ultra-supara/sisakulint/src/ast"
)

type CommitSha struct {
	BaseRule
}

func CommitShaRule() *CommitSha {
	return &CommitSha{
		BaseRule: BaseRule{
			RuleName: "commit-sha",
			RuleDesc: "Warn if the action ref is not a full length commit SHA and not an official GitHub Action.",
		},
	}
}

// Check if the given ref is a full length commit SHA
func isFullLengthSha(ref string) bool {
	re := regexp.MustCompile(`^.+@([0-9a-f]{40})$`)
	return re.MatchString(ref)
}

// Check if the action is an official GitHub Action
func isOfficialAction(ref string) bool {
	re := regexp.MustCompile(`^actions\/.+`)
	return re.MatchString(ref)
}

// VisitJobPre checks each step in each job for the action ref specifications
func (rule *CommitSha) VisitJobPre(node *ast.Job) error {
	for _, step := range node.Steps {
		if step.Uses != nil {
			usesValue := step.Uses.Value
			if !isFullLengthSha(usesValue) && !isOfficialAction(usesValue) {
				rule.Errorf(step.Pos,
					"the action ref in 'uses' for step '%s' should be a full length commit SHA for immutability and security, unless it's an official GitHub Action. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
					step.ID.Value)
			}
		}
	}
	return nil
}
