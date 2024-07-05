package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/src/ast"
)

type IssueInjection struct {
	BaseRule
}

func IssueInjectionRule() *IssueInjection {
	return &IssueInjection{
		BaseRule: BaseRule{
			RuleName: "issue-injection",
			RuleDesc: "This rule checks for issue injection in the source code",
		},
	}
}

func (rule *IssueInjection) VisitJobPre(node *ast.Job) error {
	for _, s := range node.Steps {
		if s.Exec == nil || s.Exec.Kind() != ast.ExecKindRun {
			continue
		}
		run := s.Exec.(*ast.ExecRun)
		value := run.Run.Value
		lines := strings.Split(value, "\n")
		reportError := func(i int, msg string) {
			base := *run.Run.Pos // copy
			if run.Run.Literal {
				base.Line += i + 1
			}
			rule.Errorf(&base, msg)
		}
		const WarningMessage = "Direct use of ${{ ... }} in run steps; Use env instead. see also https://docs.github.com/ja/enterprise-cloud@latest/actions/security-guides/security-hardening-for-github-actions#example-of-a-script-injection-attack"
		for i, line := range lines {
			if idx := strings.Index(line, "${{"); idx != -1 {
				idxEnd := strings.Index(line, "}}")
				if idxEnd == -1 {
					j := i + 1
					for ; j < len(lines); j++ {
						if idxEnd = strings.Index(lines[j], "}}"); idxEnd != -1 {
							break
						}
					}
					if j == len(lines) {
						// nothing to do; detected by expression parser
					} else {
						reportError(i, WarningMessage)
					}
				} else {
					reportError(i, WarningMessage)
				}
			}
		}
	}
	return nil
}
