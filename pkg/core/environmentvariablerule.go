// TODO: Rule!
package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// BaseRule はルールチェッカーの基本的な属性を持つ構造体です。
type EnvironmentVariableChecker struct {
	BaseRule
}

// NewEnvironmentVariableRule は新しいEnvironmentVariableRuleインスタンスを作成します。
func EnvironmentVariableRule() *EnvironmentVariableChecker {
	return &EnvironmentVariableChecker{
		BaseRule: BaseRule{
			RuleName: "env-var",
			RuleDesc: "Checks for environment variables configuration at \"env:\"",
		},
	}
}

// CheckStep は、Stepノードの環境変数設定をチェックします。
func (checker *EnvironmentVariableChecker) VisitStep(step *ast.Step) error {
	checker.validateEnvironmentVariables(step.Env)
	return nil
}

// CheckJob は、Jobノードの環境変数設定をチェックします。
func (checker *EnvironmentVariableChecker) VisitJobPre(job *ast.Job) error {
	checker.validateEnvironmentVariables(job.Env)
	if job.Container != nil {
		checker.validateEnvironmentVariables(job.Container.Env)
	}
	for _, service := range job.Services {
		checker.validateEnvironmentVariables(service.Container.Env)
	}
	return nil
}

// CheckWorkflow は、Workflowノードの環境変数設定をチェックします。
func (checker *EnvironmentVariableChecker) VisitWorkflowPre(workflow *ast.Workflow) error {
	checker.validateEnvironmentVariables(workflow.Env)
	return nil
}

// validateEnvironmentVariables は与えられた環境変数のリストをチェックします。
func (checker *EnvironmentVariableChecker) validateEnvironmentVariables(env *ast.Env) {
	if env == nil || env.Expression != nil {
		return
	}
	for _, variable := range env.Vars {
		if variable.Name.ContainsExpression() {
			continue // 変数名には式を含むことができます (#312)
		}
		if strings.ContainsAny(variable.Name.Value, "&= ") {
			checker.Errorf(
				variable.Name.Pos,
				"Environment variable name '%q' is not formatted correctly. Please ensure that it does not include characters such as '&', '=', or spaces, as these are not allowed in variable names.",
				variable.Name.Value,
			)
		}
	}
}
