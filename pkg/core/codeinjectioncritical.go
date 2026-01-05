package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

type CodeInjectionCritical struct {
	BaseRule
	stepsWithUntrustedInput []*stepWithUntrustedInputCritical
	workflow                *ast.Workflow
}

// stepWithUntrustedInputCritical tracks steps that need auto-fixing
type stepWithUntrustedInputCritical struct {
	step           *ast.Step
	untrustedExprs []untrustedExprInfoCritical
}

// untrustedExprInfoCritical contains information about an untrusted expression
type untrustedExprInfoCritical struct {
	expr          parsedExpressionCritical
	paths         []string
	isInRunScript bool       // true for run:, false for script: in github-script
	scriptInput   *ast.Input // only set if isInRunScript is false
}

// parsedExpressionCritical represents a parsed expression with its position and AST node
type parsedExpressionCritical struct {
	raw  string                // Original expression content
	node expressions.ExprNode  // Parsed AST node
	pos  *ast.Position         // Position in source
}

func CodeInjectionCriticalRule() *CodeInjectionCritical {
	return &CodeInjectionCritical{
		BaseRule: BaseRule{
			RuleName: "code-injection-critical",
			RuleDesc: "Checks for code injection vulnerabilities when untrusted input is used directly in run scripts or script actions with privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/",
		},
		stepsWithUntrustedInput: make([]*stepWithUntrustedInputCritical, 0),
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *CodeInjectionCritical) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *CodeInjectionCritical) VisitJobPre(node *ast.Job) error {
	// Check if this workflow has privileged triggers
	if !rule.hasPrivilegedTriggers() {
		// Skip detection for non-privileged workflows
		return nil
	}

	for _, s := range node.Steps {
		if s.Exec == nil {
			continue
		}

		var stepUntrusted *stepWithUntrustedInputCritical

		// Check run: scripts
		if s.Exec.Kind() == ast.ExecKindRun {
			run := s.Exec.(*ast.ExecRun)
			exprs := rule.extractAndParseExpressions(run.Run)

			for _, expr := range exprs {
				untrustedPaths := rule.checkUntrustedInput(expr)
				if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
					if stepUntrusted == nil {
						stepUntrusted = &stepWithUntrustedInputCritical{step: s}
					}
					stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, untrustedExprInfoCritical{
						expr:          expr,
						paths:         untrustedPaths,
						isInRunScript: true,
					})

					rule.Errorf(
						expr.pos,
						"code injection (critical): \"%s\" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
						strings.Join(untrustedPaths, "\", \""),
					)
				}
			}
		}

		// Check actions/github-script script: parameter
		if s.Exec.Kind() == ast.ExecKindAction {
			action := s.Exec.(*ast.ExecAction)
			if action.Uses != nil && strings.HasPrefix(action.Uses.Value, "actions/github-script@") {
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					exprs := rule.extractAndParseExpressions(scriptInput.Value)

					for _, expr := range exprs {
						untrustedPaths := rule.checkUntrustedInput(expr)
						if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
							if stepUntrusted == nil {
								stepUntrusted = &stepWithUntrustedInputCritical{step: s}
							}
							stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, untrustedExprInfoCritical{
								expr:          expr,
								paths:         untrustedPaths,
								isInRunScript: false,
								scriptInput:   scriptInput,
							})

							rule.Errorf(
								expr.pos,
								"code injection (critical): \"%s\" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in github-script. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
								strings.Join(untrustedPaths, "\", \""),
							)
						}
					}
				}
			}
		}

		if stepUntrusted != nil {
			rule.stepsWithUntrustedInput = append(rule.stepsWithUntrustedInput, stepUntrusted)
			rule.AddAutoFixer(NewStepFixer(s, rule))
		}
	}
	return nil
}

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *CodeInjectionCritical) hasPrivilegedTriggers() bool {
	if rule.workflow == nil || rule.workflow.On == nil {
		return false
	}

	// Check for privileged triggers
	// These triggers have write access or run with secrets
	privilegedTriggers := map[string]bool{
		"pull_request_target": true,
		"workflow_run":        true,
		"issue_comment":       true,
		"issues":              true,
		"discussion_comment":  true,
	}

	for _, event := range rule.workflow.On {
		eventName := strings.ToLower(event.EventName())
		if privilegedTriggers[eventName] {
			return true
		}
	}

	return false
}

// RuleNames implements StepFixer interface
func (rule *CodeInjectionCritical) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *CodeInjectionCritical) FixStep(step *ast.Step) error {
	// Find the stepWithUntrustedInputCritical for this step
	var stepInfo *stepWithUntrustedInputCritical
	for _, s := range rule.stepsWithUntrustedInput {
		if s.step == step {
			stepInfo = s
			break
		}
	}

	if stepInfo == nil {
		return nil
	}

	// Ensure env exists in AST
	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}

	// Group expressions by their raw content to avoid duplicates
	envVarMap := make(map[string]string) // expr.raw -> env var name
	envVarsForYAML := make(map[string]string) // env var name -> env var value (for BaseNode)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr

		// Generate environment variable name from the untrusted path
		envVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		// Check if we already created an env var for this expression
		if _, exists := envVarMap[expr.raw]; !exists {
			envVarMap[expr.raw] = envVarName

			// Add to env if not already present
			if _, exists := step.Env.Vars[strings.ToLower(envVarName)]; !exists {
				step.Env.Vars[strings.ToLower(envVarName)] = &ast.EnvVar{
					Name: &ast.String{
						Value: envVarName,
						Pos:   expr.pos,
					},
					Value: &ast.String{
						Value: fmt.Sprintf("${{ %s }}", expr.raw),
						Pos:   expr.pos,
					},
				}
				// Also track for BaseNode update
				envVarsForYAML[envVarName] = fmt.Sprintf("${{ %s }}", expr.raw)
			}
		}
	}

	// Update BaseNode with env vars
	if step.BaseNode != nil && len(envVarsForYAML) > 0 {
		if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
			return fmt.Errorf("failed to add env vars to step node: %w", err)
		}
	}

	// Build replacement maps for run: and script:
	runReplacements := make(map[string]string)
	scriptReplacements := make(map[string]string)

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		envVarName := envVarMap[untrustedInfo.expr.raw]

		if untrustedInfo.isInRunScript {
			// For run: scripts, use $ENV_VAR
			runReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)
			runReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("$%s", envVarName)

			// Also update AST
			run := step.Exec.(*ast.ExecRun)
			if run.Run != nil {
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw),
					fmt.Sprintf("$%s", envVarName),
				)
				run.Run.Value = strings.ReplaceAll(
					run.Run.Value,
					fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw),
					fmt.Sprintf("$%s", envVarName),
				)
			}
		} else {
			// For github-script, use process.env.ENV_VAR
			scriptReplacements[fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)
			scriptReplacements[fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw)] = fmt.Sprintf("process.env.%s", envVarName)

			// Also update AST
			if untrustedInfo.scriptInput != nil && untrustedInfo.scriptInput.Value != nil {
				untrustedInfo.scriptInput.Value.Value = strings.ReplaceAll(
					untrustedInfo.scriptInput.Value.Value,
					fmt.Sprintf("${{ %s }}", untrustedInfo.expr.raw),
					fmt.Sprintf("process.env.%s", envVarName),
				)
				untrustedInfo.scriptInput.Value.Value = strings.ReplaceAll(
					untrustedInfo.scriptInput.Value.Value,
					fmt.Sprintf("${{%s}}", untrustedInfo.expr.raw),
					fmt.Sprintf("process.env.%s", envVarName),
				)
			}
		}
	}

	// Update BaseNode with replacements
	if step.BaseNode != nil {
		if len(runReplacements) > 0 {
			if err := ReplaceInRunScript(step.BaseNode, runReplacements); err != nil {
				// Ignore error if run section doesn't exist (might be github-script)
				if !strings.Contains(err.Error(), "run section not found") {
					return fmt.Errorf("failed to replace in run script: %w", err)
				}
			}
		}
		if len(scriptReplacements) > 0 {
			if err := ReplaceInGitHubScript(step.BaseNode, scriptReplacements); err != nil {
				// Ignore error if with/script section doesn't exist (might be run:)
				if !strings.Contains(err.Error(), "section not found") && !strings.Contains(err.Error(), "field not found") {
					return fmt.Errorf("failed to replace in github-script: %w", err)
				}
			}
		}
	}

	return nil
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *CodeInjectionCritical) generateEnvVarName(path string) string {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_INPUT"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == "github" && parts[1] == "event" {
		category := parts[2] // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, etc.

		// Convert to uppercase and join
		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := strings.ToUpper(field)

		// Create readable name
		if categoryUpper == "PULLREQUEST" {
			categoryUpper = "PR"
		}

		return fmt.Sprintf("%s_%s", categoryUpper, fieldUpper)
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	return strings.ToUpper(lastPart)
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *CodeInjectionCritical) extractAndParseExpressions(str *ast.String) []parsedExpressionCritical {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpressionCritical
	offset := 0

	for {
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}
			if str.Literal {
				pos.Line += 1
			}

			result = append(result, parsedExpressionCritical{
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
func (rule *CodeInjectionCritical) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *CodeInjectionCritical) checkUntrustedInput(expr parsedExpressionCritical) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
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
func (rule *CodeInjectionCritical) isDefinedInEnv(expr parsedExpressionCritical, env *ast.Env) bool {
	if env == nil {
		return false
	}

	normalizedExpr := normalizeExpressionCritical(expr.raw)

	if env.Vars != nil {
		for _, envVar := range env.Vars {
			if envVar.Value != nil && envVar.Value.ContainsExpression() {
				envExprs := extractExpressionsFromStringCritical(envVar.Value.Value)
				for _, envExpr := range envExprs {
					if normalizeExpressionCritical(envExpr) == normalizedExpr {
						return true
					}
				}
			}
		}
	}

	if env.Expression != nil && env.Expression.ContainsExpression() {
		envExprs := extractExpressionsFromStringCritical(env.Expression.Value)
		for _, envExpr := range envExprs {
			if normalizeExpressionCritical(envExpr) == normalizedExpr {
				return true
			}
		}
	}

	return false
}

// extractExpressionsFromStringCritical extracts expression contents from a string containing ${{ }}
func extractExpressionsFromStringCritical(s string) []string {
	var results []string
	offset := 0

	for {
		idx := strings.Index(s[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx + 3
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

// normalizeExpressionCritical normalizes an expression by removing extra whitespace
func normalizeExpressionCritical(expr string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(expr)), " ")
}
