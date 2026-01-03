package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
	"github.com/ultra-supara/sisakulint/pkg/expressions"
)

// UntrustedCheckoutRule checks for dangerous combinations of privileged triggers
// and untrusted code checkout. This rule detects the pattern where workflows
// triggered by pull_request_target, issue_comment, or workflow_run events
// explicitly check out code from pull request HEAD, which can allow malicious
// actors to execute code with access to repository secrets.
//
// This implements detection for CICD-SEC-4 (Poisoned Pipeline Execution)
// and maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).
//
// Vulnerable pattern:
//   on: pull_request_target
//   jobs:
//     build:
//       steps:
//         - uses: actions/checkout@v4
//           with:
//             ref: ${{ github.event.pull_request.head.sha }}
//
// Safe alternatives:
// 1. Use 'pull_request' trigger instead (no secrets access)
// 2. Don't checkout PR HEAD code when using privileged triggers
// 3. Use workflow_run pattern to separate privileged and unprivileged work
//
// References:
// - https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/
// - https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
// - https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
type UntrustedCheckoutRule struct {
	BaseRule
	// hasDangerousTrigger indicates if the workflow uses a dangerous trigger
	hasDangerousTrigger bool
	// dangerousTriggerPos stores the position of the dangerous trigger for error reporting
	dangerousTriggerPos *ast.Position
	// dangerousTriggerName stores the name of the dangerous trigger (e.g., "pull_request_target")
	dangerousTriggerName string
}

// NewUntrustedCheckoutRule creates a new instance of the untrusted checkout rule
func NewUntrustedCheckoutRule() *UntrustedCheckoutRule {
	return &UntrustedCheckoutRule{
		BaseRule: BaseRule{
			RuleName: "untrusted-checkout",
			RuleDesc: "Detects checkout of untrusted code in workflows with privileged triggers that have access to secrets",
		},
	}
}

// VisitWorkflowPre checks if the workflow uses dangerous triggers
// Dangerous triggers: pull_request_target, issue_comment, workflow_run
// These triggers run in the context of the base repository with access to secrets
func (rule *UntrustedCheckoutRule) VisitWorkflowPre(n *ast.Workflow) error {
	// Reset state for each workflow
	rule.hasDangerousTrigger = false
	rule.dangerousTriggerPos = nil
	rule.dangerousTriggerName = ""

	// Check all workflow triggers
	for _, event := range n.On {
		// Only WebhookEvents can be dangerous (pull_request_target, issue_comment, workflow_run)
		if webhookEvent, ok := event.(*ast.WebhookEvent); ok {
			triggerName := webhookEvent.EventName()

			// Check if this is a dangerous trigger
			// pull_request_target: Runs in base repo context with write permissions and secrets
			// issue_comment: Runs in base repo context, can be triggered by external contributors
			// workflow_run: Runs in base repo context with access to secrets
			switch triggerName {
			case "pull_request_target", "issue_comment", "workflow_run":
				rule.hasDangerousTrigger = true
				rule.dangerousTriggerPos = webhookEvent.Pos
				rule.dangerousTriggerName = triggerName
				rule.Debug("Found dangerous trigger '%s' at %s", triggerName, webhookEvent.Pos)
				// Don't break - we might find multiple dangerous triggers but we only need one
			}
		}
	}

	return nil
}

// VisitStep checks if a step performs an untrusted checkout
func (rule *UntrustedCheckoutRule) VisitStep(step *ast.Step) error {
	// Skip if no dangerous trigger found
	if !rule.hasDangerousTrigger {
		return nil
	}

	// Check if this step is an action (not a run script)
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	// Check if this is actions/checkout
	if !strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
		return nil
	}

	rule.Debug("Found checkout action at %s", step.Pos)

	// Check if the checkout has a 'ref' parameter
	// If no ref is specified, the default is safe (checks out the trigger SHA)
	if action.Inputs == nil {
		return nil
	}

	refInput, exists := action.Inputs["ref"]
	if !exists {
		return nil
	}

	refValue := refInput.Value
	if refValue == nil {
		return nil
	}

	rule.Debug("Checkout has ref parameter: %s", refValue.Value)

	// Check if the ref uses untrusted input from PR
	if rule.isUntrustedPRRef(refValue) {
		rule.Errorf(
			refValue.Pos,
			"checking out untrusted code from pull request in workflow with privileged trigger '%s' (line %d). This allows potentially malicious code from external contributors to execute with access to repository secrets. "+
				"Use 'pull_request' trigger instead, or avoid checking out PR code when using '%s'. "+
				"See https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/ for more details [untrusted-checkout]",
			rule.dangerousTriggerName,
			rule.dangerousTriggerPos.Line,
			rule.dangerousTriggerName,
		)
	}

	return nil
}

// isUntrustedPRRef checks if a ref value points to untrusted PR code
func (rule *UntrustedCheckoutRule) isUntrustedPRRef(refValue *ast.String) bool {
	// Check if the value contains expressions
	if !refValue.ContainsExpression() {
		// No expression - literal ref is safe
		return false
	}

	// Extract and parse all expressions in the ref value
	exprs := rule.extractAndParseRefExpressions(refValue)

	// Check each expression for untrusted PR references
	for _, expr := range exprs {
		if rule.isUntrustedPRExpression(expr.node, expr.raw) {
			return true
		}
	}

	return false
}

// refParsedExpression represents a parsed expression with its position and AST node
type refParsedExpression struct {
	raw  string             // Original expression content
	node expressions.ExprNode // Parsed AST node
	pos  *ast.Position      // Position in source
}

// extractAndParseRefExpressions extracts all expressions from a string and parses them
func (rule *UntrustedCheckoutRule) extractAndParseRefExpressions(str *ast.String) []refParsedExpression {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []refParsedExpression
	offset := 0

	for {
		// Find next expression start
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		// Find closing }}
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		// Extract expression content (between ${{ and }})
		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		// Parse the expression
		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			// Calculate position
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}

			result = append(result, refParsedExpression{
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
func (rule *UntrustedCheckoutRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	// The tokenizer expects the expression to end with }}
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// isUntrustedPRExpression checks if an expression accesses untrusted PR data
func (rule *UntrustedCheckoutRule) isUntrustedPRExpression(node expressions.ExprNode, rawExpr string) bool {
	// Simple string-based check for common dangerous patterns
	// These patterns access pull request HEAD code which is untrusted
	dangerousPatterns := []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(rawExpr, pattern) {
			rule.Debug("Found untrusted PR reference in expression: %s", rawExpr)
			return true
		}
	}

	return false
}

// VisitWorkflowPost resets state after workflow processing
func (rule *UntrustedCheckoutRule) VisitWorkflowPost(n *ast.Workflow) error {
	// Reset state for next workflow
	rule.hasDangerousTrigger = false
	rule.dangerousTriggerPos = nil
	rule.dangerousTriggerName = ""
	return nil
}

// VisitJobPre is required by the TreeVisitor interface but not used
func (rule *UntrustedCheckoutRule) VisitJobPre(node *ast.Job) error {
	return nil
}

// VisitJobPost is required by the TreeVisitor interface but not used
func (rule *UntrustedCheckoutRule) VisitJobPost(node *ast.Job) error {
	return nil
}
