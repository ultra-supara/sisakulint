package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// CachePoisoningRule detects potential cache poisoning vulnerabilities in GitHub Actions workflows.
// This rule checks for the combination of:
// 1. Untrusted triggers (issue_comment, pull_request_target, workflow_run)
// 2. Checking out PR head ref with actions/checkout
// 3. Using cache actions (actions/cache or setup-* with cache enabled)
type CachePoisoningRule struct {
	BaseRule
	unsafeTriggers    []string // detected unsafe triggers
	checkoutUnsafeRef bool     // whether PR head is checked out
}

// NewCachePoisoningRule creates a new cache poisoning detection rule.
func NewCachePoisoningRule() *CachePoisoningRule {
	return &CachePoisoningRule{
		BaseRule: BaseRule{
			RuleName: "cache-poisoning",
			RuleDesc: "Detects potential cache poisoning vulnerabilities when using cache with untrusted triggers",
		},
	}
}

// unsafeTriggerNames are webhook events that can be triggered by external actors
// and run in the context of the default branch
var unsafeTriggerNames = map[string]bool{
	"issue_comment":       true,
	"pull_request_target": true,
	"workflow_run":        true,
}

// isUnsafeTrigger checks if the given event name is considered unsafe for caching
func isUnsafeTrigger(eventName string) bool {
	return unsafeTriggerNames[eventName]
}

// isUnsafeCheckoutRef checks if the ref input contains patterns that indicate
// checking out untrusted PR code
func isUnsafeCheckoutRef(refValue string) bool {
	if refValue == "" {
		return false
	}

	unsafePatterns := []string{
		"github.event.pull_request.head.sha",
		"github.event.pull_request.head.ref",
		"github.head_ref",
		"refs/pull/",
	}

	lower := strings.ToLower(refValue)
	for _, pattern := range unsafePatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// isCacheAction checks if the action uses caching functionality
func isCacheAction(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	// Extract action name without version (e.g., "actions/cache@v3" -> "actions/cache")
	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	// Direct cache action
	if actionName == "actions/cache" {
		return true
	}

	// Setup actions with cache input
	if strings.HasPrefix(actionName, "actions/setup-") {
		if cacheInput, ok := inputs["cache"]; ok && cacheInput != nil {
			// cache: true, cache: npm, cache: pip, etc.
			if cacheInput.Value != nil && cacheInput.Value.Value != "" && cacheInput.Value.Value != "false" {
				return true
			}
		}
	}

	return false
}

// VisitWorkflowPre checks for unsafe triggers in the workflow's on: section
func (rule *CachePoisoningRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.unsafeTriggers = nil

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil && isUnsafeTrigger(e.Hook.Value) {
				rule.unsafeTriggers = append(rule.unsafeTriggers, e.Hook.Value)
			}
		}
	}

	return nil
}

// VisitWorkflowPost is called after visiting all jobs
func (rule *CachePoisoningRule) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

// VisitJobPre resets the checkout state for each job
func (rule *CachePoisoningRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutUnsafeRef = false
	return nil
}

// VisitJobPost is called after visiting all steps in a job
func (rule *CachePoisoningRule) VisitJobPost(node *ast.Job) error {
	return nil
}

// VisitStep checks for unsafe checkout refs and cache action usage
func (rule *CachePoisoningRule) VisitStep(node *ast.Step) error {
	// Skip if no unsafe triggers
	if len(rule.unsafeTriggers) == 0 {
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	// Extract action name without version
	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	// Check for actions/checkout with unsafe ref
	if actionName == "actions/checkout" {
		if refInput, ok := action.Inputs["ref"]; ok && refInput != nil && refInput.Value != nil {
			if isUnsafeCheckoutRef(refInput.Value.Value) {
				rule.checkoutUnsafeRef = true
			}
		}
		return nil
	}

	// Check for cache action usage after unsafe checkout
	if rule.checkoutUnsafeRef && isCacheAction(uses, action.Inputs) {
		triggers := strings.Join(rule.unsafeTriggers, ", ")
		rule.Errorf(
			node.Pos,
			"cache poisoning risk: workflow uses '%s' after checking out untrusted PR code with triggers [%s]. Attackers may poison the cache to execute code in privileged workflows. Consider validating cached content or scoping cache to pull request level",
			uses,
			triggers,
		)
	}

	return nil
}
