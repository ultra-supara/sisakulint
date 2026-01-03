package core

import (
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// CachePoisoningRule detects potential cache poisoning vulnerabilities in GitHub Actions workflows.
// It checks for the combination of:
// 1. Untrusted triggers (issue_comment, pull_request_target, workflow_run)
// 2. Checking out PR head ref with actions/checkout
// 3. Using cache actions (actions/cache or setup-* with cache enabled)
type CachePoisoningRule struct {
	BaseRule
	unsafeTriggers      []string
	checkoutUnsafeRef   bool
	unsafeCheckoutStep  *ast.Step
	autoFixerRegistered bool
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

func isCacheAction(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName == "actions/cache" {
		return true
	}

	if strings.HasPrefix(actionName, "actions/setup-") {
		if cacheInput, ok := inputs["cache"]; ok && cacheInput != nil {
			if cacheInput.Value != nil && cacheInput.Value.Value != "" && cacheInput.Value.Value != "false" {
				return true
			}
		}
	}

	return false
}

func (rule *CachePoisoningRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.unsafeTriggers = nil

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil && IsUnsafeTrigger(e.Hook.Value) {
				rule.unsafeTriggers = append(rule.unsafeTriggers, e.Hook.Value)
			}
		}
	}

	return nil
}

func (rule *CachePoisoningRule) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

func (rule *CachePoisoningRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutUnsafeRef = false
	rule.unsafeCheckoutStep = nil
	rule.autoFixerRegistered = false
	return nil
}

func (rule *CachePoisoningRule) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *CachePoisoningRule) VisitStep(node *ast.Step) error {
	if len(rule.unsafeTriggers) == 0 {
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName == "actions/checkout" {
		if refInput, ok := action.Inputs["ref"]; ok && refInput != nil && refInput.Value != nil {
			if IsUnsafeCheckoutRef(refInput.Value.Value) {
				rule.checkoutUnsafeRef = true
				rule.unsafeCheckoutStep = node
			} else {
				// Safe checkout resets the unsafe state
				// This handles the case where an unsafe checkout is followed by a safe one
				rule.checkoutUnsafeRef = false
				rule.unsafeCheckoutStep = nil
			}
		} else {
			// Checkout without ref (defaults to base branch) is safe
			rule.checkoutUnsafeRef = false
			rule.unsafeCheckoutStep = nil
		}
		return nil
	}

	if rule.checkoutUnsafeRef && isCacheAction(uses, action.Inputs) {
		triggers := strings.Join(rule.unsafeTriggers, ", ")
		rule.Errorf(
			node.Pos,
			"cache poisoning risk: '%s' used after checking out untrusted PR code (triggers: %s). Validate cached content or scope cache to PR level",
			uses,
			triggers,
		)
		if rule.unsafeCheckoutStep != nil && !rule.autoFixerRegistered {
			rule.AddAutoFixer(NewStepFixer(rule.unsafeCheckoutStep, rule))
			rule.autoFixerRegistered = true
		}
	}

	return nil
}

func (rule *CachePoisoningRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}
	return RemoveRefFromWith(node.BaseNode)
}
