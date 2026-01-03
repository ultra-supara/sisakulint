package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
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


var unsafePatternsLower = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.head_ref",
	"refs/pull/",
	".head_sha",  // Detects steps.*.outputs.head_sha
	".head_ref",  // Detects steps.*.outputs.head_ref
	".head.sha",  // Detects nested head.sha patterns
	".head.ref",  // Detects nested head.ref patterns
	"head-sha",   // Detects kebab-case variants
	"head-ref",   // Detects kebab-case variants
}

// Patterns that are explicitly safe to use with any trigger
var safePatternsLower = []string{
	"github.ref",
	"github.sha",
	"github.base_ref",
	"github.event.repository.default_branch",
}

func isUnsafeTrigger(eventName string) bool {
	return UntrustedTriggers[eventName]
}

// isUnsafeCheckoutRef checks if the ref input contains patterns that indicate
// checking out untrusted PR code. Case-insensitive matching prevents bypass attempts.
// This implements a conservative approach: with untrusted triggers, any ref expression
// is considered unsafe unless it's explicitly known to be safe.
func isUnsafeCheckoutRef(refValue string) bool {
	if refValue == "" {
		return false
	}

	lower := strings.ToLower(refValue)

	// First, check for known unsafe patterns
	for _, pattern := range unsafePatternsLower {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Conservative approach: if the ref contains an expression (${{...}}),
	// check if it's a known safe pattern
	if strings.Contains(lower, "${{") {
		// Check if it's explicitly safe
		for _, safe := range safePatternsLower {
			if strings.Contains(lower, safe) {
				return false
			}
		}
		// Unknown expression - could be unsafe (e.g., steps.*.outputs.*)
		// We treat it as potentially unsafe to avoid false negatives
		return true
	}

	return false
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
			if e.Hook != nil && isUnsafeTrigger(e.Hook.Value) {
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
			if isUnsafeCheckoutRef(refInput.Value.Value) {
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

	// Check for cache action usage after unsafe checkout
	if rule.checkoutUnsafeRef && isCacheAction(uses, action.Inputs) {
		triggers := strings.Join(rule.unsafeTriggers, ", ")
		rule.Errorf(
			node.Pos,
			"cache poisoning risk: '%s' used after checking out untrusted PR code (triggers: %s). Validate cached content or scope cache to PR level",
			uses,
			triggers,
		)
		// Only register auto-fixer once per job (for the checkout step)
		if rule.unsafeCheckoutStep != nil && !rule.autoFixerRegistered {
			rule.AddAutoFixer(NewStepFixer(rule.unsafeCheckoutStep, rule))
			rule.autoFixerRegistered = true
		}
	}

	return nil
}

// FixStep removes the unsafe ref input from checkout step to use the default (base) branch
func (rule *CachePoisoningRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}
	return removeRefFromWith(node.BaseNode)
}

func removeRefFromWith(stepNode *yaml.Node) error {
	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == "with" && val.Kind == yaml.MappingNode {
			newContent := make([]*yaml.Node, 0, len(val.Content))
			for j := 0; j < len(val.Content); j += 2 {
				if j+1 >= len(val.Content) {
					break
				}
				withKey := val.Content[j]
				if withKey.Value != "ref" {
					newContent = append(newContent, val.Content[j], val.Content[j+1])
				}
			}
			if len(newContent) == 0 {
				// Remove entire 'with' section if empty
				stepNode.Content = append(stepNode.Content[:i], stepNode.Content[i+2:]...)
			} else {
				val.Content = newContent
			}
			return nil
		}
	}
	return nil
}
