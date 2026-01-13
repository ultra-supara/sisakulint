package core

import (
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// ArtipackedRule detects credential persistence vulnerabilities in GitHub Actions workflows.
// When actions/checkout retains credentials (persist-credentials: true, which is the default),
// the GITHUB_TOKEN is stored in .git/config. If a subsequent actions/upload-artifact uploads
// the workspace (e.g., path: "."), this token can be leaked.
//
// Detection conditions:
// 1. actions/checkout step without persist-credentials: false
// 2. actions/upload-artifact step with dangerous path patterns (., ./, .., ${{ github.workspace }})
//
// Severity levels:
// - High: checkout < v6 + dangerous upload (credentials in .git/config)
// - Medium: checkout >= v6 + dangerous upload (credentials in $RUNNER_TEMP)
// - Low/Medium: checkout without dangerous upload (potential risk)
//
// References:
// - https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
// - zizmor: https://github.com/woodruffw/zizmor/blob/main/crates/zizmor/src/audit/artipacked.rs
type ArtipackedRule struct {
	BaseRule
	// checkoutSteps stores checkout steps without persist-credentials: false per job
	checkoutSteps []*checkoutInfo
	// currentJobID stores the current job being processed
	currentJobID string
}

// checkoutInfo stores information about a checkout step for later analysis
type checkoutInfo struct {
	step      *ast.Step
	version   int // 0 = unknown, 6+ = v6 or later
	stepIndex int // index of the step in the job
}

// NewArtipackedRule creates a new instance of the artipacked rule
func NewArtipackedRule() *ArtipackedRule {
	return &ArtipackedRule{
		BaseRule: BaseRule{
			RuleName: "artipacked",
			RuleDesc: "Detects credential leakage risk when actions/checkout credentials are persisted and workspace is uploaded via actions/upload-artifact",
		},
	}
}

// VisitWorkflowPre resets state for each workflow
func (rule *ArtipackedRule) VisitWorkflowPre(n *ast.Workflow) error {
	rule.checkoutSteps = nil
	rule.currentJobID = ""
	return nil
}

// VisitWorkflowPost resets state after workflow processing
func (rule *ArtipackedRule) VisitWorkflowPost(n *ast.Workflow) error {
	rule.checkoutSteps = nil
	rule.currentJobID = ""
	return nil
}

// VisitJobPre resets step tracking for each job
func (rule *ArtipackedRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutSteps = nil
	if node.ID != nil {
		rule.currentJobID = node.ID.Value
	}
	return nil
}

// VisitJobPost checks for unpaired checkout steps and reports potential risks
func (rule *ArtipackedRule) VisitJobPost(node *ast.Job) error {
	// Report remaining checkout steps without dangerous upload as low severity
	for _, info := range rule.checkoutSteps {
		severity := "Medium"
		if info.version >= 6 {
			severity = "Low"
		}
		rule.Errorf(
			info.step.Pos,
			"[%s] actions/checkout without 'persist-credentials: false' at step %q. Credentials are stored in %s. While no dangerous upload-artifact was found in this job, consider adding 'persist-credentials: false' to prevent credential exposure. "+
				"See https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
			severity,
			info.step.String(),
			rule.getCredentialLocation(info.version),
		)
		rule.AddAutoFixer(NewStepFixer(info.step, rule))
	}
	rule.checkoutSteps = nil
	return nil
}

// getCredentialLocation returns the location where credentials are stored based on checkout version
func (rule *ArtipackedRule) getCredentialLocation(version int) string {
	if version >= 6 {
		return "$RUNNER_TEMP"
	}
	return ".git/config"
}

// VisitStep analyzes checkout and upload-artifact steps
func (rule *ArtipackedRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	// Track checkout steps
	if rule.isCheckoutAction(action.Uses.Value) {
		rule.handleCheckout(step, action)
		return nil
	}

	// Check upload-artifact steps
	if rule.isUploadArtifactAction(action.Uses.Value) {
		rule.handleUploadArtifact(step, action)
	}

	return nil
}

// isCheckoutAction checks if the action is actions/checkout
func (rule *ArtipackedRule) isCheckoutAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/checkout@")
}

// isUploadArtifactAction checks if the action is actions/upload-artifact
func (rule *ArtipackedRule) isUploadArtifactAction(uses string) bool {
	return strings.HasPrefix(uses, "actions/upload-artifact@")
}

// handleCheckout processes a checkout action step
func (rule *ArtipackedRule) handleCheckout(step *ast.Step, action *ast.ExecAction) {
	// Check if persist-credentials is explicitly set to false
	if action.Inputs != nil {
		if persistCreds, exists := action.Inputs["persist-credentials"]; exists {
			if persistCreds.Value != nil && strings.ToLower(persistCreds.Value.Value) == "false" {
				// Safe: credentials will not be persisted
				rule.Debug("Checkout at %s has persist-credentials: false, skipping", step.Pos)
				return
			}
		}
	}

	// Get checkout version
	version := rule.getCheckoutVersion(action.Uses.Value)

	// Add to tracking list
	stepIndex := len(rule.checkoutSteps)
	rule.checkoutSteps = append(rule.checkoutSteps, &checkoutInfo{
		step:      step,
		version:   version,
		stepIndex: stepIndex,
	})

	rule.Debug("Found vulnerable checkout at %s, version=%d", step.Pos, version)
}

// getCheckoutVersion extracts the major version from checkout action reference
func (rule *ArtipackedRule) getCheckoutVersion(uses string) int {
	// Extract version from uses string (e.g., "actions/checkout@v4", "actions/checkout@v6.0.0")
	parts := strings.Split(uses, "@")
	if len(parts) != 2 {
		return 0 // unknown
	}

	version := parts[1]

	// Handle tag format (v1, v2, v4, v6, etc.)
	versionPattern := regexp.MustCompile(`^v?(\d+)`)
	matches := versionPattern.FindStringSubmatch(version)
	if len(matches) >= 2 {
		var major int
		_, err := parseVersion(matches[1], &major)
		if err == nil {
			return major
		}
	}

	// Handle commit SHA (40 hex characters) - treat as unknown
	if len(version) == 40 && isHexString(version) {
		return 0 // unknown, treat conservatively
	}

	return 0 // unknown
}

// parseVersion is a simple helper to parse version number
func parseVersion(s string, v *int) (int, error) {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	*v = n
	return n, nil
}

// isHexString checks if a string is a valid hex string
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// handleUploadArtifact processes an upload-artifact action step
func (rule *ArtipackedRule) handleUploadArtifact(step *ast.Step, action *ast.ExecAction) {
	// Check if the upload path is dangerous
	pathValue := rule.getUploadPath(action)
	if !rule.isDangerousUploadPath(pathValue) {
		return
	}

	// Check if there are any preceding checkout steps with credential persistence
	if len(rule.checkoutSteps) == 0 {
		return
	}

	// Report error for each vulnerable checkout-upload pair
	for _, checkoutInfo := range rule.checkoutSteps {
		severity := "High"
		if checkoutInfo.version >= 6 {
			severity = "Medium"
		}

		rule.Errorf(
			step.Pos,
			"[%s] actions/upload-artifact uploads workspace with path %q, which may include credentials from actions/checkout at line %d. "+
				"The checkout action stores GITHUB_TOKEN in %s. "+
				"Add 'persist-credentials: false' to the checkout step or avoid uploading the entire workspace. "+
				"See https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/",
			severity,
			pathValue,
			checkoutInfo.step.Pos.Line,
			rule.getCredentialLocation(checkoutInfo.version),
		)

		// Add auto-fixer for the checkout step
		rule.AddAutoFixer(NewStepFixer(checkoutInfo.step, rule))
	}

	// Clear the checkout steps since we've reported them
	rule.checkoutSteps = nil
}

// getUploadPath extracts the path input from upload-artifact action
func (rule *ArtipackedRule) getUploadPath(action *ast.ExecAction) string {
	if action.Inputs == nil {
		return ""
	}

	pathInput, exists := action.Inputs["path"]
	if !exists || pathInput == nil || pathInput.Value == nil {
		return ""
	}

	return pathInput.Value.Value
}

// isDangerousUploadPath checks if the upload path includes the workspace root
func (rule *ArtipackedRule) isDangerousUploadPath(path string) bool {
	if path == "" {
		return false
	}

	path = strings.TrimSpace(path)

	// Check for current directory patterns
	if path == "." || path == "./" {
		return true
	}

	// Check for parent directory patterns
	if path == ".." || strings.HasPrefix(path, "../") {
		return true
	}

	// Check for github.workspace reference
	if strings.Contains(path, "github.workspace") {
		return true
	}

	// Check for GITHUB_WORKSPACE environment variable
	if strings.Contains(path, "GITHUB_WORKSPACE") {
		return true
	}

	return false
}

// FixStep implements the StepFixer interface to add persist-credentials: false
func (rule *ArtipackedRule) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "step is not an action")
	}

	// Only fix checkout actions
	if !rule.isCheckoutAction(action.Uses.Value) {
		return FormattedError(step.Pos, rule.RuleName, "not a checkout action")
	}

	// Initialize Inputs if nil
	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	// Add persist-credentials: false
	action.Inputs["persist-credentials"] = &ast.Input{
		Name: &ast.String{
			Value: "persist-credentials",
			Pos:   step.Pos,
		},
		Value: &ast.String{
			Value: "false",
			Pos:   step.Pos,
		},
	}

	// Update YAML node
	rule.addPersistCredentialsToWithSection(step.BaseNode)

	rule.Debug("Fixed checkout at %s: added persist-credentials: false", step.Pos)
	return nil
}

// addPersistCredentialsToWithSection adds persist-credentials: false to the with section
func (rule *ArtipackedRule) addPersistCredentialsToWithSection(stepNode *yaml.Node) {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return
	}

	// Find the 'with' section
	withIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMWith {
			withIndex = i
			break
		}
	}

	persistKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "persist-credentials"}
	persistValue := &yaml.Node{Kind: yaml.ScalarNode, Value: "false"}

	if withIndex >= 0 {
		// 'with' section exists, add persist-credentials
		withNode := stepNode.Content[withIndex+1]
		if withNode.Kind == yaml.MappingNode {
			// Check if persist-credentials already exists
			for i := 0; i < len(withNode.Content); i += 2 {
				if withNode.Content[i].Value == "persist-credentials" {
					// Update existing value
					withNode.Content[i+1] = persistValue
					return
				}
			}
			// Add new persist-credentials entry at the beginning
			withNode.Content = append([]*yaml.Node{persistKey, persistValue}, withNode.Content...)
		}
		return
	}

	// 'with' section doesn't exist, create it after 'uses'
	usesIndex := -1
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMUses {
			usesIndex = i
			break
		}
	}

	withKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "with"}
	withValue := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{persistKey, persistValue},
	}

	if usesIndex >= 0 {
		// Insert 'with' section after 'uses'
		insertIndex := usesIndex + 2
		stepNode.Content = append(
			stepNode.Content[:insertIndex],
			append([]*yaml.Node{withKey, withValue}, stepNode.Content[insertIndex:]...)...,
		)
	} else {
		// 'uses' not found, append at the end
		stepNode.Content = append(stepNode.Content, withKey, withValue)
	}
}
