package core

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// RefConfusion detects ref confusion vulnerabilities where both a branch and tag
// with the same name exist, which can lead to supply chain attacks.
type RefConfusion struct {
	BaseRule
	// cache for ref confusion check results to avoid repeated API calls
	refCache     map[string]bool
	refCacheMu   sync.Mutex
	ghClient     *github.Client
	ghClientOnce sync.Once
}

// RefConfusionRule creates a new RefConfusion rule instance.
func RefConfusionRule() *RefConfusion {
	return &RefConfusion{
		BaseRule: BaseRule{
			RuleName: "ref-confusion",
			RuleDesc: "Detects actions using refs that exist as both a branch and tag, which can lead to supply chain attacks.",
		},
		refCache: make(map[string]bool),
	}
}

// isSymbolicRef checks if the given ref is a symbolic reference (not a full commit SHA).
// Returns true for refs like "v1", "v1.0.0", "main", etc.
// Returns false for full length commit SHAs (40 hex characters).
func isSymbolicRef(ref string) bool {
	// Full length commit SHA pattern
	shaPattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
	return !shaPattern.MatchString(ref)
}

// parseActionRef parses an action reference in the format "owner/repo@ref" or "owner/repo/path@ref".
// Returns owner, repo, ref, and whether parsing was successful.
func parseActionRef(usesValue string) (owner, repo, ref string, ok bool) {
	// Skip local actions (starting with ./)
	if strings.HasPrefix(usesValue, "./") {
		return "", "", "", false
	}

	// Split by @
	parts := strings.Split(usesValue, "@")
	if len(parts) != 2 {
		return "", "", "", false
	}

	ref = parts[1]
	ownerRepoPath := parts[0]

	// Split by / - could be "owner/repo" or "owner/repo/path"
	pathParts := strings.Split(ownerRepoPath, "/")
	if len(pathParts) < 2 {
		return "", "", "", false
	}

	owner = pathParts[0]
	repo = pathParts[1]

	return owner, repo, ref, true
}

// getGitHubClient returns the GitHub client, initializing it if necessary.
func (rule *RefConfusion) getGitHubClient() *github.Client {
	rule.ghClientOnce.Do(func() {
		rule.ghClient = github.NewClient(http.DefaultClient)
	})
	return rule.ghClient
}

// hasBranch checks if a branch with the given name exists in the repository.
func (rule *RefConfusion) hasBranch(ctx context.Context, owner, repo, branchName string) (bool, error) {
	client := rule.getGitHubClient()
	_, resp, err := client.Repositories.GetBranch(ctx, owner, repo, branchName, 0)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// hasTag checks if a tag with the given name exists in the repository.
func (rule *RefConfusion) hasTag(ctx context.Context, owner, repo, tagName string) (bool, error) {
	client := rule.getGitHubClient()
	// Try to get the ref for the tag
	_, resp, err := client.Git.GetRef(ctx, owner, repo, "tags/"+tagName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isConfusable checks if the given ref exists as both a branch and tag.
// Results are cached to avoid repeated API calls.
func (rule *RefConfusion) isConfusable(owner, repo, ref string) (bool, error) {
	cacheKey := owner + "/" + repo + "@" + ref

	rule.refCacheMu.Lock()
	if result, ok := rule.refCache[cacheKey]; ok {
		rule.refCacheMu.Unlock()
		return result, nil
	}
	rule.refCacheMu.Unlock()

	ctx := context.Background()

	// Check if branch exists
	hasBranch, err := rule.hasBranch(ctx, owner, repo, ref)
	if err != nil {
		rule.Debug("failed to check branch existence for %s/%s@%s: %v", owner, repo, ref, err)
		// Don't cache errors, return false to avoid false positives
		return false, nil
	}

	// If no branch exists, no confusion is possible
	if !hasBranch {
		rule.refCacheMu.Lock()
		rule.refCache[cacheKey] = false
		rule.refCacheMu.Unlock()
		return false, nil
	}

	// Check if tag exists
	hasTag, err := rule.hasTag(ctx, owner, repo, ref)
	if err != nil {
		rule.Debug("failed to check tag existence for %s/%s@%s: %v", owner, repo, ref, err)
		// Don't cache errors, return false to avoid false positives
		return false, nil
	}

	// Confusion is possible if both branch and tag exist
	confusable := hasBranch && hasTag

	rule.refCacheMu.Lock()
	rule.refCache[cacheKey] = confusable
	rule.refCacheMu.Unlock()

	return confusable, nil
}

// VisitStep checks each step for ref confusion vulnerabilities.
func (rule *RefConfusion) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value

	// Parse the action reference
	owner, repo, ref, ok := parseActionRef(usesValue)
	if !ok {
		return nil
	}

	// Skip if the ref is already a full commit SHA
	if !isSymbolicRef(ref) {
		return nil
	}

	// Check if the ref is confusable (exists as both branch and tag)
	confusable, err := rule.isConfusable(owner, repo, ref)
	if err != nil {
		rule.Debug("error checking ref confusion for %s: %v", usesValue, err)
		return nil
	}

	if confusable {
		rule.Errorf(step.Pos,
			"action '%s' uses ref '%s' which exists as both a branch and a tag in %s/%s. "+
				"This can lead to supply chain attacks if an attacker creates a branch with the same name as a tag. "+
				"Consider pinning to a full commit SHA for security. See: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			usesValue, ref, owner, repo)
		// Add auto-fixer to convert to commit SHA (reuse CommitShaRule's fixer logic)
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}

	return nil
}

// VisitJobPre is a no-op for this rule.
func (rule *RefConfusion) VisitJobPre(node *ast.Job) error {
	return nil
}

// VisitJobPost is a no-op for this rule.
func (rule *RefConfusion) VisitJobPost(node *ast.Job) error {
	return nil
}

// VisitWorkflowPre is a no-op for this rule.
func (rule *RefConfusion) VisitWorkflowPre(node *ast.Workflow) error {
	return nil
}

// VisitWorkflowPost is a no-op for this rule.
func (rule *RefConfusion) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

// FixStep implements the auto-fix by converting the symbolic ref to a commit SHA.
// This delegates to the same logic used by CommitShaRule.
func (rule *RefConfusion) FixStep(step *ast.Step) error {
	action := step.Exec.(*ast.ExecAction)
	usesValue := action.Uses.Value

	owner, repo, ref, ok := parseActionRef(usesValue)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "invalid action reference format: '%s'", usesValue)
	}

	client := rule.getGitHubClient()

	// Get commit SHA for the ref
	sha, _, err := client.Repositories.GetCommitSHA1(context.TODO(), owner, repo, ref, "")
	if err != nil {
		return FormattedError(step.Pos, rule.RuleName, "failed to get commit SHA for %s/%s@%s: %s", owner, repo, ref, err.Error())
	}

	// Preserve the original path if any (for actions like owner/repo/path@ref)
	atIdx := strings.Index(usesValue, "@")
	if atIdx == -1 {
		return FormattedError(step.Pos, rule.RuleName, "invalid action reference format: '%s'", usesValue)
	}
	ownerRepoPath := usesValue[:atIdx]

	action.Uses.BaseNode.Value = ownerRepoPath + "@" + sha
	action.Uses.BaseNode.LineComment = ref

	return nil
}
