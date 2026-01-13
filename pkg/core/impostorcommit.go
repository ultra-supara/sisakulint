package core

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// ImpostorCommitRule detects impostor commits - commits that exist in the fork network
// but not in any branch or tag of the specified repository.
// This is a supply chain attack vector where attackers create malicious commits in forks
// and trick users into referencing them as if they were from the original repository.
type ImpostorCommitRule struct {
	BaseRule
	client          *github.Client
	clientOnce      sync.Once
	commitCache     map[string]*commitVerificationResult
	commitCacheMu   sync.Mutex
	tagCache        map[string][]*github.RepositoryTag
	tagCacheMu      sync.Mutex
	branchCache     map[string][]*github.Branch
	branchCacheMu   sync.Mutex
	latestTagCache  map[string]string
	latestTagCacheMu sync.Mutex
}

// commitVerificationResult holds the result of commit verification
type commitVerificationResult struct {
	isImpostor bool
	latestTag  string // for auto-fix suggestion
	err        error
}

// ImpostorCommitRuleFactory creates a new ImpostorCommitRule instance
func ImpostorCommitRuleFactory() *ImpostorCommitRule {
	return &ImpostorCommitRule{
		BaseRule: BaseRule{
			RuleName: "impostor-commit",
			RuleDesc: "Detects impostor commits that exist in the fork network but not in the repository's branches or tags",
		},
		commitCache:    make(map[string]*commitVerificationResult),
		tagCache:       make(map[string][]*github.RepositoryTag),
		branchCache:    make(map[string][]*github.Branch),
		latestTagCache: make(map[string]string),
	}
}

// fullShaPattern matches a 40-character hexadecimal SHA
var fullShaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// isFullSha checks if the given ref is a full 40-character SHA
func isFullSha(ref string) bool {
	return fullShaPattern.MatchString(ref)
}

// parseActionRef parses a GitHub action reference like "owner/repo@ref"
// Returns owner, repo, ref, and a boolean indicating if it's a local action or invalid format
func parseActionRef(usesValue string) (owner, repo, ref string, isLocal bool) {
	// Skip Docker images and local actions
	if strings.HasPrefix(usesValue, "docker://") || strings.HasPrefix(usesValue, "./") || strings.HasPrefix(usesValue, ".\\") {
		return "", "", "", true
	}

	parts := strings.Split(usesValue, "@")
	if len(parts) != 2 {
		return "", "", "", true
	}

	ownerRepo := strings.Split(parts[0], "/")
	if len(ownerRepo) < 2 {
		return "", "", "", true
	}

	// Handle nested paths like "actions/aws/ec2@v1" -> owner=actions, repo=aws
	return ownerRepo[0], ownerRepo[1], parts[1], false
}

// getGitHubClient returns a GitHub client, initializing it once
func (rule *ImpostorCommitRule) getGitHubClient() *github.Client {
	rule.clientOnce.Do(func() {
		rule.client = github.NewClient(http.DefaultClient)
	})
	return rule.client
}

// VisitStep checks each step's action reference for impostor commits
func (rule *ImpostorCommitRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value
	owner, repo, ref, isLocal := parseActionRef(usesValue)

	// Skip local actions and non-SHA refs
	if isLocal || !isFullSha(ref) {
		return nil
	}

	// Verify the commit
	result := rule.verifyCommit(owner, repo, ref)
	if result.err != nil {
		rule.Debug("Error verifying commit %s/%s@%s: %v", owner, repo, ref, result.err)
		return nil // Don't fail the entire lint for API errors
	}

	if result.isImpostor {
		rule.Errorf(action.Uses.Pos,
			"potential impostor commit detected: the commit '%s' is not found in any branch or tag of '%s/%s'. "+
				"This could be a supply chain attack where an attacker created a malicious commit in a fork. "+
				"Verify the commit exists in the official repository or use a known tag instead. "+
				"See: https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd",
			ref, owner, repo)

		// Add auto-fixer if we have a latest tag to suggest
		if result.latestTag != "" {
			rule.AddAutoFixer(NewStepFixer(step, &impostorCommitFixer{
				rule:      rule,
				owner:     owner,
				repo:      repo,
				latestTag: result.latestTag,
			}))
		}
	}

	return nil
}

// verifyCommit checks if the given commit SHA exists in the repository's branches or tags
func (rule *ImpostorCommitRule) verifyCommit(owner, repo, sha string) *commitVerificationResult {
	cacheKey := fmt.Sprintf("%s/%s@%s", owner, repo, sha)

	// Check cache first
	rule.commitCacheMu.Lock()
	if result, ok := rule.commitCache[cacheKey]; ok {
		rule.commitCacheMu.Unlock()
		return result
	}
	rule.commitCacheMu.Unlock()

	result := rule.doVerifyCommit(owner, repo, sha)

	// Cache the result
	rule.commitCacheMu.Lock()
	rule.commitCache[cacheKey] = result
	rule.commitCacheMu.Unlock()

	return result
}

// doVerifyCommit performs the actual commit verification using GitHub API
// This implements a multi-stage verification process:
// 1. Fast path: Check if SHA matches any tag or branch tip
// 2. Medium path: Use branch_commits API (undocumented)
// 3. Slow path: Compare API to check if commit is in history
func (rule *ImpostorCommitRule) doVerifyCommit(owner, repo, sha string) *commitVerificationResult {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := rule.getGitHubClient()
	repoKey := fmt.Sprintf("%s/%s", owner, repo)

	// Stage 1: Fast path - Check tag tips
	tags := rule.getTags(ctx, client, owner, repo)
	var latestTag string
	for _, tag := range tags {
		if tag.GetCommit().GetSHA() == sha {
			// SHA matches a tag tip - this is a valid commit
			return &commitVerificationResult{isImpostor: false}
		}
		// Track the first (latest) tag for auto-fix suggestion
		if latestTag == "" && tag.GetName() != "" {
			// Prefer semver tags for auto-fix
			tagName := tag.GetName()
			if strings.HasPrefix(tagName, "v") {
				latestTag = tagName
			}
		}
	}

	// If no semver tag found, use the first tag
	if latestTag == "" && len(tags) > 0 {
		latestTag = tags[0].GetName()
	}

	// Cache the latest tag for this repo
	rule.latestTagCacheMu.Lock()
	if latestTag != "" {
		rule.latestTagCache[repoKey] = latestTag
	}
	rule.latestTagCacheMu.Unlock()

	// Stage 1b: Check branch tips
	branches := rule.getBranches(ctx, client, owner, repo)
	for _, branch := range branches {
		if branch.GetCommit().GetSHA() == sha {
			// SHA matches a branch tip - this is a valid commit
			return &commitVerificationResult{isImpostor: false}
		}
	}

	// Stage 2: Medium path - Try undocumented branch_commits API
	// This API returns the branches that contain a given commit
	branchCommitsURL := fmt.Sprintf("repos/%s/%s/commits/%s/branches-where-head", owner, repo, sha)
	req, err := client.NewRequest("GET", branchCommitsURL, nil)
	if err == nil {
		var branchList []*github.Branch
		resp, err := client.Do(ctx, req, &branchList)
		if err == nil && resp.StatusCode == 200 && len(branchList) > 0 {
			// Commit is found in at least one branch
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
		// If the API returns empty or 404, continue to slow path
	}

	// Stage 3: Slow path - Compare API for each main branch
	// Check if the commit is in the history of main branches
	mainBranches := []string{"main", "master", "develop"}
	for _, branchName := range mainBranches {
		comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, branchName, sha, nil)
		if err != nil {
			continue // Branch might not exist
		}

		// If status is "behind" or "identical", the commit is in the branch history
		status := comparison.GetStatus()
		if status == "behind" || status == "identical" {
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
	}

	// Stage 4: Check against all tags' commit histories
	for _, tag := range tags {
		tagSha := tag.GetCommit().GetSHA()
		if tagSha == "" {
			continue
		}

		comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, tagSha, sha, nil)
		if err != nil {
			continue
		}

		status := comparison.GetStatus()
		if status == "behind" || status == "identical" {
			return &commitVerificationResult{isImpostor: false, latestTag: latestTag}
		}
	}

	// If we've exhausted all checks and didn't find the commit, it's likely an impostor
	return &commitVerificationResult{isImpostor: true, latestTag: latestTag}
}

// getTags fetches and caches repository tags
func (rule *ImpostorCommitRule) getTags(ctx context.Context, client *github.Client, owner, repo string) []*github.RepositoryTag {
	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	rule.tagCacheMu.Lock()
	if tags, ok := rule.tagCache[cacheKey]; ok {
		rule.tagCacheMu.Unlock()
		return tags
	}
	rule.tagCacheMu.Unlock()

	var allTags []*github.RepositoryTag
	opts := &github.ListOptions{PerPage: 100}

	for i := 0; i < 5; i++ { // Limit to 5 pages (500 tags)
		tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			break
		}
		allTags = append(allTags, tags...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	rule.tagCacheMu.Lock()
	rule.tagCache[cacheKey] = allTags
	rule.tagCacheMu.Unlock()

	return allTags
}

// getBranches fetches and caches repository branches
func (rule *ImpostorCommitRule) getBranches(ctx context.Context, client *github.Client, owner, repo string) []*github.Branch {
	cacheKey := fmt.Sprintf("%s/%s", owner, repo)

	rule.branchCacheMu.Lock()
	if branches, ok := rule.branchCache[cacheKey]; ok {
		rule.branchCacheMu.Unlock()
		return branches
	}
	rule.branchCacheMu.Unlock()

	var allBranches []*github.Branch
	opts := &github.BranchListOptions{ListOptions: github.ListOptions{PerPage: 100}}

	for i := 0; i < 3; i++ { // Limit to 3 pages (300 branches)
		branches, resp, err := client.Repositories.ListBranches(ctx, owner, repo, opts)
		if err != nil {
			break
		}
		allBranches = append(allBranches, branches...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	rule.branchCacheMu.Lock()
	rule.branchCache[cacheKey] = allBranches
	rule.branchCacheMu.Unlock()

	return allBranches
}

// impostorCommitFixer implements StepFixer to replace impostor commits with valid tags
type impostorCommitFixer struct {
	rule      *ImpostorCommitRule
	owner     string
	repo      string
	latestTag string
}

func (f *impostorCommitFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *impostorCommitFixer) FixStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return fmt.Errorf("step is not an action")
	}

	// Get the latest tag's commit SHA
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := f.rule.getGitHubClient()
	sha, _, err := client.Repositories.GetCommitSHA1(ctx, f.owner, f.repo, f.latestTag, "")
	if err != nil {
		return fmt.Errorf("failed to get commit SHA for tag %s: %w", f.latestTag, err)
	}

	// Update the action reference
	newUses := fmt.Sprintf("%s/%s@%s", f.owner, f.repo, sha)
	action.Uses.Value = newUses
	action.Uses.BaseNode.Value = newUses
	action.Uses.BaseNode.LineComment = f.latestTag

	return nil
}
