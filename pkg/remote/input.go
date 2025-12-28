package remote

import (
	"fmt"
	"net/url"
	"strings"
)

// InputType represents the type of input
type InputType int

const (
	InputTypeURL InputType = iota
	InputTypeOwnerRepo
	InputTypeSearchQuery
)

// ParsedInput represents parsed input
type ParsedInput struct {
	Type  InputType
	Owner string // for URL/OwnerRepo
	Repo  string // for URL/OwnerRepo
	Query string // for search
}

// ParseInput automatically detects and parses the input string
func ParseInput(input string) (*ParsedInput, error) {
	// 1. Check URL format: https://github.com/owner/repo
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return parseURL(input)
	}

	// 2. Check owner/repo format
	if isOwnerRepoFormat(input) {
		return parseOwnerRepo(input)
	}

	// 3. Treat everything else as a search query
	return parseSearchQuery(input), nil
}

func parseURL(input string) (*ParsedInput, error) {
	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	if u.Host != "github.com" {
		return nil, fmt.Errorf("URLs other than github.com are not supported: %s", u.Host)
	}

	// Expecting /owner/repo format
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid GitHub URL format: %s", input)
	}

	return &ParsedInput{
		Type:  InputTypeURL,
		Owner: parts[0],
		Repo:  parts[1],
	}, nil
}

func parseOwnerRepo(input string) (*ParsedInput, error) {
	parts := strings.Split(input, "/")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid owner/repo format: %s", input)
	}

	return &ParsedInput{
		Type:  InputTypeOwnerRepo,
		Owner: parts[0],
		Repo:  parts[1],
	}, nil
}

func parseSearchQuery(input string) *ParsedInput {
	return &ParsedInput{
		Type:  InputTypeSearchQuery,
		Query: input,
	}
}

func isOwnerRepoFormat(input string) bool {
	// owner/repo format: single slash, no spaces, no GitHub search syntax keywords
	if strings.Count(input, "/") != 1 {
		return false
	}
	if strings.ContainsAny(input, " \t\n") {
		return false
	}

	// No GitHub search syntax keywords
	searchKeywords := []string{"language:", "stars:", "in:", "user:", "org:", "topic:", "repo:"}
	for _, kw := range searchKeywords {
		if strings.Contains(input, kw) {
			return false
		}
	}

	return true
}
