package remote

import (
	"fmt"
	"net/url"
	"strings"
)

// InputType は入力の種類を表す
type InputType int

const (
	InputTypeURL InputType = iota
	InputTypeOwnerRepo
	InputTypeSearchQuery
)

// ParsedInput はパースされた入力を表す
type ParsedInput struct {
	Type  InputType
	Owner string // URL/OwnerRepo用
	Repo  string // URL/OwnerRepo用
	Query string // 検索用
}

// ParseInput は入力文字列を自動判別してパース
func ParseInput(input string) (*ParsedInput, error) {
	// 1. URL形式チェック: https://github.com/owner/repo
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return parseURL(input)
	}

	// 2. owner/repo形式チェック
	if isOwnerRepoFormat(input) {
		return parseOwnerRepo(input)
	}

	// 3. それ以外は検索クエリとして扱う
	return parseSearchQuery(input), nil
}

func parseURL(input string) (*ParsedInput, error) {
	u, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("URLのパースに失敗: %w", err)
	}

	if u.Host != "github.com" {
		return nil, fmt.Errorf("github.com以外のURLはサポートされていません: %s", u.Host)
	}

	// /owner/repo の形式を期待
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("無効なGitHub URL形式: %s", input)
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
		return nil, fmt.Errorf("owner/repo形式が不正: %s", input)
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
	// owner/repo形式: スラッシュが1つ、スペースなし、GitHub検索構文キーワードなし
	if strings.Count(input, "/") != 1 {
		return false
	}
	if strings.ContainsAny(input, " \t\n") {
		return false
	}

	// GitHub検索構文のキーワードがない
	searchKeywords := []string{"language:", "stars:", "in:", "user:", "org:", "topic:", "repo:"}
	for _, kw := range searchKeywords {
		if strings.Contains(input, kw) {
			return false
		}
	}

	return true
}
