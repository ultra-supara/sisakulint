package remote

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/v68/github"
)

// RepositoryInfo はリポジトリ情報を表す
type RepositoryInfo struct {
	Owner    string
	Name     string
	FullName string // "owner/repo"
}

// WorkflowFile はワークフローファイル情報を表す
type WorkflowFile struct {
	Path     string // .github/workflows/ci.yml
	Content  []byte
	RepoInfo *RepositoryInfo
}

// Fetcher はGitHub APIからリポジトリやワークフローを取得する
type Fetcher struct {
	client *github.Client
	limit  int
}

// NewFetcher は新しいFetcherを作成する
func NewFetcher(limit int) (*Fetcher, error) {
	var httpClient *http.Client

	// GITHUB_TOKEN または GH_TOKEN から認証トークンを取得
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}

	if token != "" {
		httpClient = &http.Client{
			Transport: &tokenTransport{token: token},
		}
	}

	client := github.NewClient(httpClient)

	return &Fetcher{
		client: client,
		limit:  limit,
	}, nil
}

// tokenTransport はGitHub APIリクエストにトークンを付与するTransport
type tokenTransport struct {
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "token "+t.token)
	return http.DefaultTransport.RoundTrip(req)
}

// FetchRepositories は入力に基づいてリポジトリを取得する
func (f *Fetcher) FetchRepositories(ctx context.Context, input *ParsedInput) ([]*RepositoryInfo, error) {
	switch input.Type {
	case InputTypeURL, InputTypeOwnerRepo:
		return f.fetchSingleRepo(ctx, input.Owner, input.Repo)
	case InputTypeSearchQuery:
		return f.searchRepositories(ctx, input.Query)
	default:
		return nil, fmt.Errorf("未知の入力タイプ: %d", input.Type)
	}
}

func (f *Fetcher) fetchSingleRepo(ctx context.Context, owner, repo string) ([]*RepositoryInfo, error) {
	r, _, err := f.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("リポジトリの取得に失敗: %w", err)
	}

	return []*RepositoryInfo{
		{
			Owner:    r.GetOwner().GetLogin(),
			Name:     r.GetName(),
			FullName: r.GetFullName(),
		},
	}, nil
}

func (f *Fetcher) searchRepositories(ctx context.Context, query string) ([]*RepositoryInfo, error) {
	opts := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: f.limit,
		},
	}

	result, _, err := f.client.Search.Repositories(ctx, query, opts)
	if err != nil {
		return nil, fmt.Errorf("リポジトリの検索に失敗: %w", err)
	}

	repos := make([]*RepositoryInfo, 0, len(result.Repositories))
	for _, r := range result.Repositories {
		repos = append(repos, &RepositoryInfo{
			Owner:    r.GetOwner().GetLogin(),
			Name:     r.GetName(),
			FullName: r.GetFullName(),
		})

		if len(repos) >= f.limit {
			break
		}
	}

	return repos, nil
}

// FetchWorkflows はリポジトリからワークフローファイルを取得する
func (f *Fetcher) FetchWorkflows(ctx context.Context, repo *RepositoryInfo) ([]*WorkflowFile, error) {
	_, contents, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		".github/workflows",
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("ワークフローディレクトリの取得に失敗: %w", err)
	}

	workflows := make([]*WorkflowFile, 0)
	for _, content := range contents {
		if content.GetType() != "file" {
			continue
		}
		name := content.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		fileContent, _, _, err := f.client.Repositories.GetContents(
			ctx,
			repo.Owner,
			repo.Name,
			content.GetPath(),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("ワークフローファイル %s の取得に失敗: %w", content.GetPath(), err)
		}

		decodedContent, err := fileContent.GetContent()
		if err != nil {
			return nil, fmt.Errorf("ファイル %s のコンテンツ取得に失敗: %w", content.GetPath(), err)
		}

		workflows = append(workflows, &WorkflowFile{
			Path:     content.GetPath(),
			Content:  []byte(decodedContent),
			RepoInfo: repo,
		})
	}

	return workflows, nil
}

// FetchSingleWorkflow は単一のワークフローファイルを取得する
func (f *Fetcher) FetchSingleWorkflow(ctx context.Context, repo *RepositoryInfo, workflowPath string) (*WorkflowFile, error) {
	fileContent, _, _, err := f.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		workflowPath,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("ワークフローファイル %s の取得に失敗: %w", workflowPath, err)
	}

	decodedContent, err := fileContent.GetContent()
	if err != nil {
		return nil, fmt.Errorf("ファイル %s のコンテンツ取得に失敗: %w", workflowPath, err)
	}

	return &WorkflowFile{
		Path:     workflowPath,
		Content:  []byte(decodedContent),
		RepoInfo: repo,
	}, nil
}
