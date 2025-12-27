package remote

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// LintFunc はワークフローをスキャンする関数の型
type LintFunc func(filepath string, content []byte) (hasErrors bool, err error)

// Scanner はリモートリポジトリをスキャンする
type Scanner struct {
	fetcher     *Fetcher
	parallelism int
	recursive   bool
	maxDepth    int
	verbose     bool
	output      io.Writer
	lintFunc    LintFunc
}

// ScanResult はスキャン結果を表す
type ScanResult struct {
	Repository *RepositoryInfo
	HasErrors  bool  // エラーがあったかどうか
	Error      error // リポジトリ全体のエラー
}

// ReusableAction は再利用可能なワークフローを表す
type ReusableAction struct {
	Owner    string
	Repo     string
	Path     string
	Ref      string
	FullPath string // owner/repo/.github/workflows/workflow.yml@ref
}

// ScannerOptions はスキャナーのオプションを表す
type ScannerOptions struct {
	Parallelism int
	Recursive   bool
	MaxDepth    int
	Limit       int
	Verbose     bool
	Output      io.Writer
	LintFunc    LintFunc
}

// NewScanner は新しいScannerを作成する
func NewScanner(opts *ScannerOptions) (*Scanner, error) {
	fetcher, err := NewFetcher(opts.Limit)
	if err != nil {
		return nil, fmt.Errorf("Fetcherの初期化に失敗: %w", err)
	}

	output := opts.Output
	if output == nil {
		output = io.Discard
	}

	if opts.LintFunc == nil {
		return nil, fmt.Errorf("LintFuncが指定されていません")
	}

	return &Scanner{
		fetcher:     fetcher,
		parallelism: opts.Parallelism,
		recursive:   opts.Recursive,
		maxDepth:    opts.MaxDepth,
		verbose:     opts.Verbose,
		output:      output,
		lintFunc:    opts.LintFunc,
	}, nil
}

// Scan は入力をパースしてリポジトリをスキャンする
func (s *Scanner) Scan(ctx context.Context, input string) ([]*ScanResult, error) {
	// 入力をパース
	parsedInput, err := ParseInput(input)
	if err != nil {
		return nil, fmt.Errorf("入力のパースに失敗: %w", err)
	}

	// リポジトリを取得
	repos, err := s.fetcher.FetchRepositories(ctx, parsedInput)
	if err != nil {
		return nil, fmt.Errorf("リポジトリの取得に失敗: %w", err)
	}

	if len(repos) == 0 {
		return nil, fmt.Errorf("対象のリポジトリが見つかりませんでした")
	}

	if s.verbose {
		fmt.Fprintf(s.output, "Found %d repositories to scan\n", len(repos))
	}

	// リポジトリをスキャン
	return s.scanRepositories(ctx, repos)
}

func (s *Scanner) scanRepositories(ctx context.Context, repos []*RepositoryInfo) ([]*ScanResult, error) {
	eg, ctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, s.parallelism)

	var mu sync.Mutex
	results := make([]*ScanResult, 0, len(repos))

	for _, repo := range repos {
		repo := repo
		eg.Go(func() error {
			sem <- struct{}{}
			defer func() { <-sem }()

			result := s.scanRepository(ctx, repo)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *Scanner) scanRepository(ctx context.Context, repo *RepositoryInfo) *ScanResult {
	if s.verbose {
		fmt.Fprintf(s.output, "Scanning repository: %s\n", repo.FullName)
	}

	// ワークフローファイルを取得
	workflows, err := s.fetcher.FetchWorkflows(ctx, repo)
	if err != nil {
		return &ScanResult{
			Repository: repo,
			Error:      fmt.Errorf("ワークフローの取得に失敗: %w", err),
		}
	}

	if len(workflows) == 0 {
		return &ScanResult{
			Repository: repo,
			HasErrors:  false,
		}
	}

	hasErrors := false
	scanned := make(map[string]bool) // 無限ループ防止用

	// 初期ワークフローをスキャン
	for _, wf := range workflows {
		if s.scanWorkflowRecursive(ctx, wf, 0, scanned) {
			hasErrors = true
		}
	}

	return &ScanResult{
		Repository: repo,
		HasErrors:  hasErrors,
	}
}

func (s *Scanner) scanWorkflowRecursive(ctx context.Context, wf *WorkflowFile, currentDepth int, scanned map[string]bool) bool {
	// 仮想パスを構築: "owner/repo/.github/workflows/file.yml"
	virtualPath := fmt.Sprintf("%s/%s", wf.RepoInfo.FullName, wf.Path)

	// すでにスキャン済みならスキップ
	if scanned[virtualPath] {
		return false
	}
	scanned[virtualPath] = true

	if s.verbose {
		indent := strings.Repeat("  ", currentDepth)
		fmt.Fprintf(s.output, "%sScanning: %s (depth: %d)\n", indent, virtualPath, currentDepth)
	}

	// lintFuncでスキャン（Linterが直接出力を行う）
	hasErrors, err := s.lintFunc(virtualPath, wf.Content)
	if err != nil {
		if s.verbose {
			fmt.Fprintf(s.output, "Error scanning %s: %v\n", virtualPath, err)
		}
		return false
	}

	// 再帰的スキャンが有効で、まだ深度制限に達していない場合
	if s.recursive && currentDepth < s.maxDepth {
		// reusable actionsを抽出
		reusableActions := extractReusableActions(wf.Content)

		if s.verbose && len(reusableActions) > 0 {
			indent := strings.Repeat("  ", currentDepth)
			fmt.Fprintf(s.output, "%sFound %d reusable actions\n", indent, len(reusableActions))
		}

		for _, action := range reusableActions {
			// reusable actionのワークフローを取得
			actionRepo := &RepositoryInfo{
				Owner:    action.Owner,
				Name:     action.Repo,
				FullName: fmt.Sprintf("%s/%s", action.Owner, action.Repo),
			}

			actionWorkflow, err := s.fetcher.FetchSingleWorkflow(ctx, actionRepo, action.Path)
			if err != nil {
				if s.verbose {
					fmt.Fprintf(s.output, "Failed to fetch reusable action %s: %v\n", action.FullPath, err)
				}
				continue
			}

			// 再帰的にスキャン
			if s.scanWorkflowRecursive(ctx, actionWorkflow, currentDepth+1, scanned) {
				hasErrors = true
			}
		}
	}

	return hasErrors
}

// extractReusableActions はワークフローファイルから再利用可能なワークフロー呼び出しを抽出する
// Format: owner/repo/.github/workflows/workflow.yml@ref
func extractReusableActions(content []byte) []ReusableAction {
	var actions []ReusableAction

	// YAMLをパース
	var workflow map[string]interface{}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return actions
	}

	// jobsセクションを取得
	jobs, ok := workflow["jobs"].(map[string]interface{})
	if !ok {
		return actions
	}

	// 各ジョブをチェック
	for _, job := range jobs {
		jobMap, ok := job.(map[string]interface{})
		if !ok {
			continue
		}

		// usesフィールドをチェック - reusable workflow用
		if uses, ok := jobMap["uses"].(string); ok {
			if action := parseReusableAction(uses); action != nil {
				actions = append(actions, *action)
			}
		}
	}

	return actions
}

// parseReusableAction は再利用可能なワークフロー参照をパースする
// Format: owner/repo/.github/workflows/workflow.yml@ref
var reusableActionRegex = regexp.MustCompile(`^([^/]+)/([^/]+)/\.github/workflows/([^@]+)@?(.*)$`)

func parseReusableAction(uses string) *ReusableAction {
	matches := reusableActionRegex.FindStringSubmatch(uses)
	if len(matches) != 5 {
		return nil
	}

	owner := matches[1]
	repo := matches[2]
	workflow := matches[3]
	ref := matches[4]

	// refが空の場合はデフォルトブランチを使用
	if ref == "" {
		ref = "main"
	}

	path := fmt.Sprintf(".github/workflows/%s", workflow)

	return &ReusableAction{
		Owner:    owner,
		Repo:     repo,
		Path:     path,
		Ref:      ref,
		FullPath: uses,
	}
}
