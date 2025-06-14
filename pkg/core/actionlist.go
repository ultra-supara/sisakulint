package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// ActionListConfig は許可/禁止されたアクションのリストを管理する設定
type ActionListConfig struct {
	WhiteList []string `yaml:"whitelist,omitempty"`
	BlackList []string `yaml:"blacklist,omitempty"`
}

// ActionList はアクション参照のホワイトリスト/ブラックリストを実装するルール
type ActionList struct {
	BaseRule
	Config ActionListConfig
}

// configPathDefault は設定ファイルのデフォルトの場所
const configPathDefault = ".github/actionlist.yaml"

// NewActionListRule は新しい ActionList ルールを作成
func NewActionListRule() *ActionList {
	return &ActionList{
		BaseRule: BaseRule{
			RuleName: "action-list",
			RuleDesc: "Check if action references are in whitelist or not in blacklist",
		},
		Config: ActionListConfig{
			WhiteList: []string{},
			BlackList: []string{},
		},
	}
}

// LoadConfigFromFile は指定されたパスから設定を読み込む
func (rule *ActionList) LoadConfigFromFile(configPath string) error {
	if configPath == "" {
		configPath = configPathDefault
	}

	// ファイルが存在しなければスキップ
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ActionListConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	rule.Config = config
	return nil
}

// GenerateDefaultConfig はデフォルト設定ファイルを生成
func (rule *ActionList) GenerateDefaultConfig(outputPath string) error {
	if outputPath == "" {
		outputPath = configPathDefault
	}

	// ディレクトリが存在しなければ作成
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	config := ActionListConfig{
		WhiteList: []string{
			"actions/checkout@*",
			"actions/setup-node@*",
			"actions/cache@*",
		},
		BlackList: []string{
			"untrusted/*@*",
			"suspicious/*@*",
		},
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// isActionAllowed はアクションがルールに基づいて許可されているかチェック
func (rule *ActionList) isActionAllowed(actionRef string) (bool, string) {
	// 設定が空の場合は全て許可
	if len(rule.Config.WhiteList) == 0 && len(rule.Config.BlackList) == 0 {
		return true, ""
	}
	
	// ホワイトリストが設定されていて、マッチするなら許可
	if len(rule.Config.WhiteList) > 0 {
		for _, pattern := range rule.Config.WhiteList {
			if matchActionPattern(actionRef, pattern) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("action '%s' is not in the whitelist", actionRef)
	}

	// ブラックリストがあり、マッチするなら禁止
	for _, pattern := range rule.Config.BlackList {
		if matchActionPattern(actionRef, pattern) {
			return false, fmt.Sprintf("action '%s' is in the blacklist", actionRef)
		}
	}

	// ホワイトリストがなく、ブラックリストにマッチしなかった場合は許可
	return true, ""
}

// matchActionPattern はアクション参照がパターンにマッチするかチェック
// パターン例: "actions/checkout@*", "actions/*@v2", "owner/repo@v1.*"
func matchActionPattern(actionRef, pattern string) bool {
	// ワイルドカードをエスケープしてから特定の場所に適用する正規表現に変換
	regexPattern := strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*")
	re, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return false
	}
	return re.MatchString(actionRef)
}

// VisitStep はステップ内のアクション参照をチェック
func (rule *ActionList) VisitStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		usesValue := action.Uses.Value
		allowed, reason := rule.isActionAllowed(usesValue)
		if !allowed {
			rule.Errorf(step.Pos, "%s in step '%s'", reason, step.String())
			rule.AddAutoFixer(NewStepFixer(step, rule))
		}
	}
	return nil
}

// ここにVisitJobPre, VisitJobPost, VisitWorkflowPre, VisitWorkflowPostを実装
func (rule *ActionList) VisitJobPre(node *ast.Job) error {
	return nil
}

func (rule *ActionList) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *ActionList) VisitWorkflowPre(node *ast.Workflow) error {
	return nil
}

func (rule *ActionList) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

// FixStep は非準拠のアクション参照を修正するためのAutoFixer
func (rule *ActionList) FixStep(step *ast.Step) error {
	// action が ExecAction かどうかを安全にチェック
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return FormattedError(step.Pos, rule.RuleName, "expected ExecAction but got %T", step.Exec)
	}
	
	usesValue := action.Uses.Value
	
	// ブラックリスト対象のアクションがあるかチェック
	for _, blackPattern := range rule.Config.BlackList {
		if !matchActionPattern(usesValue, blackPattern) {
			continue // マッチしなければ次のパターンへ
		}
		
		// ブラックリストされたアクションには自動修正を適用しない
		// 代わりにエラーを返して手動での修正を促す
		return FormattedError(step.Pos, rule.RuleName, 
			"this action is blacklisted and must be replaced manually: %s", usesValue)
	}
	
	// ホワイトリストの場合（ホワイトリストに無いアクションが使われている場合）
	if len(rule.Config.WhiteList) > 0 {
		// ホワイトリストにマッチするか確認
		allowed := false
		for _, whitePattern := range rule.Config.WhiteList {
			if matchActionPattern(usesValue, whitePattern) {
				allowed = true
				break
			}
		}
		
		// マッチしなかったらエラーを返す
		if !allowed {
			return FormattedError(step.Pos, rule.RuleName,
				"this action is not in the whitelist and must be replaced manually: %s", usesValue)
		}
	}
	
	return nil
}