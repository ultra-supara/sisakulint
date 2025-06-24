package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// ActionList はアクション参照のホワイトリスト/ブラックリストを実装するルール
type ActionList struct {
	BaseRule
	Config *Config // Configはsisakulint.yamlからの設定へのポインタ
}

// NewActionListRule は新しい ActionList ルールを作成
func NewActionListRule(config *Config) *ActionList {
	return &ActionList{
		BaseRule: BaseRule{
			RuleName: "action-list",
			RuleDesc: "Check if action references are in whitelist or not in blacklist",
		},
		Config: config,
	}
}


// isActionAllowed はアクションがルールに基づいて許可されているかチェック
func (rule *ActionList) isActionAllowed(actionRef string) (bool, string) {
	// 設定がnilまたは空の場合は全て許可
	if rule.Config == nil || 
	   (len(rule.Config.ActionList.WhiteList) == 0 && len(rule.Config.ActionList.BlackList) == 0) {
		return true, ""
	}
	
	// ホワイトリストが設定されていて、マッチするなら許可
	if len(rule.Config.ActionList.WhiteList) > 0 {
		for _, pattern := range rule.Config.ActionList.WhiteList {
			if matchActionPattern(actionRef, pattern) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("action '%s' is not in the whitelist", actionRef)
	}

	// ブラックリストがあり、マッチするなら禁止
	for _, pattern := range rule.Config.ActionList.BlackList {
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
	
	// 設定がnilの場合は何もしない
	if rule.Config == nil {
		return nil
	}

	// ブラックリスト対象のアクションがあるかチェック
	for _, blackPattern := range rule.Config.ActionList.BlackList {
		if !matchActionPattern(usesValue, blackPattern) {
			continue // マッチしなければ次のパターンへ
		}
		
		// ブラックリストされたアクションには自動修正を適用しない
		// 代わりにエラーを返して手動での修正を促す
		return FormattedError(step.Pos, rule.RuleName, 
			"this action is blacklisted and must be replaced manually: %s", usesValue)
	}
	
	// ホワイトリストの場合（ホワイトリストに無いアクションが使われている場合）
	if len(rule.Config.ActionList.WhiteList) > 0 {
		// ホワイトリストにマッチするか確認
		allowed := false
		for _, whitePattern := range rule.Config.ActionList.WhiteList {
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