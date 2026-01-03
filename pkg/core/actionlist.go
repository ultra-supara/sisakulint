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
}

// NewActionListRule は新しい ActionList ルールを作成
func NewActionListRule() *ActionList {
	return &ActionList{
		BaseRule: BaseRule{
			RuleName: "action-list",
			RuleDesc: "Check if action references are in whitelist or not in blacklist",
		},
	}
}

// isActionAllowed はアクションがルールに基づいて許可されているかチェック
func (rule *ActionList) isActionAllowed(actionRef string) (bool, string) {
	// 設定がnilまたは空の場合は全て許可
	if rule.userConfig == nil || len(rule.userConfig.actionListRegex) == 0 {
		return true, ""
	}

	// ホワイトリストが設定されていて、マッチするなら許可
	for _, pattern := range rule.userConfig.actionListRegex {
		if pattern.MatchString(actionRef) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("action '%s' is not in the whitelist", actionRef)
}

// matchActionPattern はアクション参照がパターンにマッチするかチェック
// パターン例: "actions/checkout@*", "actions/*@v2", "owner/repo@v1.*"
func compileActionPattern(pattern string) (*regexp.Regexp, error) {
	// ワイルドカードをエスケープしてから特定の場所に適用する正規表現に変換
	regexPattern := strings.ReplaceAll(regexp.QuoteMeta(pattern), "\\*", ".*")
	re, err := regexp.Compile("^" + regexPattern + "$")
	if err != nil {
		return nil, err
	}
	return re, nil
}

// VisitJobPre checks if actions used in job steps are allowed
func (rule *ActionList) VisitJobPre(node *ast.Job) error {
	for _, step := range node.Steps {
		if action, ok := step.Exec.(*ast.ExecAction); ok {
			usesValue := action.Uses.Value
			allowed, reason := rule.isActionAllowed(usesValue)
			if !allowed {
				rule.Errorf(step.Pos, "%s in step '%s'", reason, step.String())
			}
		}
	}
	return nil
}
