package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
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
	if rule.userConfig == nil || len(rule.userConfig.ActionList) == 0 {
		return true, ""
	}

	// ホワイトリストが設定されていて、マッチするなら許可
	for _, pattern := range rule.userConfig.ActionList {
		if matchActionPattern(actionRef, pattern) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("action '%s' is not in the whitelist", actionRef)
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

// ここにVisitJobPre, VisitJobPost, VisitWorkflowPre, VisitWorkflowPostを実装
func (rule *ActionList) VisitJobPre(node *ast.Job) error {
	var currentFixTargetSteps []*ast.Step
	for _, step := range node.Steps {
		if action, ok := step.Exec.(*ast.ExecAction); ok {
			usesValue := action.Uses.Value
			allowed, reason := rule.isActionAllowed(usesValue)
			if !allowed {
				rule.Errorf(step.Pos, "%s in step '%s'", reason, step.String())
				currentFixTargetSteps = append(currentFixTargetSteps, step)
			}
		}
	}
	if len(currentFixTargetSteps) > 0 {
		rule.AddAutoFixer(NewFuncFixer("action-list", func() error {
			return rule.fixJob(node, currentFixTargetSteps)
		}))
	}
	return nil
}

// FixStep は非準拠のアクション参照を修正するためのAutoFixer
func (rule *ActionList) fixJob(job *ast.Job, steps []*ast.Step) error {
	for i, node := range job.BaseNode.Content {
		if node.Value == "steps" {
			seqNode := job.BaseNode.Content[i+1]
			var newContent []*yaml.Node
		OUTER:
			for _, step := range seqNode.Content {
				for _, targetStep := range steps {
					if step == targetStep.BaseNode {
						continue OUTER // 修正対象のステップはスキップ
					}
				}
				newContent = append(newContent, step)
			}
			seqNode.Content = newContent
		}
	}
	return nil
}
