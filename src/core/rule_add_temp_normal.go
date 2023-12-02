// TODO: Rule!
// build対象外のテンプレートファイル
package core

import (
	"github.com/ultra-supara/sisakulint/src/ast"
)

type AddRule struct {
	BaseRule
	//todo:必要に応じてここにルールを追加してください
}

// ConditionalRule は 新しいConditionalRuleを作ります
func NewAddRule() *AddRule {
	return &AddRule{
		BaseRule: BaseRule{
			RuleName: "add",
			RuleDesc: "?",
		},
	}
}

// VisitStep is callback when visiting Step node.
func (rule *AddRule) VisitStep(n *ast.Step) error {
	//todo:ここに実装を追加してください
	return nil
}

//VisitJobPre is called before visiting a job children
func (rule *AddRule) VisitJobPre(n *ast.Job) error {
	//todo:ここに実装を追加してください
	return nil
}

//VisitJobPost is called after visiting a job children
func (rule *AddRule) VisitJobPost(n *ast.Job) error {
	//todo:ここに実装を追加してください
	return nil
}

//todo : validateの関数を実装してください
