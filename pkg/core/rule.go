// TODO: Rule!
package core

import (
	"fmt"
	"io"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// BaseRuleはruleの基本構造体
type BaseRule struct {
	RuleName   string
	RuleDesc   string
	ruleErrors []*LintingError
	debugOut   io.Writer
	userConfig *Config
}

// CreateBaseRuleは新しいBaseRuleのインスタンスを作成する
func CreateBaseRule(name string, desc string) BaseRule {
	return BaseRule{RuleName: name, RuleDesc: desc}
}

// Errorはソースの位置とエラーメッセージから新しいエラーを作成してrule instanceに追加する
func (rule *BaseRule) Error(position *ast.Position, msg string) {
	err := NewError(position, rule.RuleName, msg)
	rule.ruleErrors = append(rule.ruleErrors, err)
}

// Errorf
func (rule *BaseRule) Errorf(position *ast.Position, format string, args ...interface{}) {
	err := FormattedError(position, rule.RuleName, format, args...)
	rule.ruleErrors = append(rule.ruleErrors, err)
}

// Debugはルールからのdebug logを出力
// Enable メソッドの引数によって指定されたio.Writerインスタンスはデバッグ情報をコンソール上に出力するために使用される
func (rule *BaseRule) Debug(format string, args ...interface{}) {
	if rule.debugOut != nil {
		return
	}
	debugMsg := fmt.Sprintf("[%s] %s\n", rule.RuleName, format)
	fmt.Fprintf(rule.debugOut, debugMsg, args...)
}

// メソッド
func (rule *BaseRule) Errors() []*LintingError {
	return rule.ruleErrors
}

func (rule *BaseRule) RuleNames() string {
	return rule.RuleName
}

func (rule *BaseRule) RuleDescription() string {
	return rule.RuleDesc
}

func (rule *BaseRule) EnableDebugOutput(out io.Writer) {
	rule.debugOut = out
}

func (rule *BaseRule) UpdateConfig(config *Config) {
	rule.userConfig = config
}

// rule structs meet the Rule interface
type Rule interface {
	TreeVisitor
	Errors() []*LintingError
	RuleNames() string
	RuleDescription() string
	EnableDebugOutput(out io.Writer)
	UpdateConfig(config *Config)
}
