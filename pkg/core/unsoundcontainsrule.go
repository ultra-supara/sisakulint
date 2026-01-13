package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
)

// UnsoundContainsRule は不健全なcontains()関数の使用を検出するルールです。
// contains()関数の第1引数が文字列リテラルで、第2引数がユーザー制御可能な
// コンテキストの場合、攻撃者がブランチ名を操作することで条件をバイパスできる
// 可能性があります。
//
// 脆弱なパターン例:
//
//	if: contains('refs/heads/main refs/heads/develop', github.ref)
//
// 安全なパターン:
//
//	if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
type UnsoundContainsRule struct {
	BaseRule
	currentJob  *ast.Job
	currentStep *ast.Step
}

// NewUnsoundContainsRule は新しいUnsoundContainsRuleインスタンスを作成します。
func NewUnsoundContainsRule() *UnsoundContainsRule {
	return &UnsoundContainsRule{
		BaseRule: BaseRule{
			RuleName: "unsound-contains",
			RuleDesc: "Detects bypassable contains() function usage in conditions",
		},
	}
}

// userControllableContexts はユーザー制御可能なコンテキストのリストです。
var userControllableContexts = map[string]bool{
	"github.actor":             true,
	"github.base_ref":          true,
	"github.head_ref":          true,
	"github.ref":               true,
	"github.ref_name":          true,
	"github.sha":               true,
	"github.triggering_actor":  true,
	"github.event.sender.type": true,
}

// userControllableContextPrefixes はユーザー制御可能なコンテキストのプレフィックスです。
var userControllableContextPrefixes = []string{
	"env.",
	"inputs.",
	"github.event.",
}

// VisitJobPre is called before visiting a job's children.
func (rule *UnsoundContainsRule) VisitJobPre(n *ast.Job) error {
	rule.currentJob = n
	rule.checkCondition(n.If, "job", n, nil)
	return nil
}

// VisitJobPost is called after visiting a job's children.
func (rule *UnsoundContainsRule) VisitJobPost(_ *ast.Job) error {
	rule.currentJob = nil
	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *UnsoundContainsRule) VisitStep(n *ast.Step) error {
	rule.currentStep = n
	rule.checkCondition(n.If, "step", nil, n)
	rule.currentStep = nil
	return nil
}

// checkCondition は条件式内のcontains()関数の使用をチェックします。
func (rule *UnsoundContainsRule) checkCondition(cond *ast.String, context string, job *ast.Job, step *ast.Step) {
	if cond == nil {
		return
	}

	var exprStr string
	if cond.ContainsExpression() {
		// ${{ }} で囲まれた式を抽出
		exprStr = extractExpressionContent(cond.Value)
	} else {
		// if 条件式は ${{ }} を省略できる
		exprStr = cond.Value
	}

	if exprStr == "" {
		return
	}

	// 式をパースしてcontains()関数を検出
	p := expressions.NewMiniParser()
	src := exprStr + "}}"
	l := expressions.NewTokenizer(src)
	expr, err := p.Parse(l)
	if err != nil {
		return
	}

	// contains()関数の呼び出しを検出
	rule.visitExprNode(expr, cond.Pos, context, job, step, cond)
}

// visitExprNode は式ノードを再帰的に訪問してcontains()関数を検出します。
func (rule *UnsoundContainsRule) visitExprNode(node expressions.ExprNode, pos *ast.Position, context string, job *ast.Job, step *ast.Step, condStr *ast.String) {
	expressions.VisitExprNode(node, func(n, _ expressions.ExprNode, entering bool) {
		if !entering {
			return
		}

		funcCall, ok := n.(*expressions.FuncCallNode)
		if !ok {
			return
		}

		// contains関数かチェック（大文字小文字を区別しない）
		if strings.ToLower(funcCall.Callee) != "contains" {
			return
		}

		// 引数が2つあるかチェック
		if len(funcCall.Args) != 2 {
			return
		}

		// 第1引数が文字列リテラルかチェック
		_, isStringLiteral := funcCall.Args[0].(*expressions.StringNode)
		if !isStringLiteral {
			return
		}

		// 第2引数がユーザー制御可能なコンテキストかチェック
		userControlledContext := rule.extractContextPath(funcCall.Args[1])
		if userControlledContext == "" {
			return
		}

		// condStr.Value から実際の文字列リテラルを正規表現で抽出
		// Note: トークナイザーのバグにより StringNode.Value が正しくないため
		stringLitValue := rule.extractStringLiteralFromCondition(condStr.Value, userControlledContext)
		if stringLitValue == "" {
			return
		}

		isHighSeverity := rule.isUserControllableContext(userControlledContext)

		// エラーを報告
		var severity string
		if isHighSeverity {
			severity = "HIGH"
		} else {
			severity = "INFORMATIONAL"
		}

		rule.Errorf(
			pos,
			"[%s] Unsound use of contains() in %s condition. The first argument '%s' is a string literal and the second argument '%s' is user-controllable. An attacker could create a branch named '%s' to bypass this condition. Use fromJSON() with an array instead: contains(fromJSON('%s'), %s)",
			severity,
			context,
			stringLitValue,
			userControlledContext,
			stringLitValue,
			rule.convertToJSONArray(stringLitValue),
			userControlledContext,
		)

		// auto-fixerを追加
		if step != nil {
			fixer := &unsoundContainsStepFixer{
				step:         step,
				rule:         rule,
				stringLit:    stringLitValue,
				contextPath:  userControlledContext,
				originalCond: condStr,
			}
			rule.AddAutoFixer(NewStepFixer(step, fixer))
		} else if job != nil {
			fixer := &unsoundContainsJobFixer{
				job:          job,
				rule:         rule,
				stringLit:    stringLitValue,
				contextPath:  userControlledContext,
				originalCond: condStr,
			}
			rule.AddAutoFixer(NewJobFixer(job, fixer))
		}
	})
}

// extractContextPath は式ノードからコンテキストパスを抽出します。
func (rule *UnsoundContainsRule) extractContextPath(node expressions.ExprNode) string {
	switch n := node.(type) {
	case *expressions.VariableNode:
		return n.Name
	case *expressions.ObjectDerefNode:
		receiver := rule.extractContextPath(n.Receiver)
		if receiver == "" {
			return ""
		}
		return receiver + "." + n.Property
	case *expressions.IndexAccessNode:
		operand := rule.extractContextPath(n.Operand)
		if operand == "" {
			return ""
		}
		// インデックスが文字列リテラルの場合
		if strNode, ok := n.Index.(*expressions.StringNode); ok {
			return operand + "." + strNode.Value
		}
		// 動的なインデックスの場合は[*]として表記
		return operand + "[*]"
	default:
		return ""
	}
}

// extractStringLiteralFromCondition は条件文字列からcontains()の第1引数の文字列リテラルを抽出します。
func (rule *UnsoundContainsRule) extractStringLiteralFromCondition(condValue, contextPath string) string {
	// contains('...',contextPath) または contains("...",contextPath) パターンを検索
	// Note: contextPath は小文字に正規化されているため、大文字小文字を区別しない検索が必要
	escapedContextPath := regexp.QuoteMeta(contextPath)

	// シングルクォートパターン（大文字小文字を区別しない）
	patternSingle := fmt.Sprintf(`(?i)contains\s*\(\s*'([^']*)'\s*,\s*%s\s*\)`, escapedContextPath)
	re := regexp.MustCompile(patternSingle)
	matches := re.FindStringSubmatch(condValue)
	if len(matches) > 1 {
		return matches[1]
	}

	// ダブルクォートパターン（大文字小文字を区別しない）
	patternDouble := fmt.Sprintf(`(?i)contains\s*\(\s*"([^"]*)"\s*,\s*%s\s*\)`, escapedContextPath)
	re = regexp.MustCompile(patternDouble)
	matches = re.FindStringSubmatch(condValue)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// isUserControllableContext はコンテキストがユーザー制御可能かどうかをチェックします。
func (rule *UnsoundContainsRule) isUserControllableContext(contextPath string) bool {
	// 完全一致チェック
	if userControllableContexts[contextPath] {
		return true
	}

	// プレフィックスチェック
	for _, prefix := range userControllableContextPrefixes {
		if strings.HasPrefix(contextPath, prefix) {
			return true
		}
	}

	return false
}

// convertToJSONArray は文字列リテラルをJSON配列に変換します。
func (rule *UnsoundContainsRule) convertToJSONArray(stringLiteral string) string {
	// スペースまたはカンマで区切られた値を配列要素として抽出
	parts := regexp.MustCompile(`[,\s]+`).Split(stringLiteral, -1)

	var elements []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			elements = append(elements, fmt.Sprintf(`"%s"`, part))
		}
	}

	return "[" + strings.Join(elements, ", ") + "]"
}

// extractExpressionContent は${{ }}で囲まれた式から内容を抽出します。
func extractExpressionContent(value string) string {
	// ${{ で始まり }} で終わる式を抽出
	start := strings.Index(value, "${{")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(value, "}}")
	if end == -1 || end <= start {
		return ""
	}
	return strings.TrimSpace(value[start+3 : end])
}

// unsoundContainsStepFixer はStep内のunsound contains()を修正するfixerです。
type unsoundContainsStepFixer struct {
	step         *ast.Step
	rule         *UnsoundContainsRule
	stringLit    string
	contextPath  string
	originalCond *ast.String
}

func (f *unsoundContainsStepFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *unsoundContainsStepFixer) FixStep(_ *ast.Step) error {
	// Use f.step directly since it was captured during rule detection
	if f.step == nil {
		return nil
	}
	if f.step.If == nil {
		return nil
	}
	return f.fixCondition(f.step.If)
}

func (f *unsoundContainsStepFixer) fixCondition(cond *ast.String) error {
	newValue := f.replaceContainsPattern(cond.Value)
	cond.Value = newValue
	cond.BaseNode.Value = newValue
	return nil
}

// replaceContainsPattern は正規表現を使ってcontains()パターンを置換します。
func (f *unsoundContainsStepFixer) replaceContainsPattern(value string) string {
	// 正規表現で空白を考慮したパターンマッチング
	// contains\s*\(\s*['"]<stringLit>['"]\s*,\s*<contextPath>\s*\)
	escapedStringLit := regexp.QuoteMeta(f.stringLit)
	escapedContextPath := regexp.QuoteMeta(f.contextPath)

	// シングルクォートパターン
	patternSingle := fmt.Sprintf(`contains\s*\(\s*'%s'\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)
	// ダブルクォートパターン
	patternDouble := fmt.Sprintf(`contains\s*\(\s*"%s"\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)

	newPattern := fmt.Sprintf("contains(fromJSON('%s'), %s)", f.rule.convertToJSONArray(f.stringLit), f.contextPath)

	re := regexp.MustCompile(patternSingle)
	result := re.ReplaceAllString(value, newPattern)
	if result != value {
		return result
	}

	re = regexp.MustCompile(patternDouble)
	return re.ReplaceAllString(value, newPattern)
}

// unsoundContainsJobFixer はJob内のunsound contains()を修正するfixerです。
type unsoundContainsJobFixer struct {
	job          *ast.Job
	rule         *UnsoundContainsRule
	stringLit    string
	contextPath  string
	originalCond *ast.String
}

func (f *unsoundContainsJobFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *unsoundContainsJobFixer) FixJob(_ *ast.Job) error {
	// Use f.job directly since it was captured during rule detection
	if f.job == nil || f.job.If == nil {
		return nil
	}
	return f.fixCondition(f.job.If)
}

func (f *unsoundContainsJobFixer) fixCondition(cond *ast.String) error {
	newValue := f.replaceContainsPattern(cond.Value)
	cond.Value = newValue
	cond.BaseNode.Value = newValue
	return nil
}

// replaceContainsPattern は正規表現を使ってcontains()パターンを置換します。
func (f *unsoundContainsJobFixer) replaceContainsPattern(value string) string {
	escapedStringLit := regexp.QuoteMeta(f.stringLit)
	escapedContextPath := regexp.QuoteMeta(f.contextPath)

	patternSingle := fmt.Sprintf(`contains\s*\(\s*'%s'\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)
	patternDouble := fmt.Sprintf(`contains\s*\(\s*"%s"\s*,\s*%s\s*\)`, escapedStringLit, escapedContextPath)

	newPattern := fmt.Sprintf("contains(fromJSON('%s'), %s)", f.rule.convertToJSONArray(f.stringLit), f.contextPath)

	re := regexp.MustCompile(patternSingle)
	result := re.ReplaceAllString(value, newPattern)
	if result != value {
		return result
	}

	re = regexp.MustCompile(patternDouble)
	return re.ReplaceAllString(value, newPattern)
}
