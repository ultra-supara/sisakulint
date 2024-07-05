package expressions

import (
	"strings"
)

// UntiCheckerは、式構文木内の信頼できない入力を検出するためのチェッカーです。
// このチェッカーは、オブジェクトプロパティアクセス、配列インデックスアクセス、およびオブジェクトフィルターを信頼できない入力に対してチェックします。
// 信頼できない入力へのパスを検出し、このインスタンスで見つかったエラーを保存します。これらのエラーは、Errsメソッドを介して取得できます。
type UntiChecker struct {
	roots           ContextPropertySearchRoots // 信頼できない入力パスを定義する検索ツリー
	filteringObject bool                       // 現在のノードがオブジェクトフィルターであるかどうか
	cur             []*ContextPropertyMap      // 現在のノードの信頼できない入力マップ
	start           ExprNode                   // 現在の式の開始ノード
	errs            []*ExprError               // 現在の式で見つかったエラー
}

// NewUntiCheckerは、新しいUntiCheckerインスタンスを作成します。
// roots引数は、検索ツリー内の信頼できない入力パスを定義します。
func NewUntiChecker(roots ContextPropertySearchRoots) *UntiChecker {
	return &UntiChecker{
		roots:           roots,
		filteringObject: false,
		cur:             nil,
		start:           nil,
		errs:            []*ExprError{},
	}
}

// resetは、次の検索のために状態をリセットします。
func (u *UntiChecker) reset() {
	u.start = nil
	u.filteringObject = false
	u.cur = u.cur[:0]
}

// compactは、現在のノードの信頼できない入力マップをコンパクトにし、nil値を削除します。
func (u *UntiChecker) compact() {
	delta := 0
	for i, c := range u.cur {
		if c == nil {
			delta++
			continue
		}
		if delta > 0 {
			u.cur[i-delta] = c
		}
	}
	u.cur = u.cur[:len(u.cur)-delta]
}

// onVarは、変数ノードが訪問されたときに呼び出されます。
// ルートコンテキスト（現在は "github" のみ）を見つけ、現在のノードの信頼できない入力マップに追加します。
func (u *UntiChecker) onVar(v *VariableNode) {
	c, ok := u.roots[v.Name]
	if !ok {
		return
	}
	u.start = v
	u.cur = append(u.cur, c)
}

// onPropAccessは、プロパティアクセスノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップ内で指定された名前のオブジェクトプロパティを見つけます。
// プロパティが見つからない場合、現在のノードの信頼できない入力マップをnilに設定します。
func (u *UntiChecker) onPropAccess(name string) {
	compact := false
	for i, cur := range u.cur {
		c, ok := cur.findObjectProp(name)
		if !ok {
			u.cur[i] = nil
			compact = true
			continue
		}
		u.cur[i] = c // depth + 1
	}
	if compact {
		u.compact()
	}
}

// onIndexAccessは、インデックスアクセスノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップ内で配列要素を見つけます。
// 要素が見つからない場合、現在のノードの信頼できない入力マップをnilに設定します。
func (u *UntiChecker) onIndexAccess() {
	if u.filteringObject {
		u.filteringObject = false
		return // 例えば、`github.event.*.body[0]`を`github.event.commits[0].body`としてマッチさせる
	}

	compact := false
	for i, cur := range u.cur {
		if c, ok := cur.findArrayElem(); ok {
			u.cur[i] = c
			continue
		}
		u.cur[i] = nil
		compact = true
	}
	if compact {
		u.compact()
	}
}

// onObjectFilterは、オブジェクトフィルターノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップをオブジェクトフィルターの子に設定します。
// 現在のノードの信頼できない入力マップが空の場合、それをnilに設定します。
func (u *UntiChecker) onObjectFilter() {
	u.filteringObject = true

	compact := false
	for i, cur := range u.cur {
		// 配列のオブジェクトフィルター
		if c, ok := cur.findArrayElem(); ok {
			u.cur[i] = c
			continue
		}

		if len(cur.Children) == 0 {
			u.cur[i] = nil
			compact = true
		}

		// オブジェクトのオブジェクトフィルター
		first := true
		for _, c := range cur.Children {
			if first {
				u.cur[i] = c
				first = false
			} else {
				u.cur = append(u.cur, c)
			}
		}
	}
	if compact {
		u.compact()
	}
}

// endは、ノードの訪問が終了したときに呼び出されます。
// 現在のノードの信頼できない入力マップで見つかった信頼できない入力へのパスを構築します。
// 1つの信頼できない入力のみが見つかった場合、その入力に対してエラーを追加します。
// 複数の信頼できない入力が見つかった場合、それらすべてに対してエラーを追加します。
func (u *UntiChecker) end() {
	var inputs []string
	for _, cur := range u.cur {
		if cur.Children != nil {
			continue // `Children`がnilの場合、ノードは葉です
		}
		var b strings.Builder
		cur.buildPath(&b)
		inputs = append(inputs, b.String())
	}

	if len(inputs) == 1 {
		err := errorfAtExpr(
			u.start,
			"%q is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
			inputs[0],
		)
		u.errs = append(u.errs, err)
	} else if len(inputs) > 1 {
		// 複数の信頼できない入力が検出された場合、式がオブジェクトフィルター構文で複数のプロパティを抽出していることを意味します。エラーメッセージにすべてのプロパティを表示します。
		err := errorfAtExpr(
			u.start,
			"Object filter extracts potentially untrusted properties %s. Avoid using the value directly in inline scripts. Instead, pass the value through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
			SortedQuotes(inputs),
		)
		u.errs = append(u.errs, err)
	}

	u.reset()
}

// OnVisitNodeLeaveは、子ノードの訪問後にノードを訪問する際に呼び出されるべきコールバックです。
// 訪問されたノードのタイプに応じて適切なメソッドを呼び出します。
func (u *UntiChecker) OnVisitNodeLeave(n ExprNode) {
	switch n := n.(type) {
	case *VariableNode:
		u.end()
		u.onVar(n)
	case *ObjectDerefNode:
		u.onPropAccess(n.Property)
	case *IndexAccessNode:
		if lit, ok := n.Index.(*StringNode); ok {
			// 特別なケース、例えばgithub['event']['issue']['title']
			u.onPropAccess(lit.Value)
			break
		}
		u.onIndexAccess()
	case *ArrayDerefNode:
		u.onObjectFilter()
	default:
		u.end()
	}
}

// OnVisitEndは、構文木全体の訪問後に呼び出されるべきコールバックです。
// このコールバックは、式のルートに信頼できない入力アクセスがある場合を処理するために必要です。
func (u *UntiChecker) OnVisitEnd() {
	u.end()
}

// Errsは、このチェッカーによって検出されたエラーを返します。
// このメソッドは、構文木のすべてのノードを訪問した後
func (u *UntiChecker) Errs() []*ExprError {
	return u.errs
}

// Init initializes a state of checker.
func (u *UntiChecker) Init() {
	u.errs = u.errs[:0]
	u.reset()
}
