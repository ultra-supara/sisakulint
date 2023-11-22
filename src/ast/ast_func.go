package ast

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ultra-supara/sisakulint/src/expressions"
)

// String は Position の文字列表現を返します。
// 形式は "line:行番号,col:列番号" です。
func (p *Position) String() string {
	return fmt.Sprintf("line:%d,col:%d", p.Line, p.Col)
}

// IsBefore は、現在の位置が他の位置よりも前にあるかどうかを返します。
// 位置が等しい場合、この関数は false を返します。
func (p *Position) IsBefore(other *Position) bool {
	if p.Line < other.Line {
		return true
	}
	if p.Line > other.Line {
		return false
	}
	return p.Col < other.Col
}

// containsExpression は与えられた文字列に "${{" と "}}" が含まれているかをチェックします。
// ただし、"${{" が "}}" よりも先に現れる必要があります。
func containsExpression(s string) bool {
	i := strings.Index(s, "${{")
	return i >= 0 && i < strings.Index(s, "}}")
}

// ContainsExpression は文字列が少なくとも一つの ${{ }} 式を含んでいるかどうかを返します。
func (s *String) ContainsExpression() bool {
	return containsExpression(s.Value)
}

// isExprAssigned は与えられた文字列が "${{" と "}}" で囲まれているかをチェックします。
// これは式が直接割り当てられているかどうかを判断するために使用されます。
// 例: if: ${{ env.foo == '{"foo": {"bar": true}}' }}
// 上記の例では、式全体が割り当てられていますが、JSON文字列内に "}}" が含まれているため、
// strings.Count(s.Value, "}}") == 1 という条件だけでは不十分です。
func IsExprAssigned(s string) bool {
	v := strings.TrimSpace(s)
	return strings.HasPrefix(v, "${{") &&
		strings.HasSuffix(v, "}}") &&
		strings.Count(v, "${{") == 1
}

// IsExpressionAssigned は文字列が単一の式に割り当てられているかどうかを返します。
func (s *String) IsExpressionAssigned() bool {
	return IsExprAssigned(s.Value)
}

// String は Boolに対応する String の文字列表現を返します。
func (b *Bool) String() string {
	if b.Expression != nil {
		return b.Expression.Value
	}
	if b.Value {
		return "true"
	}
	return "false"
}

//* https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#using-filters
// IsEmpty は値を持っていない場合にtrueを返します。これはWebhookEventFilterインスタンス自体がnilである可能性もあります。
func (f *WebhookEventFilter) IsEmpty() bool {
	return f == nil || len(f.Values) == 0
}


//* https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onevent_nametypes
// EventName はこのワークフローをトリガーするイベントの名前を返します。
func (e *WebhookEvent) EventName() string {
	return e.Hook.Value
}

//* https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#scheduled-events
// EventName はこのワークフローをトリガーするイベントの名前を返します。
func (e *ScheduledEvent) EventName() string {
	return "schedule"
}

//* https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch
// EventName はこのワークフローをトリガーするイベントの名前を返します。
func (e *WorkflowDispatchEvent) EventName() string {
	return "workflow_dispatch"
}

//* https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#repository_dispatch
// EventName はこのワークフローをトリガーするイベントの名前を返します。
func (e *RepositoryDispatchEvent) EventName() string {
	return "repository_dispatch"
}

//* https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_callinputs
// IsRequired は入力が必須としてマークされているかどうかを返します。
func (i *WorkflowCallEventInput) IsRequired() bool {
	return i.Required != nil && i.Required.Value
}

//* https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow-reuse-events
// EventName はこのワークフローをトリガーするイベントの名前を返します。
func (e *WorkflowCallEvent) EventName() string {
	return "workflow_call"
}

//* https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsrun
// Kind はステップ実行の種類を返します。
func (e *ExecRun) Kind() ExecKind {
	return ExecKindRun
}

//* https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsuses
// Kind はステップの実行種別を返します。この場合はアクション実行を意味します。
func (e *ExecAction) Kind() ExecKind {
	return ExecKindAction
}

// Kind は生のYAML値の種類を返します。この場合、オブジェクトを意味します。
func (o *RawYAMLObject) Kind() RawYAMLValueKind {
	return RawYAMLValueKindObject
}

// Equals は他の値と等しいかどうかを返します。
func (o *RawYAMLObject) Equals(other RawYAMLValue) bool {
	otherObj, ok := other.(*RawYAMLObject)
	if !ok {
		return false
	}
	for n, p1 := range o.Props {
		p2, ok := otherObj.Props[n]
		if !ok || !p1.Equals(p2) {
			return false
		}
	}
	return true
}

// Pos はソースファイル内の値の開始位置を返します。
func (o *RawYAMLObject) Pos() *Position {
	return o.Posi
}

// String は値の文字列表現を返します。
func (o *RawYAMLObject) String() string {
	qs := make([]string, 0, len(o.Props))
	for n, p := range o.Props {
		qs = append(qs, fmt.Sprintf("%q: %s", n, p.String()))
	}
	sort.Strings(qs)
	return "{" + strings.Join(qs, ", ") + "}"
}

// Kind は生のYAML値の種類を返します。この場合、配列を意味します。
func (a *RawYAMLArray) Kind() RawYAMLValueKind {
	return RawYAMLValueKindArray
}

// Equals は他の値と等しいかどうかを返します。
func (a *RawYAMLArray) Equals(other RawYAMLValue) bool {
	otherArr, ok := other.(*RawYAMLArray)
	if !ok || len(a.Elems) != len(otherArr.Elems) {
		return false
	}
	for i, e1 := range a.Elems {
		if !e1.Equals(otherArr.Elems[i]) {
			return false
		}
	}
	return true
}

// Pos はソースファイル内の値の開始位置を返します。
func (a *RawYAMLArray) Pos() *Position {
	return a.Posi
}

// String は値の文字列表現を返します。
func (a *RawYAMLArray) String() string {
	var b expressions.QuotesBuilder
	b.Inner.WriteRune('[')
	for _, v := range a.Elems {
		b.Append(v.String())
	}
	b.Inner.WriteRune(']')
	return b.Build()
}

// Kind は生のYAML値の種類を返します。この場合、文字列を意味します。
func (s *RawYAMLString) Kind() RawYAMLValueKind {
	return RawYAMLValueKindString
}

// Equals は他の値と等しいかどうかを返します。
func (s *RawYAMLString) Equals(other RawYAMLValue) bool {
	otherStr, ok := other.(*RawYAMLString)
	return ok && s.Value == otherStr.Value
}

// Pos はソースファイル内の値の開始位置を返します。
func (s *RawYAMLString) Pos() *Position {
	return s.Posi
}

// String は値の文字列表現を返します。
func (s *RawYAMLString) String() string {
	return strconv.Quote(s.Value)
}

// ContainsExpression は組み合わせセクションに少なくとも一つの式ノードが含まれているかどうかを返します。
func (cs *MatrixCombinations) ContainsExpression() bool {
	if cs.Expression != nil {
		return true
	}
	for _, c := range cs.Combinations {
		if c.Expression != nil {
			return true
		}
	}
	return false
}

// FindWorkflowCallEvent : workflow_call event nodeがあった場合そのノードを返す
func (w *Workflow) FindWorkflowCallEvent() (*WorkflowCallEvent, bool) {
	for _, e := range w.On {
		if e, ok := e.(*WorkflowCallEvent); ok {
			return e, true
		}
	}
	return nil, false
}
