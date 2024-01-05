package expressions

// Tokenは式の構文から字句解析されたトークン
// * https://docs.github.com/en/actions/learn-github-actions/expressions
type Token struct {
	Kind   TokenKind // トークンの種類です。
	Value  string    // トークンの文字列表現です。
	Offset int       // トークン文字列の開始のバイトオフセットです。 この値は0から始まります。
	Line   int       // トークンの開始位置の行番号です。この値は1から始まります。
	Column int       // トークンの開始位置の列番号です。この値は1から始まります。
}

// ExprNode は式の構文木のノードです。構文については以下を参照してください。
// * https://docs.github.com/en/actions/learn-github-actions/expressions
type ExprNode interface {
	// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
	Token() *Token
}

// VariableNode は変数アクセスのためのノードです。
type VariableNode struct {
	// Name は変数の名前です
	Name string
	tok  *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *VariableNode) Token() *Token {
	return n.tok
}

// NullNode は null リテラルのためのノードです。
type NullNode struct {
	tok *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *NullNode) Token() *Token {
	return n.tok
}

// BoolNode はブールリテラル（true または false）のためのノードです。
type BoolNode struct {
	// Value はブールリテラルの値です。
	Value bool
	tok   *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *BoolNode) Token() *Token {
	return n.tok
}

// IntNode は整数リテラルのためのノードです。
type IntNode struct {
	// Value は整数リテラルの値です。
	Value int
	tok   *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *IntNode) Token() *Token {
	return n.tok
}

// FloatNode は浮動小数点リテラルのためのノードです。
type FloatNode struct {
	// Value は浮動小数点リテラルの値です。
	Value float64
	tok   *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *FloatNode) Token() *Token {
	return n.tok
}

// StringNode は文字列リテラルのためのノードです。
type StringNode struct {
	// Value は文字列リテラルの値です。エスケープは解決され、両端の引用符は削除されます。
	Value string
	tok   *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *StringNode) Token() *Token {
	return n.tok
}

// 演算子

// ObjectDerefNode はオブジェクトのプロパティ参照を表します。例えば 'foo.bar' のような。
type ObjectDerefNode struct {
	// Receiver はプロパティ参照の受信側の式です。
	Receiver ExprNode
	// Property はアクセスするプロパティの名前です。
	Property string
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n ObjectDerefNode) Token() *Token {
	return n.Receiver.Token()
}

// ArrayDerefNode は配列の要素参照を表します。例えば 'foo.bar.*.piyo' の '*' のような。
type ArrayDerefNode struct {
	// Receiver は配列要素参照の受信側の式です。
	Receiver ExprNode
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n ArrayDerefNode) Token() *Token {
	return n.Receiver.Token()
}

// IndexAccessNode はインデックスアクセスのためのノードで、動的なオブジェクトプロパティアクセスや
// 配列インデックスアクセスを表します。
type IndexAccessNode struct {
	// Operand はインデックスアクセスのオペランドの式で、配列またはオブジェクトであるべきです。
	Operand ExprNode
	// Index はインデックスの式で、整数または文字列であるべきです。
	Index ExprNode
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *IndexAccessNode) Token() *Token {
	return n.Operand.Token()
}

// 注：現在 ! は論理単項演算子としてのみ使用されます

// NotOpNode は単項 ! 演算子のためのノードです。
type NotOpNode struct {
	// Operand は ! 演算子のオペランドの式です。
	Operand ExprNode
	tok     *Token
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *NotOpNode) Token() *Token {
	return n.tok
}

// CompareOpNodeKind は比較演算子の種類です；==, !=, <, <=, >, >=。
type CompareOpNodeKind int

const (
	// CompareOpNodeKindInvalid は無効で CompareOpNodeKind の初期値です。
	CompareOpNodeKindInvalid CompareOpNodeKind = iota
	// CompareOpNodeKindLess は < 演算子の種類です。
	CompareOpNodeKindLess
	// CompareOpNodeKindLessEq は <= 演算子の種類です。
	CompareOpNodeKindLessEq
	// CompareOpNodeKindGreater は > 演算子の種類です。
	CompareOpNodeKindGreater
	// CompareOpNodeKindGreaterEq は >= 演算子の種類です。
	CompareOpNodeKindGreaterEq
	// CompareOpNodeKindEq は == 演算子の種類です。
	CompareOpNodeKindEq
	// CompareOpNodeKindNotEq は != 演算子の種類です。
	CompareOpNodeKindNotEq
)

// CompareOpNode は二項式の比較演算子のためのノードです；==, !=, <, <=, >, >=。
type CompareOpNode struct {
	// Kind はこの式の種類で、どの演算子が使用されているかを示します。
	Kind CompareOpNodeKind
	// Left は二項演算子の左側の式です。
	Left ExprNode
	// Right は二項演算子の右側の式です。
	Right ExprNode
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *CompareOpNode) Token() *Token {
	return n.Left.Token()
}

// LogicalOpNodeKind は論理演算子の種類です；&& と ||。
type LogicalOpNodeKind int

const (
	// LogicalOpNodeKindInvalid は無効で LogicalOpNodeKind の初期値です。
	LogicalOpNodeKindInvalid LogicalOpNodeKind = iota
	// LogicalOpNodeKindAnd は && 演算子の種類です。
	LogicalOpNodeKindAnd
	// LogicalOpNodeKindOr は || 演算子の種類です。
	LogicalOpNodeKindOr
)

func (k LogicalOpNodeKind) String() string {
	switch k {
	case LogicalOpNodeKindAnd:
		return "&&"
	case LogicalOpNodeKindOr:
		return "||"
	default:
		return "invalid"
	}
}

// LogicalOpNode は論理的な二項演算子のためのノードです；&& または ||。
type LogicalOpNode struct {
	// Kind はどの演算子が使用されているかを示す種類です。
	Kind LogicalOpNodeKind
	// Left は二項演算子の左側の式です。
	Left ExprNode
	// Right は二項演算子の右側の式です。
	Right ExprNode
}

// Token はノードの最初のトークンを返します。このメソッドはノードの位置を取得するのに便利です。
func (n *LogicalOpNode) Token() *Token {
	return n.Left.Token()
}

// FuncCallNode は式内の関数呼び出しを表します。
// 現在、ビルトイン関数の呼び出しのみがサポートされていることに注意してください。
type FuncCallNode struct {
	// Callee は呼び出された関数の名前です。現在ビルトイン関数のみが呼び出せるため、これは文字列値です。
	Callee string
	// Args は関数呼び出しの引数です。
	Args []ExprNode
	tok  *Token
}

// Token はノードの最初のトークンを返します。このメソッドは、このノードの位置を取得するのに役立ちます。
func (n *FuncCallNode) Token() *Token {
	return n.tok
}

// VisitExprNodeFunc は VisitExprNode() のためのビジター関数です。
// entering 引数は、子ノードを訪問する前に呼び出されるときに true に設定されます。
// 子ノードを訪問した後に呼び出されるときは false に設定されます。
// つまり、この関数は同じノードに対して2回呼び出されることを意味します。
// parentは、ノードの親です。ノードがルートの場合、その親は nil です。
type VisitExprNodeFunc func(node, parent ExprNode, entering bool)

func visitExprNode(n, p ExprNode, f VisitExprNodeFunc) {
	f(n, p, true)
	switch n := n.(type) {
	case *ObjectDerefNode:
		visitExprNode(n.Receiver, n, f)
	case *ArrayDerefNode:
		visitExprNode(n.Receiver, n, f)
	case *IndexAccessNode:
		// インデックスは、UntrustedInputChecker が正しく動作するために、オペランドの前に訪問
		visitExprNode(n.Index, n, f)
		visitExprNode(n.Operand, n, f)
	case *NotOpNode:
		visitExprNode(n.Operand, n, f)
	case *CompareOpNode:
		visitExprNode(n.Left, n, f)
		visitExprNode(n.Right, n, f)
	case *LogicalOpNode:
		visitExprNode(n.Left, n, f)
		visitExprNode(n.Right, n, f)
	case *FuncCallNode:
		for _, a := range n.Args {
			visitExprNode(a, n, f)
		}
	}
	f(n, p, false)
}

// VisitExprNode は与えられた式の構文木を指定された関数 f で訪問します。
func VisitExprNode(n ExprNode, f VisitExprNodeFunc) {
	visitExprNode(n, nil, f)
}
