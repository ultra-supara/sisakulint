package expressions

import (
	"fmt"
	"strconv"
	"strings"
)

// MiniParser is a simple parser for a subset of the expression language.
func errorpositionToken(t *Token, msg string) *ExprError {
	return &ExprError{
		Message: msg,
		Offset:  t.Offset,
		Line:    t.Line,
		Column:  t.Column,
	}
}

//MiniParser is a simple parser for expression syntax.
//* https://docs.github.com/en/actions/learn-github-actions/expressions

type MiniParser struct {
	cur       *Token
	tokenizer *Tokenizer
	err       *ExprError
}

// NewMiniParser creates a new MiniParser.
func NewMiniParser() *MiniParser {
	return &MiniParser{}
}

// error creates a new error.
func (p *MiniParser) error(msg string) {
	if p.err == nil {
		p.err = errorpositionToken(p.cur, msg)
	}
}

// errorf creates a new error with a formatted message.
func (p *MiniParser) errorf(format string, args ...interface{}) {
	p.error(fmt.Sprintf(format, args...))
}

// unexpected creates a new error for an unexpected token.
func (p *MiniParser) unexpected(where string, expected []TokenKind) {
	if p.err != nil {
		return
	}
	qb := QuotesBuilder{}
	for _, k := range expected {
		qb.Append(k.String())
	}
	var what string
	if p.cur.Kind == TokenKindEnd {
		what = "end of expression"
	} else {
		what = fmt.Sprintf("token %q", p.cur.Kind.String())
	}
	msg := fmt.Sprintf("unexpected %s, while parsing %s, expected %s", what, where, qb.Build())
	p.error(msg)
}

// next advances the parser to the next token.
func (p *MiniParser) next() *Token {
	ret := p.cur
	p.cur = p.tokenizer.AnalyzeToken()
	return ret
}

// peek returns the next token without advancing the parser.
func (p *MiniParser) peek() *Token {
	return p.cur
}

// the given expressionのparse.
func (p *MiniParser) parsing() ExprNode {
	ident := p.next() // identを取得
	switch p.peek().Kind {
	case TokenKindLeftParen:
		// 一般的には関数呼び出しは後置式として解析されますが、ここでは主要な式として関数呼び出しを解析します。
		// その理由は、ワークフロー式の構文において許可されるのは組み込み関数の呼び出しのみであり、
		// 呼び出し対象は常に組み込み関数の名前で、一般的な式ではないためです。
		p.next() // '(' を取得
		args := []ExprNode{}
		if p.peek().Kind == TokenKindRightParen {
			// 引数なし
			p.next() // ')' を取得
		} else {
		LoopArgs:
			for {
				arg := p.parseOrExpression()
				if arg == nil {
					return nil
				}

				args = append(args, arg)

				switch p.peek().Kind {
				case TokenKindComma:
					p.next() // ',' を取得
					// 次の引数に進む
				case TokenKindRightParen:
					p.next() // ')' を取得
					break LoopArgs
				default:
					p.unexpected("arguments of function call", []TokenKind{TokenKindComma, TokenKindRightParen})
					return nil
				}
			}
		}
		return &FuncCallNode{ident.Value, args, ident}
	default:
		//todo:キーワードを処理する。
		//キーワードは大文字と小文字が区別されることに注意。TRUE, FALSE, NULL は無効
		switch ident.Value {
		case "null":
			return &NullNode{ident}
		case "true":
			return &BoolNode{true, ident}
		case "false":
			return &BoolNode{false, ident}
		default:
			// 変数名のアクセスは大文字と小文字が区別されない。例 : github.event = GITHUB.event
			return &VariableNode{strings.ToLower(ident.Value), ident}
		}
	}
}

// parseNested
func (p *MiniParser) parseNested() ExprNode {
	p.next() // '(' を取得
	nested := p.parseOrExpression()
	if nested == nil {
		return nil
	}
	if p.peek().Kind == TokenKindRightParen {
		p.next() // ')' を取得
	} else {
		p.unexpected("closing ')' , nested expression (...)", []TokenKind{TokenKindRightParen})
		return nil
	}
	return nested
}

// parseInt parses an integer literal.
func (p *MiniParser) parseInt() ExprNode {
	t := p.peek() // 数値を取得
	ism, err := strconv.ParseInt(t.Value, 0, 32)
	if err != nil {
		p.errorf("invalid integer literal %q: %s", t.Value, err)
		return nil
	}
	p.next() // 数値を取得
	return &IntNode{int(ism), t}
}

// floating-point literalのparse.
func (p *MiniParser) parseFloat() ExprNode {
	t := p.peek() // 数値を取得
	f, err := strconv.ParseFloat(t.Value, 64)
	if err != nil {
		p.errorf("invalid floating-point literal %q: %s", t.Value, err)
		return nil
	}
	p.next() // 数値を取得
	return &FloatNode{f, t}
}

// string literalのparse.
func (p *MiniParser) parseString() ExprNode {
	t := p.next() // 文字列を取得
	// Note: we're removing the ineffectual assignment
	// s := t.Value[1 : len(t.Value)-1]
	// s = strings.ReplaceAll(s, `\"`, `"`)
	return &StringNode{t.Value, t}
}

// OR expressionのparse.
func (p *MiniParser) parseOrExpression() ExprNode {
	l := p.parseAndExpression()
	if l == nil {
		return nil
	}
	if p.peek().Kind != TokenKindOr {
		return l
	}
	p.next() // '||' を取得
	r := p.parseOrExpression()
	if r == nil {
		return nil
	}
	return &LogicalOpNode{LogicalOpNodeKindOr, l, r}
}

// AND expressionのparse.
func (p *MiniParser) parseAndExpression() ExprNode {
	l := p.parseComparisonOperator()
	if l == nil {
		return nil
	}
	if p.peek().Kind != TokenKindAnd {
		return l
	}
	p.next() // '&&' を取得
	r := p.parseAndExpression()
	if r == nil {
		return nil
	}
	return &LogicalOpNode{LogicalOpNodeKindAnd, l, r}
}

func (p *MiniParser) parsePrefixOperator() ExprNode {
	currentToken := p.peek()
	if currentToken.Kind != TokenKindNot {
		return p.parsePostfixOperator()
	}
	p.next() // consume '!' token

	operand := p.parsePrefixOperator()
	if operand == nil {
		return nil
	}

	return &NotOpNode{operand, currentToken}
}

func (p *MiniParser) parsePrimaryExpression() ExprNode {
	// 次のトークンに応じて適切な解析関数を呼び出す
	switch p.peek().Kind {
	case TokenKindIdent:
		return p.parsing()
	case TokenKindLeftParen:
		return p.parseNested()
	case TokenKindInt:
		return p.parseInt()
	case TokenKindFloat:
		return p.parseFloat()
	case TokenKindString:
		return p.parseString()
	default:
		p.unexpected(
			"variable access, function call, null, bool, int, float or string",
			[]TokenKind{
				TokenKindIdent,
				TokenKindLeftParen,
				TokenKindInt,
				TokenKindFloat,
				TokenKindString,
			},
		)
		return nil
	}
}

func (p *MiniParser) parsePostfixOperator() ExprNode {
	result := p.parsePrimaryExpression()
	if result == nil {
		return nil
	}

	for {
		currentToken := p.peek()
		switch currentToken.Kind {
		case TokenKindDot:
			p.next() // consume '.'
			switch p.peek().Kind {
			case TokenKindStar:
				p.next() // consume '*'
				result = &ArrayDerefNode{result}
			case TokenKindIdent:
				identifierToken := p.next() // consume the identifier after the '.'
				// Property names are case insensitive. For example, github.event and github.EVENT are equivalent.
				result = &ObjectDerefNode{result, strings.ToLower(identifierToken.Value)}
			default:
				p.unexpected(
					"expected an object property dereference (like 'a.b') or an array element dereference (like 'a.*')",
					[]TokenKind{TokenKindIdent, TokenKindStar},
				)
				return nil
			}
		case TokenKindLeftBracket:
			p.next() // consume '['
			index := p.parseOrExpression()
			if index == nil {
				return nil
			}
			result = &IndexAccessNode{result, index}
			if p.peek().Kind != TokenKindRightBracket {
				p.unexpected("expected a closing bracket ']' for index access", []TokenKind{TokenKindRightBracket})
				return nil
			}
			p.next() // consume ']'
		default:
			return result
		}
	}
}

func (p *MiniParser) parseComparisonOperator() ExprNode {
	leftOperand := p.parsePrefixOperator()
	if leftOperand == nil {
		return nil
	}

	var operatorType CompareOpNodeKind
	switch p.peek().Kind {
	case TokenKindLess:
		operatorType = CompareOpNodeKindLess
	case TokenKindLessEq:
		operatorType = CompareOpNodeKindLessEq
	case TokenKindGreater:
		operatorType = CompareOpNodeKindGreater
	case TokenKindGreaterEq:
		operatorType = CompareOpNodeKindGreaterEq
	case TokenKindEq:
		operatorType = CompareOpNodeKindEq
	case TokenKindNotEq:
		operatorType = CompareOpNodeKindNotEq
	default:
		return leftOperand
	}
	p.next() // consume the operator token

	rightOperand := p.parseComparisonOperator()
	if rightOperand == nil {
		return nil
	}

	return &CompareOpNode{operatorType, leftOperand, rightOperand}
}

// Error returns the error, if any.
func (p *MiniParser) Error() *ExprError {
	if err := p.tokenizer.GetError(); err != nil {
		return err
	}
	return p.err
}

// Parse parses the given expression.
func (p *MiniParser) Parse(l *Tokenizer) (ExprNode, *ExprError) {
	//todo:初期化
	p.err = nil
	p.tokenizer = l
	p.cur = l.AnalyzeToken()

	root := p.parseOrExpression()
	if err := p.Error(); err != nil {
		return nil, err
	}

	// トークンのシーケンスの終端に到達しているかを確認します。
	if t := p.peek(); t.Kind != TokenKindEnd {
		// まだ残っているトークンをリストアップ
		remainingTokens := []string{t.Kind.String()}

		for {
			t = p.tokenizer.AnalyzeToken()
			if t.Kind == TokenKindEnd {
				break
			}
			remainingTokens = append(remainingTokens, t.Kind.String())
		}

		// エラーメッセージを作成して報告します。
		tokenList := strings.Join(remainingTokens, ", ")
		p.errorf("Parser did not consume the entire input. %d token(s) remain: %s", len(remainingTokens), tokenList)
		return nil, p.err
	}
	return root, nil
}
