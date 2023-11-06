package expressions

import "fmt"

// ExprErrorは、式の構文の字句解析/構文解析によって引き起こされるエラーを表します。
// https://docs.github.com/ja/actions/learn-github-actions/expressions
type ExprError struct {
	// Messageはエラーメッセージです。
	Message string
	// Offsetはエラーの原因となったバイトオフセットの位置です。この値は0ベースであることに注意してください。
	Offset int
	// Lineはエラーの原因となった行番号の位置です。この値は1ベースであることに注意してください。
	Line int
	// Columnはエラーの原因となった列番号の位置です。この値は1ベースであることに注意してください。
	Column int
}

// Errorは行、列、オフセット情報を持つエラーメッセージを返します。
func (e *ExprError) Error() string {
	return fmt.Sprintf("Line %d, Column %d (Offset %d): %s", e.Line, e.Column, e.Offset, e.Message)
}

// Stringはエラーメッセージを返します。
func (e *ExprError) String() string {
	return e.Error()
}
