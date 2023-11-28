package expressions

import (
	"sort"
	"strconv"
	"strings"
)

const someThreshold = 1024 // バッファのサイズ閾値を設定

type QuotesBuilder struct {
    Inner strings.Builder
    buf   []byte
    comma bool
}

// Append は文字列を引用符で囲んで追加します。
// 引用符で囲まれた文字列は、カンマで区切られます。
func (builder *QuotesBuilder) Append(s string) {
    // バッファのサイズが閾値を超えた場合は再割り当て
    if len(builder.buf) > someThreshold {
        builder.buf = make([]byte, 0, len(s)+2) // 2は引用符のため
    } else {
        builder.buf = builder.buf[:0]
    }

    // 文字列を引用符で囲む
    builder.buf = strconv.AppendQuote(builder.buf, s)

    // カンマの追加
    if builder.comma {
        builder.Inner.WriteString(", ")
    } else {
        builder.comma = true
    }

    // 結果を内部ビルダーに書き込む
    builder.Inner.Write(builder.buf)
}

// Build は構築された文字列を返します。
func (builder *QuotesBuilder) Build() string {
    return builder.Inner.String()
}

// quotes は文字列のスライスを引用符で囲んだ文字列に変換します。
func quotes(ss []string) string {
    if len(ss) == 0 {
        return ""
    }

    b := QuotesBuilder{
        buf: make([]byte, 0, someThreshold),
    }
    for _, s := range ss {
        b.Append(s)
    }
    return b.Build()
}

// SortedQuotes は文字列のスライスをソートして引用符で囲んだ文字列に変換します。
func SortedQuotes(ss []string) string {
    sort.Strings(ss)
    return quotes(ss)
}

// quotesAll は複数の文字列スライスを引用符で囲んだ文字列に変換します。
func quotesAll(sss ...[]string) string {
    b := QuotesBuilder{
        buf: make([]byte, 0, someThreshold),
    }
    for _, ss := range sss {
        for _, s := range ss {
            b.Append(s)
        }
    }
    return b.Build()
}
