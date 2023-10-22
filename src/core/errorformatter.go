package core

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/mattn/go-runewidth"
	"github.com/ultra-supara/sisakulint/src/ast"
)

//コンソール出力時における色付けのための定数
var (
	BoldStyle = color.New(color.Bold)
	GreenStyle = color.New(color.FgGreen)
	YellowStyle = color.New(color.FgYellow)
	GrayStyle = color.New(color.FgHiBlack)
)

//LintingErrorはsisakulintにおけるlinting errorの詳細を表す構造体
type LintingError struct {
	//LintingErrorの種類
	Description string
	//LintingErrorが発生したファイルのパス
	FilePath string
	//LintingErrorが発生した行番号
	LineNumber int
	//LintingErrorが発生した列番号
	ColNumber int
	//LintingErrorが発生した行の内容
	Type string
}

func (e *LintingError) Error() string {
	return fmt.Sprintf("%s:%d:%d: %s [%s]", e.FilePath, e.LineNumber, e.ColNumber, e.Description, e.Type)
}

func (e *LintingError) String() string {
	return e.Error()
}

func NewError(position *ast.Position, errorType string, message string) *LintingError {
	return &LintingError{
		Description: message,
		LineNumber: position.Line,
		ColNumber: position.Col,
		Type: errorType,
	}
}

func FormattedError(position *ast.Position, errorType string, format string, args ...interface{}) *LintingError {
	return &LintingError{
		Description: fmt.Sprintf(format, args...),
		LineNumber: position.Line,
		ColNumber: position.Col,
		Type: errorType,
	}
}

//ExtractTemplateFieldsはLintingErrorからテンプレートの生成に必要なフィールドを抽出する
func (e *LintingError) ExtractTemplateFields(sourceContent []byte) *TemplateFields {
	codeSnippet := ""
	endingColumn := e.ColNumber

	if len(sourceContent) > 0 && e.LineNumber > 0 {
		if lineContent, found := e.extractLineContent(sourceContent); found {
			codeSnippet = lineContent
			if len(lineContent) < e.ColNumber - 1 {
				if indicator := e.determineIndicator(lineContent); indicator != "" {
					codeSnippet +=  "\n" + indicator
					endingColumn = len(indicator)
				}
			}
		}
	}
	return &TemplateFields{
		Message : e.Description,
		Filepath: e.FilePath,
		Line: e.LineNumber,
		Column: e.ColNumber,
		Type: e.Type,
		Snippet: codeSnippet,
		EndColumn: endingColumn,
	}
}

type RuleTemplateField struct {
	Name string
	Description string
}

type ByRuleTemplateField []*RuleTemplateField

func (a ByRuleTemplateField) Len() int {
	return len(a)
}

func (a ByRuleTemplateField) Less(i, j int) bool {
	return strings.Compare(a[i].Name, a[j].Name) < 0
}

func (a ByRuleTemplateField) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

//DisplayErrorはエラーを見やすい形で出力する
//ソースコードのスニペットのindicatorと一緒に表示
//sourceがnilな場合はスニペットは表示しない
func (e *LintingError) DisplayError(output io.Writer, sourceContent []byte) {
	printColored(output, YellowStyle, e.FilePath)
	printColored(output, GrayStyle, ":")
	fmt.Fprint(output, e.LineNumber)
	printColored(output, GrayStyle, ":")
	fmt.Fprint(output, e.ColNumber)
	printColored(output, GrayStyle, ": ")
	printColored(output, BoldStyle, e.Description)
	printColored(output, GrayStyle, fmt.Sprintf(" [%s]\n", e.Type))

	if len(sourceContent) == 0 || e.LineNumber == 0 {
		return
	}

	lineContent, found := e.extractLineContent(sourceContent)
	if !found || len(lineContent) < e.ColNumber - 1 {
		return
	}

	lineHeader := fmt.Sprintf("%d | ", e.LineNumber)
	padding := strings.Repeat(" ", len(lineHeader) - 2)
	printColored(output, GrayStyle, fmt.Sprintf("%s %s\n", padding, lineContent))
	printColored(output, GrayStyle, fmt.Sprintf("%s %s", padding, lineHeader))
	fmt.Fprintln(output,lineContent)
	printColored(output, GrayStyle, fmt.Sprintf("%s %s", padding, strings.Repeat(" ", e.ColNumber - 1)))
	printColored(output, GreenStyle, e.determineIndicator(lineContent))
}

//helper function to print with color
func printColored(output io.Writer, colorizer *color.Color, content string) {
	colorizer.Fprint(output, content)
}

//extractLineContentはソースコードの中からエラーが発生した行の内容を抽出する
func (e *LintingError) extractLineContent(sourceContent []byte) (string, bool) {
	s := bufio.NewScanner(bytes.NewReader(sourceContent))
	lineNumber := 0
	for s.Scan() {
		lineNumber++
		if lineNumber == e.LineNumber {
			return s.Text(), true
		}
	}
	return "", false
}

//determineIndicatorはエラーが発生した箇所を示すindicatorを生成する
func (e *LintingError) determineIndicator(lineContent string) string {
	if e.ColNumber <= 0 {
		return ""
	}
	startPos := e.ColNumber - 1

	underlineWidth := 0
	r := strings.NewReader(lineContent[startPos:])
	for {
		char, size, err := r.ReadRune()
		if err != nil || size == 0 || char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			break
		}
		underlineWidth += runewidth.RuneWidth(char)
	}
	if underlineWidth > 0 {
		underlineWidth--
	}

	spaceWidth := runewidth.StringWidth(lineContent[:startPos])
	return fmt.Sprintf("%s%s", strings.Repeat(" ", spaceWidth), strings.Repeat("-", underlineWidth))
}

type ByRuleErrorPosition []*LintingError

func (a ByRuleErrorPosition) Len() int {
	return len(a)
}

func (a ByRuleErrorPosition) Less(i, j int) bool {
	if comparisonResult := strings.Compare(a[i].FilePath, a[j].FilePath); comparisonResult != 0 {
		return comparisonResult < 0
	}
	if a[i].LineNumber == a[j].LineNumber {
		return a[i].ColNumber < a[j].ColNumber
	}
	return a[i].LineNumber < a[j].LineNumber
}

func (a ByRuleErrorPosition) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

//TemplateFieldsはエラーメッセージをフォーマットするためのフィールド保持
type TemplateFields struct {
	// Message はエラーメッセージの本文
	Message string `json:"message"`
	// Filepath は正規の相対ファイルパスです。入力が標準入力から読み取られた場合、このフィールドは空に
	// JSONにエンコードする際、ファイルパスが空の場合（このフィールドは省略される可能性あり）
	Filepath string `json:"filepath,omitempty"`
	// Line はエラー位置の行番号
	Line int `json:"line"`
	// Column はエラー位置の列番号
	Column int `json:"column"`
	// Type はエラーが属しているルールの名前
	Type string `json:"type"`
	// Snippet はエラーが発生した位置を示すコードスニペットおよびインジケーター
	// JSONにエンコードする際、スニペットが空の場合、(このフィールドは省略される可能性あり)
	Snippet string `json:"snippet,omitempty"`
	// EndColumn はエラーインジケーター(^~~~~~~)が終了する列番号
	//インジケーターが表示されない場合、EndColumn=Column
	EndColumn int `json:"end_column"`
}

//backslashのunescape
func unescapeBackslash(input string) string {
	replacer := strings.NewReplacer("\a", "\a", "\b", "\b", "\f", "\f", "\\", "\\", "\n", "\n", "\r", "\r", "\t", "\t", "\v", "\v")
	return replacer.Replace(input)
}

//文字列をパスカルケースに変換
func toPascalCase(input string) string {
	words := strings.FieldsFunc(input, func(r rune) bool {
		return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9')
	})
	for i, word := range words {
		var firstChar rune
		for _, firstChar = range word {
			break
		}
		if 'a' <= firstChar && firstChar <= 'z' {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, "")
}

//ErrorFormatterはErrorTemplateFieldsのスライスをフォーマットする
//todo: -formatでエラーメッセージをフォーマットするために使用される
type ErrorFormatter struct {
	templateInstance *template.Template
	ruleTemplates map[string]*RuleTemplateField
}

//NewErrorformatterは新しいErrorFormatterインスタンスを作成する。
//指定されたフォーマットには少なくとも1つの{{}}が入っていてほしい
// \nはunescapedされる
func NewErrorFormatter(format string) (*ErrorFormatter, error) {
	if !strings.Contains(format, "{{") {
		return nil, fmt.Errorf("The specified format should contain at least one {{ }} placeholder : %s", format)
	}

	ruleTemplates := map[string]*RuleTemplateField{
		"syntax-check": {"syntax-check", "Check the Github Actions workflow syntax"},
	}

	funcMap := template.FuncMap(map[string]interface{}{
		"json": func(data interface{}) (string, error) {
			var builder strings.Builder
			encoder := json.NewEncoder(&builder)
			if err := encoder.Encode(data); err != nil {
				return "", fmt.Errorf("failed to encode data to json: %w", err)
			}
			return builder.String(), nil
		},

		//TODO:
		"replace": func(str string , oldnew ...string) string {
			return strings.NewReplacer(oldnew...).Replace(str)
		},

		"toPascalCase": toPascalCase,
		//"getVersion": getCommandVersion,
		"allKinds": func() []*RuleTemplateField {
			ret := make([]*RuleTemplateField, 0, len(ruleTemplates))
			for _, rule := range ruleTemplates {
				ret = append(ret, rule)
			}
			sort.Sort(ByRuleTemplateField(ret))
			return ret
		},
	})
	t, err := template.New("error formatter").Funcs(funcMap).Parse(unescapeBackslash(format))
	if err != nil {
		return nil, fmt.Errorf("failed to ast %q the specified format: %w", format, err)
	}
	return &ErrorFormatter{t, ruleTemplates}, nil
}

//PrintErrorsはテンプレートでフォーマットした後でエラーを出力する
func (formatter *ErrorFormatter) Print(writer io.Writer, templateFields []*TemplateFields) error {
	if err := formatter.templateInstance.Execute(writer, templateFields); err != nil {
		return fmt.Errorf("failed to error message format: %w", err)
	}
	return nil
}

//PrintErrorsはテンプレートでフォーマットした後でエラー出力
func (formatter *ErrorFormatter) PrintErrors(writer io.Writer, lintErrors []*LintingError, source []byte) error {
	templateFieldsList := make([]*TemplateFields, 0, len(lintErrors))
	for _, lintError := range lintErrors {
		templateFieldsList = append(templateFieldsList, lintError.ExtractTemplateFields(source))
	}
	return formatter.Print(writer, templateFieldsList)
}

//RegisterRuleはルール登録
//登録済みのルールは、エラーフォーマットテンプレート内のkindDescriptionやkindIndexで取得
func (formatter *ErrorFormatter) RegisterRule(rule Rule) {
	ruleName := rule.RuleNames()
	if _, exists := formatter.ruleTemplates[ruleName]; !exists {
		formatter.ruleTemplates[ruleName] = &RuleTemplateField{
			Name: ruleName,
			Description: rule.RuleDescription(),
		}
	}
}
