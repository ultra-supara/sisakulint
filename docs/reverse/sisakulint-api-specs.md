# sisakulint API仕様書（逆生成）

## コマンドライン API

### 基本コマンド

```
sisakulint [FLAGS] [FILES...] [OPTIONS]
```

sisakulintは、GitHub Actionsのワークフローファイル（`.github/workflows/*.yml`または`.yaml`）を対象とした静的解析ツールです。

### フラグとオプション

| フラグ | 引数タイプ | 説明 | デフォルト値 |
|--------|------------|------|-------------|
| `-verbose` | なし | 詳細な出力を有効にする | `false` |
| `-debug` | なし | デバッグ出力を有効にする（開発用） | `false` |
| `-version` | なし | バージョンとインストール情報を表示 | `false` |
| `-format` | string | エラーメッセージのカスタムフォーマット（Goテンプレート構文） | `""` |
| `-config-file` | string | 設定ファイルへのパス | `""` |
| `-init` | なし | カレントプロジェクトの`.github/action.yaml`にデフォルトの設定ファイルを生成 | `false` |
| `-boilerplate` | なし | GitHub Actionsワークフロー用のカスタマイズテンプレートファイルを生成 | `false` |
| `-stdin-filename` | string | 標準入力から読み込む際のファイル名 | `""` |
| `-fix` | string | 自動修正モード（`off`、`on`、`dry-run`） | `"off"` |
| `-ignore` | string | 無視したいエラーメッセージにマッチする正規表現（複数指定可） | `[]` |

### 終了コード

| コード | 定数名 | 説明 |
|--------|--------|------|
| 0 | `ExitStatusSuccessNoProblem` | コマンドが成功し、問題が見つからなかった |
| 1 | `ExitStatusSuccessProblemFound` | コマンドが成功し、問題が見つかった |
| 2 | `ExitStatusInvalidCommandOption` | コマンドラインオプションの解析に失敗した |
| 3 | `ExitStatusFailure` | ワークフローチェック中に致命的なエラーが発生した |

### 使用例

#### 基本的な使用法

```bash
# カレントリポジトリのGitHubワークフローファイルを検証
$ sisakulint

# デバッグモードで検証
$ sisakulint -debug

# 特定のファイルを検証
$ sisakulint path/to/workflow.yml
```

#### 出力フォーマットの指定

```bash
# SARIF形式で出力
$ sisakulint -format "{{sarif .}}"

# reviewdogで使用
$ sisakulint -format "{{sarif .}}" | reviewdog -f=sarif -reporter=github-pr-review
```

#### 自動修正機能

```bash
# 自動修正を適用
$ sisakulint -fix on

# 自動修正をドライラン（変更内容のプレビューのみ）
$ sisakulint -fix dry-run
```

#### 設定関連

```bash
# デフォルト設定ファイルを生成
$ sisakulint -init

# ボイラープレートテンプレートを生成
$ sisakulint -boilerplate

# 特定の設定ファイルを使用
$ sisakulint -config-file custom-config.yaml
```

## カスタムフォーマット

sisakulintでは、`-format`フラグを使用して出力形式をカスタマイズできます。フォーマットはGoのテンプレート構文を使用します。

### テンプレート変数

| 変数 | 説明 |
|------|------|
| `.Filepath` | エラーが検出されたファイルのパス |
| `.Line` | エラー位置の行番号 |
| `.Column` | エラー位置の列番号 |
| `.Message` | エラーメッセージ本文 |
| `.Type` | エラーのタイプ（ルール名） |
| `.Snippet` | エラーが含まれるコードスニペット |

### フォーマット例

```
# 標準フォーマット（デフォルト）
{{.Filepath}}:{{.Line}}:{{.Column}}: {{.Message}} [{{.Type}}]

# SARIF形式
{{sarif .}}

# カスタムフォーマット例
[Error] File: {{.Filepath}}, Line: {{.Line}}, Type: {{.Type}}
Message: {{.Message}}
```

## 設定ファイル

sisakulintは`.github/action.yaml`（または`-config-file`で指定されたファイル）から設定を読み込みます。

### 設定ファイルの構造

```yaml
# ルール設定
rules:
  # ID衝突検出ルール
  id:
    enabled: true  # ルールの有効/無効
    
  # 環境変数チェックルール
  env-var:
    enabled: true
    
  # 認証情報ハードコード検出ルール
  credentials:
    enabled: true
    
  # コミットSHA検証ルール
  commit-sha:
    enabled: true
    exclude-actions: 
      - "actions/checkout"  # 検証から除外するアクション
    
  # 権限設定検証ルール
  permissions:
    enabled: true
    
  # ワークフローコール検証ルール
  workflow-call:
    enabled: true
    
  # タイムアウト設定検証ルール
  missing-timeout-minutes:
    enabled: true
    
  # 条件式検証ルール
  cond:
    enabled: true
    
  # スクリプトインジェクション脆弱性検出ルール
  issue-injection:
    enabled: true

# 共通設定
common:
  # エラーを無視するパターン
  ignores:
    - "pattern1"
    - "pattern2"
```

## プログラミングインターフェース

sisakulintは主にコマンドラインツールとして設計されていますが、内部的には次のようなプログラミングインターフェースを提供しています。これらのインターフェースを利用して、sisakulintをプログラムに組み込むことも可能です。

### コアコンポーネント

#### `Command` 構造体

コマンドラインインターフェースを提供する構造体です。

```go
type Command struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// コマンドを実行
func (cmd *Command) Main(args []string) int

// リンターを実行
func (cmd *Command) runLint(args []string, linterOpts *LinterOptions, initConfig bool, generateBoilerplate bool) ([]*ValidateResult, error)

// 自動修正を実行
func (cmd *Command) runAutofix(results []*ValidateResult, isDryRun bool)
```

#### `Linter` 構造体

リント処理の中核を担う構造体です。

```go
type Linter struct {
	// (フィールドは省略)
}

// 新しいLinterを作成
func NewLinter(errorOutput io.Writer, opt *LinterOptions) (*Linter, error)

// リポジトリ内のワークフローファイルを検証
func (l *Linter) LintRepository(dir string) ([]*ValidateResult, error)

// 特定のファイルを検証
func (l *Linter) LintFiles(filepaths []string, source []byte) ([]*ValidateResult, error)

// デフォルト設定を生成
func (l *Linter) GenerateDefaultConfig(dir string) error

// ボイラープレートを生成
func (l *Linter) GenerateBoilerplate(dir string) error
```

#### `Rule` インターフェース

検証ルールの共通インターフェースです。

```go
type Rule interface {
	// TreeVisitorを実装
	VisitStep(node *ast.Step) error
	VisitJobPre(node *ast.Job) error
	VisitJobPost(node *ast.Job) error
	VisitWorkflowPre(node *ast.Workflow) error
	VisitWorkflowPost(node *ast.Workflow) error
	
	// その他の操作
	Errors() []*LintingError
	RuleNames() string
	RuleDescription() string
	EnableDebugOutput(out io.Writer)
	UpdateConfig(config *Config)
	AddAutoFixer(fixer AutoFixer)
	AutoFixers() []AutoFixer
}
```

#### `AutoFixer` インターフェース

自動修正機能のインターフェースです。

```go
type AutoFixer interface {
	RuleName() string
	Fix() error
}
```

### データモデル

#### `ValidateResult` 構造体

検証結果を表す構造体です。

```go
type ValidateResult struct {
	FilePath       string
	ParsedWorkflow *ast.Workflow
	Source         []byte
	Errors         []*LintingError
	AutoFixers     []AutoFixer
}
```

#### `LintingError` 構造体

検出されたエラーを表す構造体です。

```go
type LintingError struct {
	FilePath string
	Position *ast.Position
	RuleName string
	Message  string
}
```

## 拡張方法

### カスタムルールの追加

sisakulintに新しいルールを追加するには、次の手順を実行します：

1. `Rule` インターフェースを実装した新しい構造体を作成
2. 通常は `BaseRule` を埋め込むことで基本実装を継承
3. 必要なビジターメソッド（`VisitStep`, `VisitJobPre` など）をオーバーライド
4. 検出した問題を `Error` または `Errorf` メソッドで報告
5. 必要に応じて `AutoFixer` を追加
6. `pkg/core/linter.go` の `createDefaultRules` 関数にルールを登録

```go
type MyCustomRule struct {
	BaseRule
}

func NewMyCustomRule() *MyCustomRule {
	return &MyCustomRule{
		BaseRule: BaseRule{
			RuleName: "my-custom-rule",
			RuleDesc: "Checks for my custom condition",
		},
	}
}

func (rule *MyCustomRule) VisitStep(n *ast.Step) error {
	// ルールの実装
	if /* 条件 */ {
		rule.Errorf(n.Pos, "エラーメッセージ")
		
		// 必要に応じて自動修正を追加
		rule.AddAutoFixer(NewStepFixer(n, rule))
	}
	return nil
}

func (rule *MyCustomRule) FixStep(n *ast.Step) error {
	// 自動修正の実装
	// ...
	return nil
}
```

### カスタム出力フォーマッタの追加

カスタム出力フォーマットを追加するには、次の手順を実行します：

1. `pkg/core/errorformatter.go` に新しいフォーマット関数を追加
2. `errorFormatter.AddCustomFormat` でフォーマットを登録

```go
func customFormat(fields *TemplateFields) (string, error) {
	// フォーマットの実装
	return fmt.Sprintf("Custom format: %s:%d:%d %s", fields.Filepath, fields.Line, fields.Column, fields.Message), nil
}

func init() {
	errorFormatter.AddCustomFormat("custom", customFormat)
}
```