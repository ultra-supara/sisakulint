# sisakulint アーキテクチャ設計（逆生成）

## 分析日時
2025-08-19

## システム概要

### 実装されたアーキテクチャ
- **パターン**: コマンドラインツール + プラガブルルール検証
- **フレームワーク**: 独自フレームワーク（Go標準ライブラリをベースとしたカスタム設計）
- **構成**: モジュラー設計（コア、AST、式パーサー、ルールの実装）

### 技術スタック

#### コアコンポーネント
- **言語**: Go 1.24.0
- **AST解析**: カスタムASTパーサー + gopkg.in/yaml.v3
- **エラーレポート**: カスタムエラーフォーマッタ + SARIF出力サポート
- **コマンドライン**: 標準ライブラリ flag パッケージ

#### 主要ライブラリ
- **色付き出力**: github.com/fatih/color
- **コンソール対応**: github.com/mattn/go-colorable
- **GitHub API**: github.com/google/go-github/v68
- **SARIF 出力**: github.com/haya14busa/go-sarif
- **並列処理**: golang.org/x/sync

#### 開発ツール
- **コンパイル**: Go ビルドシステム
- **テスト**: Go標準テストフレームワーク
- **デプロイ**: Homebrew タップ（macOS用）

## レイヤー構成

### 発見されたレイヤー
```
sisakulint/
├── cmd/                   # コマンドラインエントリーポイント
│   └── sisakulint/        
│       └── main.go
├── pkg/                   # 主要なライブラリコード
│   ├── ast/               # AST（抽象構文木）の定義
│   ├── core/              # コア機能（リンター、ルール、コマンド処理）
│   └── expressions/       # GitHub Actions式のパーサー
├── script/                # ユーティリティスクリプト
├── docs/                  # ドキュメント
└── [設定ファイル類]         # .github, .goreleaser.yml など
```

### レイヤー責務分析

#### コマンドライン層 (cmd/)
- **責務**: ユーザーインターフェイス、アプリケーションエントリーポイント
- **実装状況**: 最小限の実装で、main.goがコアロジックへの橋渡しをする
- **関連コンポーネント**: core.Command

#### コア層 (pkg/core/)
- **責務**: アプリケーションの主要ロジック
- **実装状況**: 充実した実装で、リンター、ルール、訪問者パターン、自動修正機能を含む
- **コンポーネント**:
  - `Command`: コマンドラインインターフェース
  - `Linter`: メインのリント処理を実行
  - `Rule`: ルールのインターフェース（各種ルールを実装）
  - `SyntaxTreeVisitor`: ASTを走査するためのビジターパターン実装
  - `AutoFixer`: 検出された問題の自動修正を行う
  - `ErrorFormatter`: エラーメッセージのフォーマット
  - `Projects`: プロジェクト情報を管理

#### AST層 (pkg/ast/)
- **責務**: GitHubワークフローYAMLのASTを定義
- **実装状況**: YAML構文を抽象化したデータ構造を提供
- **コンポーネント**:
  - 基本型（String, Bool, Int, Float）
  - ワークフロー要素（Workflow, Job, Step など）

#### 式パーサー層 (pkg/expressions/)
- **責務**: GitHub Actions式のパース
- **実装状況**: 式のトークン化、パース、セマンティック検証
- **コンポーネント**:
  - `Tokenizer`: 式を字句解析
  - `Parser`: 式を構文解析
  - `Semantics`: 式の意味解析

## デザインパターン

### 発見されたパターン

#### Visitor Pattern
- **実装**: `TreeVisitor` インターフェースと `SyntaxTreeVisitor` 構造体
- **使用箇所**: AST ノードの走査
- **目的**: ノード構造を変更せずに操作を追加できるようにする
- **実装詳細**: 
  - `VisitWorkflowPre`, `VisitJobPre`, `VisitStep`, `VisitJobPost`, `VisitWorkflowPost` メソッド
  - 深さ優先順序でツリーを走査

#### Plugin Pattern
- **実装**: `Rule` インターフェースを各ルールが実装
- **使用箇所**: ルールのシステムへの追加
- **目的**: 新しいルールを容易に追加できるようにする
- **実装詳細**:
  - 各ルールは `BaseRule` を埋め込み、共通機能を継承
  - ルールは動的に登録され、Linterにより実行される

#### Strategy Pattern
- **実装**: `AutoFixer` インターフェースと各種 Fixer 実装
- **使用箇所**: 自動修正ロジック
- **目的**: 異なる修正戦略を選択可能にする
- **実装詳細**:
  - `StepFixer`, `JobFixer`, `FuncFixer` の各戦略
  - 適切な修正方法をルールに基づいて選択

#### Factory Method Pattern
- **実装**: 各種ルールの作成関数（例: `IDRule()`, `PermissionsRule()`）
- **使用箇所**: ルールインスタンスの作成
- **目的**: 構造体の初期化ロジックをカプセル化
- **実装詳細**:
  - ファクトリ関数が適切な初期値を設定したルールを返す

#### Command Pattern (弱い形式)
- **実装**: `Command` 構造体とそのメソッド
- **使用箇所**: コマンドラインオプションの処理
- **目的**: コマンド実行をカプセル化
- **実装詳細**:
  - 入出力を構造体にカプセル化
  - オプションに基づいた実行フローの制御

## 非機能要件の実装状況

### セキュリティ
- **焦点**: GitHub Actionsのセキュリティベストプラクティス検証
- **実装方式**: 複数のセキュリティチェックルール
  - ハードコードされた認証情報検出
  - スクリプトインジェクション脆弱性検出
  - コミットSHA検証
  - 権限設定検証
- **OWASP対応**: CI/CD セキュリティリスクトップ10に対応

### パフォーマンス
- **並列処理**: 複数ファイルの同時処理に対応（errgroup使用）
- **最適化**: キャッシュを活用したワークフロー呼び出し検証
- **メモリ効率**: AST走査時に最小限のメモリ使用

### 操作性・使いやすさ
- **カラー出力**: エラーの視認性向上のためのカラー出力
- **詳細なエラーメッセージ**: 問題箇所の正確な特定とガイダンス
- **自動修正**: 検出された問題の自動修正機能
- **ドキュメントリンク**: エラーメッセージにドキュメントへのリンク
- **reviewdog対応**: SARIF出力によるGitHubでのレビュー支援

### 拡張性
- **プラガブルルール**: 新しいルールを容易に追加可能
- **カスタムフォーマット**: エラー出力のカスタマイズオプション
- **設定ファイル**: `.github/action.yaml` でのカスタム設定

### 運用・監視
- **デバッグ機能**: `-debug` フラグによる詳細なログ出力
- **バージョン情報**: ビルド情報の表示
- **終了コード**: 異なる状態に応じた終了コード

## 重要なクラス図

```mermaid
classDiagram
    class Command {
        +Stdin io.Reader
        +Stdout io.Writer
        +Stderr io.Writer
        +Main(args []string) int
        +runLint(args []string, opts *LinterOptions, initConfig bool, generateBoilerplate bool) []*ValidateResult
        +runAutofix(results []*ValidateResult, isDryRun bool)
    }
    
    class Linter {
        +projectInformation *Projects
        +errorOutput io.Writer
        +logOutput io.Writer
        +loggingLevel LogLevel
        +errorFormatter *ErrorFormatter
        +LintRepository(dir string) []*ValidateResult
        +LintFiles(filepaths []string, source []byte) []*ValidateResult
        +GenerateDefaultConfig(dir string) error
        +GenerateBoilerplate(dir string) error
    }
    
    class SyntaxTreeVisitor {
        +passes []TreeVisitor
        +debugW io.Writer
        +AddVisitor(visitor TreeVisitor)
        +VisitTree(node *ast.Workflow) error
    }
    
    class TreeVisitor {
        <<interface>>
        +VisitStep(node *ast.Step) error
        +VisitJobPre(node *ast.Job) error
        +VisitJobPost(node *ast.Job) error
        +VisitWorkflowPre(node *ast.Workflow) error
        +VisitWorkflowPost(node *ast.Workflow) error
    }
    
    class Rule {
        <<interface>>
        +TreeVisitor
        +Errors() []*LintingError
        +RuleNames() string
        +RuleDescription() string
        +EnableDebugOutput(out io.Writer)
        +UpdateConfig(config *Config)
        +AddAutoFixer(fixer AutoFixer)
        +AutoFixers() []AutoFixer
    }
    
    class BaseRule {
        +RuleName string
        +RuleDesc string
        -ruleErrors []*LintingError
        -autoFixers []AutoFixer
        -debugOut io.Writer
        -userConfig *Config
        +Error(position *ast.Position, msg string)
        +Errorf(position *ast.Position, format string, args ...interface{})
    }
    
    class AutoFixer {
        <<interface>>
        +RuleName() string
        +Fix() error
    }
    
    class Workflow {
        +Name *String
        +On []Event
        +Env *Env
        +Defaults *Defaults
        +Jobs map[string]*Job
        +Permissions *Permissions
        +Pos *Position
        +BaseNode *yaml.Node
    }
    
    class Job {
        +ID *String
        +Name *String
        +Needs []string
        +RunsOn *String
        +Environment *String
        +If *String
        +Steps []*Step
        +Env *Env
        +TimeoutMinutes *Int
        +Permissions *Permissions
        +Pos *Position
        +BaseNode *yaml.Node
    }
    
    class Step {
        +ID *String
        +Name *String
        +If *String
        +Env *Env
        +Exec ExecStep
        +ContinueOnError *Bool
        +TimeoutMinutes *Int
        +Pos *Position
        +BaseNode *yaml.Node
        +String() string
    }
    
    Command --> Linter : creates
    Linter --> SyntaxTreeVisitor : uses
    SyntaxTreeVisitor o-- TreeVisitor : contains
    Rule --|> TreeVisitor : implements
    BaseRule ..|> Rule : implements
    Linter o-- Rule : contains
    Rule o-- AutoFixer : contains
    SyntaxTreeVisitor ..> Workflow : visits
    SyntaxTreeVisitor ..> Job : visits
    SyntaxTreeVisitor ..> Step : visits
```

## アーキテクチャの特徴

### モジュール性
- 独立したパッケージによる明確な責任の分離
- インターフェースを通じたコンポーネント間の疎結合

### 拡張性
- ルールとして新しい検証を容易に追加可能
- ビジターパターンによるAST操作の拡張性確保

### 堅牢性
- 詳細なエラーハンドリング
- 位置情報付きのエラーレポート
- 並列処理によるファイル処理の安定性

### カスタマイズ性
- 設定ファイルによるカスタマイズ
- 出力フォーマットのカスタマイズオプション
- 自動修正機能によるユーザビリティ向上

### シンプルさ
- 単一の責任を持つ小さなコンポーネント
- 明確なデータフロー
- 標準ライブラリの積極的活用

## 技術的負債と改善点

### コード品質
- 一部のエラーハンドリングの一貫性不足
- `Debug()` メソッドの実装ミス（条件判断の逆転）
- 一部のコメントの不足または不正確な部分

### テスト不足
- いくつかのルール実装にテストがない
- E2Eテストの不足

### ドキュメント
- コードコメントが不足している箇所がある
- APIドキュメントの不足

### パフォーマンス
- 大規模リポジトリでの並列処理の最適化余地

### セキュリティ
- GitHub API呼び出しの認証情報管理の改善余地