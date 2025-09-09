# sisakulint データフロー図（逆生成）

## コマンドライン実行フロー

### 基本実行フロー
```mermaid
sequenceDiagram
    participant User as ユーザー
    participant Main as main.go
    participant Cmd as core.Command
    participant Linter as core.Linter
    participant Parser as YAML Parser
    participant Visitor as SyntaxTreeVisitor
    participant Rules as ルール群
    
    User->>Main: sisakulint [オプション] [ファイル]
    Main->>Cmd: cmd.Main(os.Args)
    Cmd->>Cmd: flag.Parse()
    
    alt リポジトリスキャン
        Cmd->>Linter: LintRepository(".")
        Linter->>Linter: 再帰的にGitHubワークフローファイルを検索
    else 特定ファイルの検査
        Cmd->>Linter: LintFiles(args, nil)
    end
    
    Linter->>Parser: YAMLファイルをパース
    Parser-->>Linter: ASTを返却
    
    Linter->>Visitor: VisitTree(workflow)
    
    loop 各ルール
        Visitor->>Rules: VisitWorkflowPre(workflow)
    end
    
    loop 各Job
        Visitor->>Visitor: visitJob(job)
        
        loop 各ルール
            Visitor->>Rules: VisitJobPre(job)
        end
        
        loop 各Step
            Visitor->>Visitor: visitStep(step)
            
            loop 各ルール
                Visitor->>Rules: VisitStep(step)
                Rules-->>Visitor: エラーまたはnil
            end
        end
        
        loop 各ルール
            Visitor->>Rules: VisitJobPost(job)
        end
    end
    
    loop 各ルール
        Visitor->>Rules: VisitWorkflowPost(workflow)
    end
    
    Visitor-->>Linter: 検証結果
    
    alt エラーあり
        Linter->>Linter: エラーのフォーマット
        
        alt 自動修正モード
            Linter->>Cmd: 検証結果と自動修正情報を返却
            Cmd->>Cmd: runAutofix(results, isDryRun)
        else 通常モード
            Linter-->>Cmd: 検証結果を返却
        end
        
        Cmd->>User: エラー出力（標準またはSARIF形式）
        Cmd->>Main: ExitStatusSuccessProblemFound (1)
    else エラーなし
        Linter-->>Cmd: 空の結果を返却
        Cmd->>User: 成功メッセージ
        Cmd->>Main: ExitStatusSuccessNoProblem (0)
    end
    
    Main->>User: プロセス終了
```

## ルール検証フロー

### 一般的なルール検証プロセス
```mermaid
flowchart TD
    A[ワークフローファイル] --> B[YAMLパーサー]
    B --> C[AST生成]
    C --> D[SyntaxTreeVisitor]
    
    D --> |VisitWorkflowPre| E1[ID衝突検出]
    D --> |VisitWorkflowPre| E2[権限設定検証]
    D --> |VisitWorkflowPre| E3[ワークフローコール検証]
    
    D --> |visitJob| F[各Jobの処理]
    
    F --> |VisitJobPre| G1[タイムアウト検証]
    F --> |VisitJobPre| G2[環境変数検証]
    F --> |VisitJobPre| G3[認証情報検証]
    F --> |VisitJobPre| G4[条件式検証]
    
    F --> |visitStep| H[各Stepの処理]
    
    H --> |VisitStep| I1[コミットSHA検証]
    H --> |VisitStep| I2[ID衝突検出]
    H --> |VisitStep| I3[スクリプトインジェクション検出]
    H --> |VisitStep| I4[タイムアウト検証]
    
    F --> |VisitJobPost| J[ジョブ後処理]
    
    D --> |VisitWorkflowPost| K[ワークフロー後処理]
    
    I1 & I2 & I3 & I4 --> L1[エラー収集]
    G1 & G2 & G3 & G4 --> L2[エラー収集]
    E1 & E2 & E3 & K & J --> L3[エラー収集]
    
    L1 & L2 & L3 --> M[エラーフォーマット]
    M --> N[出力生成]
    
    N --> O1[標準エラー出力]
    N --> O2[SARIF出力]
```

## 自動修正フロー

### 自動修正プロセス
```mermaid
sequenceDiagram
    participant Cmd as core.Command
    participant Result as ValidateResult
    participant Fixer as AutoFixer
    participant YAML as yaml.Encoder
    participant FS as ファイルシステム
    
    Cmd->>Cmd: runAutofix(results, isDryRun)
    
    loop 各検証結果
        Cmd->>Result: AutoFixers取得
        
        loop 各Fixer
            Cmd->>Fixer: Fix()
            alt 修正成功
                Fixer-->>Cmd: nil
            else 修正失敗
                Fixer-->>Cmd: error
                Cmd->>Cmd: エラー表示
            end
        end
        
        Cmd->>YAML: ASTをYAMLにエンコード
        YAML-->>Cmd: YAMLテキスト
        
        alt ドライラン
            Cmd->>Cmd: 修正後YAMLを表示
        else 実際の修正
            Cmd->>FS: ファイル書き込み
            alt 書き込み成功
                Cmd->>Cmd: 成功メッセージ表示
            else 書き込み失敗
                Cmd->>Cmd: エラー表示
                Cmd->>FS: 元ファイルを復元
            end
        end
    end
```

## ルール別データフロー

### ID衝突検出ルールのデータフロー
```mermaid
flowchart TD
    A[RuleID初期化] --> B[VisitJobPre]
    B --> C[seen mapをクリア]
    B --> D[ジョブIDの検証]
    B --> E[依存ジョブIDの検証]
    
    A --> F[VisitStep]
    F --> G{ステップにIDがある?}
    G -->|Yes| H[IDの命名規則チェック]
    G -->|No| I[何もしない]
    
    H --> J{IDが既にseenに存在する?}
    J -->|Yes| K[重複エラー報告]
    J -->|No| L[IDをseenに追加]
    
    A --> M[VisitJobPost]
    M --> N[seenをクリア]
```

### 認証情報検出ルールのデータフロー
```mermaid
flowchart TD
    A[CredentialRule初期化] --> B[VisitJobPre]
    B --> C{ジョブにコンテナがある?}
    C -->|Yes| D[コンテナの認証情報チェック]
    C -->|No| E[何もしない]
    
    B --> F[各サービスをループ]
    F --> G[サービスコンテナの認証情報チェック]
    
    D & G --> H{パスワードが式でない?}
    H -->|Yes| I[ハードコードパスワードエラー報告]
    H -->|No| J[OK]
    
    I --> K[AutoFixerの追加]
```

### スクリプトインジェクション検出ルールのデータフロー
```mermaid
flowchart TD
    A[IssueInjection初期化] --> B[VisitJobPre]
    B --> C[各ステップをループ]
    
    C --> D{ステップがExecRunか?}
    D -->|Yes| E[runコマンドを取得]
    D -->|No| F[次のステップへ]
    
    E --> G[コマンドを行に分割]
    G --> H[各行をループ]
    
    H --> I{${{ が存在する?}
    I -->|Yes| J{}} が存在する?}
    I -->|No| K[次の行へ]
    
    J -->|Yes| L[スクリプトインジェクション警告]
    J -->|No| M{複数行にまたがるか確認}
    
    M -->|Yes| N[複数行にまたがる式を検出]
    M -->|No| O[式構文エラー]
    
    N --> P[スクリプトインジェクション警告]
```

### コミットSHA検証ルールのデータフロー
```mermaid
flowchart TD
    A[CommitShaRule初期化] --> B[VisitStep]
    
    B --> C{ステップがアクションを使用?}
    C -->|Yes| D[usesの値を取得]
    C -->|No| E[何もしない]
    
    D --> F{フルレングスのSHAか?}
    F -->|Yes| G[OK]
    F -->|No| H[コミットSHA警告]
    
    H --> I[AutoFixerの追加]
    
    I --> J{自動修正実行}
    J --> K[GitHub APIでSHA取得]
    K --> L[コミットSHAで参照を更新]
```

## SARIF出力生成フロー

### SARIF変換プロセス
```mermaid
flowchart TD
    A[検証エラーリスト] --> B[toSARIF関数]
    
    B --> C[SARIF基本構造作成]
    
    C --> D[各エラーをループ]
    D --> E[toResult関数]
    
    E --> F[SARIF結果オブジェクト作成]
    F --> G[ルールID設定]
    F --> H[警告レベル設定]
    F --> I[エラーメッセージ設定]
    F --> J[ロケーション情報設定]
    
    J --> K[ファイルパス設定]
    J --> L[行・列情報設定]
    J --> M[スニペット設定]
    
    C --> N[結果のJSONマーシャル]
    N --> O[JSONテキスト返却]
```

## 設定ファイル読み込みフロー

```mermaid
flowchart TD
    A[Linter初期化] --> B{設定ファイルパス指定あり?}
    
    B -->|Yes| C[指定パスから読み込み]
    B -->|No| D[デフォルトパス検索]
    
    D --> E{.github/action.yamlが存在?}
    E -->|Yes| F[設定ファイル読み込み]
    E -->|No| G[デフォルト設定使用]
    
    C & F --> H[YAML解析]
    H --> I[Config構造体に変換]
    
    I --> J[ルールのUpdateConfig呼び出し]
```

## メモリと状態管理

### 主要な状態保持コンポーネント

1. **Command構造体**
   - Stdin, Stdout, Stderrを保持
   - 短命: コマンド実行期間のみ有効

2. **Linter構造体**
   - プロジェクト情報
   - エラー/ログ出力先
   - 設定情報
   - 長命: リント処理全体を通じて有効

3. **Rule実装**
   - 検出されたエラーのリスト
   - 自動修正情報
   - ルール特有の状態（例: RuleIDのseen map）
   - 中命: 特定のファイルの検証中のみ有効

4. **VisitorPattern**
   - ルールのリスト（passes）
   - デバッグ出力先
   - 中命: ファイル処理中のみ有効

### 状態管理の特徴

- **イミュータブル設計志向**: 多くの構造体は初期化後に内部状態を変更しない
- **明示的な依存関係**: 依存オブジェクトは構造体初期化時に渡される
- **スコープ制限**: データはできるだけ必要なスコープでのみ保持
- **ルールごとの独立性**: 各ルールはOthers状態を共有せず独立して動作

## エラー処理フロー

```mermaid
flowchart TD
    A[エラー検出] --> B[LintingError作成]
    B --> C[ルールのエラーリストに追加]
    
    C --> D{検証終了?}
    D -->|Yes| E[ValidateResultに集約]
    D -->|No| F[検証継続]
    
    E --> G{カスタムフォーマット指定?}
    G -->|Yes| H[テンプレート適用]
    G -->|No| I{SARIF出力?}
    
    I -->|Yes| J[SARIF変換]
    I -->|No| K[標準エラーフォーマット]
    
    H & J & K --> L[出力生成]
    
    L --> M{自動修正モード?}
    M -->|Yes| N[AutoFixersを実行]
    M -->|No| O[処理終了]
```