# sisakulint テスト仕様書（逆生成）

## 分析概要

**分析日時**: 2025-08-19
**対象コードベース**: /Users/atsushi.sada/go/src/github.com/ultra-supara/sisakulint
**テストカバレッジ**: 推定15-20%（不完全なテストが多い）
**生成テストケース数**: 57個
**実装推奨テスト数**: 45個

## 現在のテスト実装状況

### テストフレームワーク
- **単体テスト**: Go標準テストパッケージ (testing)
- **統合テスト**: なし
- **E2Eテスト**: なし
- **コードカバレッジ**: なし

### テストカバレッジ詳細

| ファイル/ディレクトリ | ステートメントカバレッジ | 条件カバレッジ | 関数カバレッジ |
|---------------------|-------------------|-------------|-------------|
| pkg/core/conditionalrule.go | ~0% | ~0% | ~0% |
| pkg/core/environmentvariablerule.go | ~20% | ~10% | ~30% |
| pkg/core/idrule.go | ~30% | ~15% | ~40% |
| pkg/core/permissionrule.go | ~0% | ~0% | ~0% |
| pkg/core/duprecate_commands_pattern.go | ~30% | ~20% | ~30% |
| pkg/core/ (その他のファイル) | ~0% | ~0% | ~0% |
| **全体** | ~15% | ~10% | ~20% |

### テストカテゴリ別実装状況

#### 単体テスト
- [x] **IDルール**: idrule_test.go (基本テストのみ)
- [x] **環境変数ルール**: environmentvariablerule_test.go (基本テストのみ)
- [x] **条件式ルール**: conditionalrule_test.go (スケルトンのみ)
- [x] **権限ルール**: permissionrule_test.go (スケルトンのみ)
- [x] **非推奨コマンドルール**: duprecate_commands_pattern_test.go (基本テストのみ)
- [ ] **コミットSHAルール**: 未実装
- [ ] **タイムアウトルール**: 未実装
- [ ] **スクリプトインジェクションルール**: 未実装
- [ ] **コア機能テスト（Linter）**: 未実装
- [ ] **コマンドライン解析テスト**: 未実装
- [ ] **自動修正機能テスト**: 未実装

#### 統合テスト
- [ ] **複数ルール統合テスト**: 未実装
- [ ] **エラー出力フォーマットテスト**: 未実装
- [ ] **SARIF出力テスト**: 未実装
- [ ] **設定ファイル読み込みテスト**: 未実装

#### E2Eテスト
- [ ] **実ワークフローファイル検証テスト**: 未実装
- [ ] **自動修正結果検証テスト**: 未実装
- [ ] **ディレクトリスキャンテスト**: 未実装

## ユニットテスト仕様

### コア機能テスト

#### TC-U-001: Linter初期化テスト

**テスト目的**: Linterの初期化が正しく行われることを確認

**テスト内容**:
```go
func TestNewLinter(t *testing.T) {
	// デフォルトオプションでのLinter初期化テスト
	t.Run("default options", func(t *testing.T) {
		var out bytes.Buffer
		linter, err := NewLinter(&out, &LinterOptions{})
		
		if err != nil {
			t.Errorf("NewLinter() error = %v", err)
			return
		}
		
		if linter == nil {
			t.Errorf("NewLinter() returned nil linter")
			return
		}
		
		// デフォルト設定の確認
		if linter.loggingLevel != LogLevelNoOutput {
			t.Errorf("default loggingLevel = %v, want %v", linter.loggingLevel, LogLevelNoOutput)
		}
	})
	
	// カスタムオプションでのLinter初期化テスト
	t.Run("custom options", func(t *testing.T) {
		var out bytes.Buffer
		linter, err := NewLinter(&out, &LinterOptions{
			IsVerboseOutputEnabled: true,
			IsDebugOutputEnabled:   true,
		})
		
		if err != nil {
			t.Errorf("NewLinter() error = %v", err)
			return
		}
		
		if linter.loggingLevel != LogLevelAllOutputIncludingDebug {
			t.Errorf("custom loggingLevel = %v, want %v", linter.loggingLevel, LogLevelAllOutputIncludingDebug)
		}
	})
	
	// 設定ファイル指定でのLinter初期化テスト
	// ...
}
```

#### TC-U-002: ルール登録テスト

**テスト目的**: ルールが正しく登録され、訪問者に追加されることを確認

**テスト内容**:
```go
func TestLinter_RegisterRules(t *testing.T) {
	var out bytes.Buffer
	linter, _ := NewLinter(&out, &LinterOptions{})
	
	// 内部的に実装されているcreateSyntaxTreeVisitorAndRulesをモック
	visitor := NewSyntaxTreeVisitor()
	rules := createDefaultRules()
	
	// ルールの数を確認
	if len(rules) == 0 {
		t.Errorf("createDefaultRules() returned empty rules")
	}
	
	// 各ルールの型と名前を確認
	ruleNames := make(map[string]bool)
	for _, rule := range rules {
		name := rule.RuleNames()
		if name == "" {
			t.Errorf("rule has empty name")
		}
		
		// ルール名の重複を確認
		if ruleNames[name] {
			t.Errorf("duplicate rule name: %s", name)
		}
		ruleNames[name] = true
		
		// ルール説明が存在することを確認
		if rule.RuleDescription() == "" {
			t.Errorf("rule %s has empty description", name)
		}
	}
	
	// 実際にビジターにルールを追加
	for _, rule := range rules {
		visitor.AddVisitor(rule)
	}
	
	// ビジターに追加されたルールの数を確認
	if len(visitor.passes) != len(rules) {
		t.Errorf("visitor.passes has %d rules, want %d", len(visitor.passes), len(rules))
	}
}
```

#### TC-U-003: Linter実行テスト

**テスト目的**: Linterが正しく動作し、エラーを検出できることを確認

**テスト内容**:
```go
func TestLinter_LintFiles(t *testing.T) {
	// 無効なYAMLファイル
	t.Run("invalid yaml", func(t *testing.T) {
		var out bytes.Buffer
		linter, _ := NewLinter(&out, &LinterOptions{})
		
		// 不正なYAMLを含むソースを作成
		source := []byte("invalid: - yaml: content")
		
		// ファイルを指定してリント
		results, err := linter.LintFiles([]string{"test.yml"}, source)
		
		// エラーの確認
		if err == nil {
			t.Errorf("LintFiles() did not return error for invalid YAML")
		}
		
		// 結果が空であることを確認
		if len(results) != 0 {
			t.Errorf("LintFiles() returned %d results, want 0", len(results))
		}
	})
	
	// 有効なワークフローファイルで、エラーを含むもの
	t.Run("valid workflow with errors", func(t *testing.T) {
		var out bytes.Buffer
		linter, _ := NewLinter(&out, &LinterOptions{})
		
		// エラーを含む有効なYAMLワークフローを作成
		source := []byte(`
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set output
        run: |
          echo ::set-output name=test::value
`)
		
		// ファイルを指定してリント
		results, err := linter.LintFiles([]string{"test.yml"}, source)
		
		// エラーがないことを確認
		if err != nil {
			t.Errorf("LintFiles() error = %v", err)
		}
		
		// 結果が1つあることを確認
		if len(results) != 1 {
			t.Errorf("LintFiles() returned %d results, want 1", len(results))
			return
		}
		
		// エラーが少なくとも1つあることを確認（非推奨コマンドエラー）
		if len(results[0].Errors) == 0 {
			t.Errorf("LintFiles() returned no errors, want at least 1")
		}
	})
}
```

#### TC-U-004: コマンドライン解析テスト

**テスト目的**: コマンドライン引数が正しく解析されることを確認

**テスト内容**:
```go
func TestCommand_Main(t *testing.T) {
	// ヘルプフラグのテスト
	t.Run("help flag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := Command{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		
		exit := cmd.Main([]string{"sisakulint", "-h"})
		
		// 終了コードの確認
		if exit != ExitStatusSuccessNoProblem {
			t.Errorf("Main() exit = %v, want %v", exit, ExitStatusSuccessNoProblem)
		}
		
		// ヘルプメッセージが出力されることを確認
		if !strings.Contains(stderr.String(), "Usage: sisakulint") {
			t.Errorf("Help message not found in stderr")
		}
	})
	
	// バージョンフラグのテスト
	t.Run("version flag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := Command{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		
		exit := cmd.Main([]string{"sisakulint", "-version"})
		
		// 終了コードの確認
		if exit != ExitStatusSuccessNoProblem {
			t.Errorf("Main() exit = %v, want %v", exit, ExitStatusSuccessNoProblem)
		}
		
		// バージョン情報が出力されることを確認
		if !strings.Contains(stdout.String(), "Tool version:") {
			t.Errorf("Version info not found in stdout")
		}
	})
	
	// 無効なフラグのテスト
	t.Run("invalid flag", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		cmd := Command{
			Stdin:  strings.NewReader(""),
			Stdout: &stdout,
			Stderr: &stderr,
		}
		
		exit := cmd.Main([]string{"sisakulint", "-invalid-flag"})
		
		// 終了コードの確認
		if exit != ExitStatusInvalidCommandOption {
			t.Errorf("Main() exit = %v, want %v", exit, ExitStatusInvalidCommandOption)
		}
	})
}
```

### ルール単体テスト

#### TC-U-101: ID衝突検出ルールテスト（完全版）

**テスト目的**: IDルールが正しくID衝突を検出できることを確認

**テスト内容**:
```go
func TestRuleID_VisitStep_Duplicate(t *testing.T) {
	// テストケースのセットアップ
	rule := IDRule()
	
	// ジョブを初期化（seenマップをクリアするため）
	mockJob := &ast.Job{
		ID: &ast.String{Value: "test_job"},
	}
	rule.VisitJobPre(mockJob)
	
	// 最初のステップ（エラーなし）
	mockStep1 := &ast.Step{
		ID: &ast.String{
			Value: "step_id",
			Pos:   &ast.Position{Line: 1, Col: 1},
		},
	}
	err := rule.VisitStep(mockStep1)
	if err != nil {
		t.Errorf("VisitStep() first step error = %v, wantErr %v", err, false)
	}
	
	// 同じIDの2つ目のステップ（エラーあり）
	mockStep2 := &ast.Step{
		ID: &ast.String{
			Value: "step_id", // 重複するID
			Pos:   &ast.Position{Line: 2, Col: 1},
		},
	}
	err = rule.VisitStep(mockStep2)
	if err != nil {
		t.Errorf("VisitStep() second step error = %v, wantErr %v", err, false)
	}
	
	// エラーが検出されていることを確認
	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errors))
		return
	}
	
	// エラーメッセージが正しいことを確認
	if !strings.Contains(errors[0].Message, "duplicate") {
		t.Errorf("Error message does not contain 'duplicate': %s", errors[0].Message)
	}
	
	// エラーの位置情報が正しいことを確認
	if errors[0].Position.Line != 2 || errors[0].Position.Col != 1 {
		t.Errorf("Error position = %v, want {Line: 2, Col: 1}", errors[0].Position)
	}
}

func TestRuleID_validateConvention(t *testing.T) {
	rule := IDRule()
	
	testCases := []struct {
		name     string
		idValue  string
		what     string
		wantErr  bool
	}{
		{"valid_id", "valid_id", "job", false},
		{"valid_with_hyphen", "valid-id", "job", false},
		{"valid_with_numbers", "valid123", "job", false},
		{"valid_underscore_start", "_valid", "job", false},
		{"invalid_space", "invalid id", "job", true},
		{"invalid_special_chars", "invalid@id", "job", true},
		{"invalid_starts_with_number", "1invalid", "job", true},
		{"invalid_starts_with_hyphen", "-invalid", "job", true},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// エラーの初期数を記録
			initialErrorCount := len(rule.Errors())
			
			// validateConventionを実行
			mockString := &ast.String{
				Value: tc.idValue,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}
			rule.validateConvention(mockString, tc.what)
			
			// エラーが追加されたかどうかを確認
			currentErrorCount := len(rule.Errors())
			hasErr := currentErrorCount > initialErrorCount
			
			if hasErr != tc.wantErr {
				t.Errorf("validateConvention() for '%s' hasErr = %v, wantErr %v", tc.idValue, hasErr, tc.wantErr)
			}
		})
	}
}
```

#### TC-U-102: 環境変数チェックルールテスト

**テスト目的**: 環境変数ルールが正しく無効な環境変数名を検出できることを確認

**テスト内容**:
```go
func TestEnvironmentVariableChecker_validateEnvironmentVariables(t *testing.T) {
	checker := EnvironmentVariableRule()
	
	testCases := []struct {
		name     string
		envVars  []*ast.EnvVar
		wantErrs int
	}{
		{
			name: "valid_env_vars",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "VALID_VAR", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
				{
					Name:  &ast.String{Value: "VALID_VAR2", Pos: &ast.Position{Line: 2, Col: 1}},
					Value: &ast.String{Value: "value2"},
				},
			},
			wantErrs: 0,
		},
		{
			name: "invalid_env_var_with_space",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "INVALID VAR", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
			},
			wantErrs: 1,
		},
		{
			name: "invalid_env_var_with_equal",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "INVALID=VAR", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
			},
			wantErrs: 1,
		},
		{
			name: "invalid_env_var_with_ampersand",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "INVALID&VAR", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
			},
			wantErrs: 1,
		},
		{
			name: "mixed_valid_and_invalid",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "VALID_VAR", Pos: &ast.Position{Line: 1, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
				{
					Name:  &ast.String{Value: "INVALID VAR", Pos: &ast.Position{Line: 2, Col: 1}},
					Value: &ast.String{Value: "value"},
				},
			},
			wantErrs: 1,
		},
		{
			name: "env_var_with_expression",
			envVars: []*ast.EnvVar{
				{
					Name:  &ast.String{Value: "${{ expr }}", Pos: &ast.Position{Line: 1, Col: 1}, BaseNode: &yaml.Node{}},
					Value: &ast.String{Value: "value"},
				},
			},
			wantErrs: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// エラーをリセット
			checker = EnvironmentVariableRule()
			
			// Envオブジェクトの作成
			env := &ast.Env{
				Vars: tc.envVars,
			}
			
			// 環境変数の検証
			checker.validateEnvironmentVariables(env)
			
			// エラー数の確認
			if len(checker.Errors()) != tc.wantErrs {
				t.Errorf("validateEnvironmentVariables() errors = %d, want %d", len(checker.Errors()), tc.wantErrs)
			}
		})
	}
}
```

#### TC-U-103: コミットSHA検証ルールテスト

**テスト目的**: コミットSHAルールが正しくフルレングスのSHAを検証できることを確認

**テスト内容**:
```go
func TestCommitSha_VisitStep(t *testing.T) {
	rule := CommitShaRule()
	
	testCases := []struct {
		name      string
		uses      string
		wantError bool
	}{
		{
			name:      "full_length_sha",
			uses:      "actions/checkout@a12345678901234567890123456789012345678",
			wantError: false,
		},
		{
			name:      "short_sha",
			uses:      "actions/checkout@v3",
			wantError: true,
		},
		{
			name:      "tag_reference",
			uses:      "actions/checkout@main",
			wantError: true,
		},
		{
			name:      "expression_reference",
			uses:      "${{ github.action }}",
			wantError: false, // 式は検証しない
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// テストケース毎にルールをリセット
			rule = CommitShaRule()
			
			// モックステップの作成
			mockStep := &ast.Step{
				Pos: &ast.Position{Line: 1, Col: 1},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: tc.uses,
						Pos:   &ast.Position{Line: 1, Col: 10},
					},
				},
			}
			
			// ステップの検証
			err := rule.VisitStep(mockStep)
			
			// エラー返却値の確認
			if err != nil {
				t.Errorf("VisitStep() error = %v, wantErr = false", err)
			}
			
			// エラーが検出されたかどうかの確認
			hasError := len(rule.Errors()) > 0
			if hasError != tc.wantError {
				t.Errorf("VisitStep() hasError = %v, wantError %v", hasError, tc.wantError)
			}
		})
	}
}

func TestCommitSha_isFullLengthSha(t *testing.T) {
	testCases := []struct {
		name  string
		ref   string
		isLong bool
	}{
		{
			name:  "full_length_sha",
			ref:   "actions/checkout@a12345678901234567890123456789012345678",
			isLong: true,
		},
		{
			name:  "short_sha",
			ref:   "actions/checkout@a123456",
			isLong: false,
		},
		{
			name:  "tag_reference",
			ref:   "actions/checkout@v3",
			isLong: false,
		},
		{
			name:  "branch_reference",
			ref:   "actions/checkout@main",
			isLong: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isFullLengthSha(tc.ref)
			if result != tc.isLong {
				t.Errorf("isFullLengthSha(%q) = %v, want %v", tc.ref, result, tc.isLong)
			}
		})
	}
}
```

#### TC-U-104: 自動修正機能テスト

**テスト目的**: 自動修正機能が正しく動作することを確認

**テスト内容**:
```go
func TestAutoFixer(t *testing.T) {
	// 基本的なAutoFixer実装のテスト
	t.Run("BaseFixer", func(t *testing.T) {
		fixer := &BaseAutoFixer{ruleName: "test-rule"}
		
		if fixer.RuleName() != "test-rule" {
			t.Errorf("RuleName() = %v, want %v", fixer.RuleName(), "test-rule")
		}
		
		if err := fixer.Fix(); err != nil {
			t.Errorf("Fix() error = %v, want nil", err)
		}
	})
	
	// StepFixerのテスト
	t.Run("StepFixer", func(t *testing.T) {
		// モックのStepFixerインターフェースを実装
		mockFixer := &struct {
			BaseRule
		}{
			BaseRule: BaseRule{RuleName: "mock-rule"},
		}
		
		// StepFixerインターフェースのメソッドを追加
		mockFixer.RuleNames = func() string {
			return "mock-rule"
		}
		
		var fixCalled bool
		mockFixer.FixStep = func(node *ast.Step) error {
			fixCalled = true
			return nil
		}
		
		// モックのステップ
		mockStep := &ast.Step{
			Pos: &ast.Position{Line: 1, Col: 1},
		}
		
		// StepFixerの作成
		stepFixer := NewStepFixer(mockStep, mockFixer)
		
		// Fix()の呼び出し
		err := stepFixer.Fix()
		
		// エラーがないことを確認
		if err != nil {
			t.Errorf("Fix() error = %v, want nil", err)
		}
		
		// FixStep()が呼ばれたことを確認
		if !fixCalled {
			t.Errorf("FixStep() was not called")
		}
	})
	
	// JobFixerのテスト
	// ...
	
	// FuncFixerのテスト
	// ...
}
```

## 統合テスト仕様

### TC-I-001: ワークフロー検証統合テスト

**テスト目的**: 複数のルールが統合されて、ワークフローファイル全体を正しく検証できることを確認

**テスト内容**:
```go
func TestIntegration_WorkflowValidation(t *testing.T) {
	// 有効なワークフローファイルで、複数のエラーを含むテスト
	workflowYAML := `
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3  # コミットSHAエラー
      - id: step1
        run: |
          echo ::set-output name=test::value  # 非推奨コマンドエラー
      - id: step1  # IDの重複エラー
        run: |
          echo "Doing something"
      - name: Set environment variable
        env:
          INVALID VAR: value  # 無効な環境変数名エラー
        run: echo "Hello"
`
	
	// Linter設定
	var out bytes.Buffer
	linter, _ := NewLinter(&out, &LinterOptions{})
	
	// ワークフローをリント
	results, err := linter.LintFiles([]string{"test-workflow.yml"}, []byte(workflowYAML))
	
	// エラーがないことを確認
	if err != nil {
		t.Fatalf("LintFiles() error = %v", err)
	}
	
	// 結果が1つあることを確認
	if len(results) != 1 {
		t.Fatalf("LintFiles() returned %d results, want 1", len(results))
	}
	
	// 特定のルールのエラーを確認
	result := results[0]
	errorsByRule := make(map[string]int)
	for _, err := range result.Errors {
		errorsByRule[err.RuleName]++
	}
	
	// 各ルールで期待するエラー数を確認
	expectedErrors := map[string]int{
		"commit-sha":           1, // コミットSHAエラー
		"deprecated-commands":  1, // 非推奨コマンドエラー
		"id":                   1, // ID重複エラー
		"env-var":              1, // 無効な環境変数名エラー
	}
	
	for ruleName, expectedCount := range expectedErrors {
		if count, exists := errorsByRule[ruleName]; !exists || count < expectedCount {
			t.Errorf("Expected at least %d errors for rule %s, got %d", expectedCount, ruleName, count)
		}
	}
}
```

### TC-I-002: SARIF出力統合テスト

**テスト目的**: エラーがSARIF形式で正しく出力されることを確認

**テスト内容**:
```go
func TestIntegration_SARIFOutput(t *testing.T) {
	// エラーを含むワークフローファイル
	workflowYAML := `
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set output
        run: |
          echo ::set-output name=test::value
`
	
	// カスタム出力フォーマットを設定
	var out bytes.Buffer
	linter, _ := NewLinter(&out, &LinterOptions{
		CustomErrorMessageFormat: "{{sarif .}}",
	})
	
	// ワークフローをリント
	results, _ := linter.LintFiles([]string{"test-workflow.yml"}, []byte(workflowYAML))
	
	// SARIFフォーマットでエラーを出力
	var outputBuffer bytes.Buffer
	errorFormatter := linter.errorFormatter
	for _, result := range results {
		for _, err := range result.Errors {
			formattedErr, formatErr := errorFormatter.Format(&TemplateFields{
				Filepath: result.FilePath,
				Line:     err.Position.Line,
				Column:   err.Position.Col,
				Message:  err.Message,
				Type:     err.RuleName,
				Snippet:  "", // スニペットは省略
			})
			
			if formatErr != nil {
				t.Fatalf("Error formatting: %v", formatErr)
			}
			
			outputBuffer.WriteString(formattedErr)
		}
	}
	
	// SARIF形式の確認
	output := outputBuffer.String()
	
	// JSONとして有効であることを確認
	var sarifData map[string]interface{}
	if err := json.Unmarshal([]byte(output), &sarifData); err != nil {
		t.Fatalf("Invalid SARIF JSON: %v", err)
	}
	
	// SARIFの基本構造を確認
	if _, exists := sarifData["version"]; !exists {
		t.Errorf("SARIF output missing 'version' field")
	}
	
	if _, exists := sarifData["runs"]; !exists {
		t.Errorf("SARIF output missing 'runs' field")
	}
	
	// ツール名の確認
	runs, _ := sarifData["runs"].([]interface{})
	if len(runs) > 0 {
		run := runs[0].(map[string]interface{})
		tool, hasTools := run["tool"].(map[string]interface{})
		
		if hasTools {
			driver, hasDriver := tool["driver"].(map[string]interface{})
			if hasDriver {
				name, hasName := driver["name"].(string)
				if !hasName || name != "sisakulint" {
					t.Errorf("Expected tool name 'sisakulint', got %v", name)
				}
			} else {
				t.Errorf("SARIF output missing 'tool.driver' field")
			}
		} else {
			t.Errorf("SARIF output missing 'tool' field")
		}
	} else {
		t.Errorf("SARIF output has no runs")
	}
}
```

### TC-I-003: 自動修正統合テスト

**テスト目的**: 検出されたエラーが自動的に修正されることを確認

**テスト内容**:
```go
func TestIntegration_AutoFix(t *testing.T) {
	// タイムアウト設定がないワークフローファイル
	workflowYAML := `
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: echo "Hello"
`
	
	// テスト用の一時ファイルを作成
	tempFile, err := os.CreateTemp("", "test-workflow-*.yml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	
	if _, err := tempFile.Write([]byte(workflowYAML)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tempFile.Close()
	
	// コマンド実行をシミュレート
	var stdout, stderr bytes.Buffer
	cmd := Command{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	
	// 自動修正フラグ付きで実行
	exit := cmd.Main([]string{"sisakulint", "-fix", "on", tempFile.Name()})
	
	// エラーなく終了することを確認
	if exit == ExitStatusFailure {
		t.Errorf("Command failed with error: %s", stderr.String())
	}
	
	// 修正後のファイルを読み込み
	fixedContent, err := os.ReadFile(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to read fixed file: %v", err)
	}
	
	// タイムアウト設定が追加されていることを確認
	if !strings.Contains(string(fixedContent), "timeout-minutes:") {
		t.Errorf("Expected timeout-minutes to be added, but it wasn't")
	}
}
```

## E2Eテスト仕様

### TC-E-001: コマンドライン実行 E2Eテスト

**テスト目的**: コマンドラインツールとして正しく機能することを確認

**テスト内容**:
```go
func TestE2E_CommandLineExecution(t *testing.T) {
	// 実際のコマンド実行をスキップするテスト用フラグ
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	// テストワークフロー用の一時ディレクトリを作成
	tempDir, err := os.MkdirTemp("", "sisakulint-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// .github/workflows ディレクトリを作成
	workflowsDir := filepath.Join(tempDir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatalf("Failed to create workflows directory: %v", err)
	}
	
	// テストワークフローファイルを作成
	workflowPath := filepath.Join(workflowsDir, "test.yml")
	workflowContent := `
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
`
	
	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("Failed to write workflow file: %v", err)
	}
	
	// バイナリのパスを取得
	binPath := os.Getenv("SISAKULINT_BIN")
	if binPath == "" {
		// テスト環境で適切にビルドされたバイナリが必要
		t.Skip("SISAKULINT_BIN environment variable not set")
	}
	
	// コマンド実行
	cmd := exec.Command(binPath)
	cmd.Dir = tempDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err = cmd.Run()
	
	// エラーが検出されるべき（コミットSHAエラー）
	if err == nil {
		t.Errorf("Expected command to exit with non-zero status")
	}
	
	// 出力にコミットSHAに関するエラーが含まれることを確認
	if !strings.Contains(stdout.String(), "commit-sha") && !strings.Contains(stderr.String(), "commit-sha") {
		t.Errorf("Expected output to contain commit-sha error")
	}
}
```

### TC-E-002: リポジトリスキャン E2Eテスト

**テスト目的**: リポジトリを自動的にスキャンしてワークフローファイルを見つけられることを確認

**テスト内容**:
```go
func TestE2E_RepositoryScan(t *testing.T) {
	// 実際のコマンド実行をスキップするテスト用フラグ
	if testing.Short() {
		t.Skip("Skipping E2E tests in short mode")
	}
	
	// テスト用の複雑なディレクトリ構造を作成
	tempDir, err := os.MkdirTemp("", "sisakulint-scan-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// ネストしたディレクトリ構造を作成
	nestedDir := filepath.Join(tempDir, "project", "subproject", ".github", "workflows")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		t.Fatalf("Failed to create nested directory: %v", err)
	}
	
	// テストワークフローファイルを作成
	workflowPath := filepath.Join(nestedDir, "test.yml")
	workflowContent := `
name: Test Workflow
on:
  push:
    branches: [ main ]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: echo "Hello"
`
	
	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("Failed to write workflow file: %v", err)
	}
	
	// バイナリのパスを取得
	binPath := os.Getenv("SISAKULINT_BIN")
	if binPath == "" {
		t.Skip("SISAKULINT_BIN environment variable not set")
	}
	
	// サブディレクトリからコマンド実行
	projectDir := filepath.Join(tempDir, "project", "subproject")
	cmd := exec.Command(binPath)
	cmd.Dir = projectDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	
	err = cmd.Run()
	
	// ワークフローファイルが見つかることを確認
	output := stdout.String() + stderr.String()
	if !strings.Contains(output, "test.yml") {
		t.Errorf("Expected output to mention test.yml, got: %s", output)
	}
}
```

## パフォーマンステスト仕様

### TC-P-001: 大規模リポジトリパフォーマンステスト

**テスト目的**: 多数のワークフローファイルを含む大規模リポジトリでのパフォーマンスを評価

**テスト内容**:
```go
func TestPerformance_LargeRepository(t *testing.T) {
	// 実際のパフォーマンステストをスキップするテスト用フラグ
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	// テスト用の大規模ディレクトリ構造を作成
	tempDir, err := os.MkdirTemp("", "sisakulint-perf-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// .github/workflows ディレクトリを作成
	workflowsDir := filepath.Join(tempDir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatalf("Failed to create workflows directory: %v", err)
	}
	
	// 多数のワークフローファイルを生成
	fileCount := 100
	for i := 0; i < fileCount; i++ {
		workflowPath := filepath.Join(workflowsDir, fmt.Sprintf("workflow-%03d.yml", i))
		workflowContent := fmt.Sprintf(`
name: Workflow %03d
on:
  push:
    branches: [ main ]
jobs:
  build-%03d:
    runs-on: ubuntu-latest
    steps:
      - name: Test
        run: echo "Hello from workflow %d"
`, i, i, i)
		
		if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
			t.Fatalf("Failed to write workflow file: %v", err)
		}
	}
	
	// Linterのパフォーマンス測定
	var out bytes.Buffer
	linter, _ := NewLinter(&out, &LinterOptions{})
	
	startTime := time.Now()
	results, err := linter.LintRepository(tempDir)
	duration := time.Since(startTime)
	
	if err != nil {
		t.Fatalf("LintRepository() error = %v", err)
	}
	
	// 結果の確認
	if len(results) != fileCount {
		t.Errorf("Expected %d results, got %d", fileCount, len(results))
	}
	
	// パフォーマンス要件の確認（例: 100ファイルを10秒以内で処理）
	if duration > 10*time.Second {
		t.Errorf("Performance below threshold: took %v to process %d files, expected under 10s", duration, fileCount)
	} else {
		t.Logf("Performance OK: took %v to process %d files", duration, fileCount)
	}
}
```

## テスト環境設定

### 環境変数

```go
func TestMain(m *testing.M) {
	// テスト環境変数の設定
	os.Setenv("SISAKULINT_TEST_MODE", "true")
	
	// GitHub API呼び出しをモック化
	mockGitHubAPI()
	
	// テスト実行
	exitCode := m.Run()
	
	// テスト後のクリーンアップ
	os.Unsetenv("SISAKULINT_TEST_MODE")
	
	os.Exit(exitCode)
}

func mockGitHubAPI() {
	// GitHub API呼び出しのモック化（コミットSHAテスト用）
	// ここにモック実装を記述...
}
```

### テストヘルパー

```go
// ルール用のモックワークフロー作成ヘルパー
func createMockWorkflow() *ast.Workflow {
	return &ast.Workflow{
		Name: &ast.String{Value: "Test Workflow", Pos: &ast.Position{Line: 1, Col: 1}},
		On: []ast.Event{
			&ast.WebhookEvent{
				Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 3, Col: 3}},
				Branches: &ast.WebhookEventFilter{
					Name: &ast.String{Value: "branches", Pos: &ast.Position{Line: 4, Col: 5}},
					Values: []*ast.String{
						{Value: "main", Pos: &ast.Position{Line: 5, Col: 7}},
					},
				},
			},
		},
		Jobs: map[string]*ast.Job{
			"build": {
				ID:      &ast.String{Value: "build", Pos: &ast.Position{Line: 7, Col: 3}},
				RunsOn:  &ast.String{Value: "ubuntu-latest", Pos: &ast.Position{Line: 8, Col: 13}},
				Steps:   []*ast.Step{},
				BaseNode: &yaml.Node{},
				Pos:     &ast.Position{Line: 7, Col: 3},
			},
		},
		BaseNode: &yaml.Node{},
		Pos:     &ast.Position{Line: 1, Col: 1},
	}
}

// エラー検出ヘルパー
func hasErrorOfType(errors []*LintingError, ruleName string) bool {
	for _, err := range errors {
		if err.RuleName == ruleName {
			return true
		}
	}
	return false
}

// YAML文字列からASTを作成するヘルパー
func parseYAMLToWorkflow(t *testing.T, yamlStr string) *ast.Workflow {
	workflow, err := ParseMain([]byte(yamlStr))
	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
		return nil
	}
	return workflow
}
```

## 不足テストの優先順位

### 高優先度（即座に実装推奨）
1. **主要ルールの単体テスト**: コミットSHAルール、タイムアウトルールなど実装されていないルールのテスト
2. **リンター本体のテスト**: Linterコア機能のテスト
3. **コマンドライン引数処理テスト**: 様々な引数パターンのテスト

### 中優先度（次のスプリントで実装）
1. **統合テスト**: 複数ルールが連携するテスト
2. **自動修正テスト**: 様々な修正シナリオのテスト
3. **設定ファイル処理テスト**: カスタム設定のテスト

### 低優先度（継続的改善として実装）
1. **E2Eテスト**: 実際のコマンドライン実行テスト
2. **パフォーマンステスト**: 大規模リポジトリでのパフォーマンステスト
3. **多言語対応テスト**: 異なるロケールでの動作テスト