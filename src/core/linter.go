package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"golang.org/x/sync/errgroup"
)

// LogLevel は Linter インスタンスで使用されるログレベルを表す型
type LogLevel int

const (
	// LogLevelNoOutputは、ログ出力が無いことを示す。
	LogLevelNoOutput LogLevel = 0
	// LogLevelDetailedOutputは、詳細なログ出力が有効であることを示す。
	LogLevelDetailedOutput = 1
	// LogLevelAllOutputIncludingDebugは、デバッグ情報を含むすべてのログ出力が有効であることを示す。
	LogLevelAllOutputIncludingDebug = 2
)

// OutputColorBehaviorは、出力の色付けの挙動を表す
type OutputColorBehavior int

const (
	// AutoColorは、出力の色付けを自動的に決定
	AutoColor OutputColorBehavior = iota
	// AlwaysColorは、常に出力を色付け
	AlwaysColor
	// NeverColorは、出力を色付けしない
	NeverColor
)

// この構造体は、NewLinter factory関数の呼び出しで使用
// 0値LinterOptions{}は、デフォルトの挙動
type LinterOptions struct {
	// IsVerboseOutputEnabledは、詳細なログ出力が有効であるかどうかを示すflag
	IsVerboseOutputEnabled bool
	// IsDebugOutputEnabledは、Debuglogの出力が有効であるかどうかを示すflag
	IsDebugOutputEnabled bool
	// LogOutputDestinationは、ログ出力を出力するためのio.Writerオブジェクト
	//todo: NOTICE: エラー出力はログ出力に含まれない
	LogOutputDestination io.Writer
	// OutputColorOptionは、エラー出力の色付けのオプション
	//それぞれの列挙値については、ColorOptionKindのドキュメントを参照
	OutputColorOption OutputColorBehavior
	// IsOneLineOutputEnabledは、1行出力が有効であるかどうかを示すflag, 出力をプログラムから読み取る際に便利なはず
	IsOneLineOutputEnabled bool
	// ShellcheckExecutableは、shellcheckを実行するための実行可能ファイル
	ShellcheckExecutable string
	// ErrorIgnorePatternsは、エラーをフィルタリングするための正規表現のリスト
	ErrorIgnorePatterns []string
	// ConfigurationFilePathは、設定ファイルのパス
	ConfigurationFilePath string
	// CustomErrorMessageFormatは、エラーメッセージをフォーマットするためのカスタムテンプレート
	CustomErrorMessageFormat string
	// StdinInputFileNameは、標準入力から読み込む際のファイル名
	StdinInputFileName string
	// CurrentWorkingDirectoryPathは、現在の作業ディレクトリのパス
	CurrentWorkingDirectoryPath string
	//todo: OnCheckRulesModifiedは、チェックルールの追加や削除を行うフック
	OnCheckRulesModified func([]Rule) []Rule
}

// Linterは、workflowをlintするための構造体
type Linter struct {
	// projectsは、プロジェクト情報を管理する構造体
	projectInformation *Projects
	// errorOutputは、Linterからのエラー出力に使用されるio.Writerオブジェクト
	errorOutput io.Writer
	// logOutputは、ログ出力に使用されるio.Writerオブジェクト
	logOutput io.Writer
	// loggingLevelは、Linterのログレベルを示す
	loggingLevel LogLevel
	// oneLineOutputEnabledは、エラー出力を1行ごとにするかどうかのflag
	oneLineOutputEnabled bool
	// shellcheckExecutableは、shellcheckの実行可能ファイルのパスまたは名前
	shellcheckExecutablePath string
	// errorIgnorePatternsは、エラーを無視するための正規表現パターンのリスト
	errorIgnorePatterns []*regexp.Regexp
	// defaultConfigurationは、sisakulintのデフォルトの設定を保持する構造体
	defaultConfiguration *Config
	// errorFormatterは、エラーメッセージをカスタムフォーマットで出力するためのformatter
	errorFormatter *ErrorFormatter
	// currentWorkingDirectoryは、現在の作業ディレクトリのパス
	currentWorkingDirectory string
	//todo: modifyCheckRulesは、チェックルールを追加または削除するためのフック関数
	modifyCheckRules func([]Rule) []Rule
}

// NewLinterは新しいLinterインスタンスを作成する
// outパラメータは、Linterインスタンスからのエラーを出力するために使用される。出力を望まない場合は、io.Discardを設定してください。
// optsパラメータは、lintの動作を設定するLinterOptionsインスタンス
func NewLinter(errorOutput io.Writer, options *LinterOptions) (*Linter, error) {
	//log levelの設定
	var logLevel LogLevel = LogLevelNoOutput
	if options.IsVerboseOutputEnabled {
		logLevel = LogLevelDetailedOutput
	} else if options.IsDebugOutputEnabled {
		logLevel = LogLevelAllOutputIncludingDebug
	}
	if options.OutputColorOption == NeverColor {
		color.NoColor = true
	} else if options.OutputColorOption == AlwaysColor {
		color.NoColor = false
	}
	//カラフル出力
	if file, ok := errorOutput.(*os.File); ok {
		errorOutput = colorable.NewColorable(file)
	}

	//logの出力の設定
	logOutput := io.Discard
	if options.LogOutputDestination != nil {
		logOutput = options.LogOutputDestination
	}

	//設定ファイルの読み込み
	var config *Config
	if options.ConfigurationFilePath != "" {
		con, err := ReadConfigFile(options.ConfigurationFilePath)
		if err != nil {
			return nil, err
		}
		config = con
	}

	ignorePatterns := make([]*regexp.Regexp, len(options.ErrorIgnorePatterns))
	for i, pattern := range options.ErrorIgnorePatterns {
		re , err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid error ignore pattern : %q : %w", pattern, err)
		}
		ignorePatterns[i] = re
	}

	//エラーメッセージのフォーマットの作成
	var errorFormatter *ErrorFormatter
	if options.CustomErrorMessageFormat != "" {
		formatter, err := NewErrorFormatter(options.CustomErrorMessageFormat)
		if err != nil {
			return nil, err
		}
		errorFormatter = formatter
	}

	//working directoryの取得
	workDir := options.CurrentWorkingDirectoryPath
	if workDir == "" {
		if dir, err := os.Getwd(); err == nil {
			workDir = dir
		}
	}

	return &Linter{
			NewProjects(),
			errorOutput,
			logOutput,
			logLevel,
			options.IsOneLineOutputEnabled,
			options.ShellcheckExecutable,
			ignorePatterns,
			config,
			errorFormatter,
			workDir,
			options.OnCheckRulesModified,
	}, nil
}

//logはlog levelがDetailedOutput以上の場合にログを出力する
func (l *Linter) log(args ...interface{}) {
	if l.loggingLevel < LogLevelDetailedOutput {
		return
	}
	fmt.Fprint(l.logOutput, "verbose(詳細): ")
	fmt.Fprintln(l.logOutput, args...)
}

//debugはlog levelがAllOutputIncludingDebug以上の場合にログを出力する
func (l *Linter) debug(format string, args ...interface{}) {
	if l.loggingLevel < LogLevelAllOutputIncludingDebug {
		return
	}
	message := fmt.Sprintf("[linter mode] %s\n", format)
	fmt.Fprintf(l.logOutput, message, args...)
}

//debugWriterはlog levelがAllOutputIncludingDebug以上の場合にログを出力する
func (l *Linter) debugWriter() io.Writer {
	if l.loggingLevel < LogLevelAllOutputIncludingDebug {
		return nil
	}
	return l.logOutput
}

//GenerateDefaultConfigは、指定されたディレクトリにデフォルトの設定ファイルを生成する
/* func (l *Linter) GenerateDefaultConfig(dir string) error {
	l.log("generating default configuration file...", dir)

	project, err := l.projectInformation.GetProjectForPath(dir)
	if err != nil {
		return err
	}
	if project == nil {
		return errors.New("project not found, Make sure the current project is initialized as a Git repository and the \".github/workflows\" directory exists")
	}

	configPath := filepath.Join(project.RootDirectory(), ".github", "sisakulint.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists: %q", configPath)
	}

	if err := writeDefaultConfigFile(configPath); err != nil {
		return err
	}

	fmt.Fprintf(l.errorOutput, "generated default config file: %q\n", configPath)
	return nil
} */

//LintRepositoryは、指定されたディレクトリのリポジトリをリントする
func (l *Linter) LintRepository(dir string) ([]*LintingError, error) {
	l.log("linting repository...", dir)

	project, err := l.projectInformation.GetProjectForPath(dir)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, errors.New("project not found")
	}
	l.log("Detected project:", project.RootDirectory())
	workflowsDir := project.WorkflowDirectory()
	return l.LintDir(workflowsDir, project)
}

//LintDirは、指定されたディレクトリをLint
func (l *Linter) LintDir(dir string, project *Project) ([]*LintingError, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("it could not read %q , failed to walk directory: %w", dir, err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in %q", dir)
	}
	l.log("the number of corrected yaml file", len(files), "yaml files")

	//sort order of filepaths
	sort.Strings(files)

	return l.LintFiles(files, project)
}

//lintFilesは、指定されたyaml workflowをlintしてエラーを返す
//projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) LintFiles(filepaths []string, project *Project) ([]*LintingError, error) {
	fileCount := len(filepaths)
	switch fileCount {
	case 0:
		//return nil, errors.New("no yaml files found")
		return []*LintingError{}, nil
	case 1:
		return l.LintFile(filepaths[0], project)
	}

	l.log("linting", fileCount, "get started linting workflows...files")

	currentDir := l.currentWorkingDirectory
	proc := NewConcurrentExecutor(runtime.NumCPU()) //process.go
	debugLog := l.debugWriter()
	actionCacheFactory := NewLocalActionsMetadataCacheFactory(debugLog) //metadata.go
	reusableWorkflowCacheFactory := NewLocalReusableWorkflowCacheFactory(currentDir, debugLog) //reusing-workflow.go

	type workspace struct {
		path string
		errors []*LintingError
		source []byte
	}
	workspaces := make([]workspace, len(filepaths))
	for i, pa := range filepaths {
		//workspaces = append(workspaces, workspace{path: pa})
		workspaces[i] = workspace{path: pa}
	}

	errorGroups := errgroup.Group{}
	for i := range workspaces {
		ws := &workspaces[i]
		localProject := project
		if localProject == nil {
			// このメソッドはl.projectInformationの状態を変更するため、並行して呼び出せない。
			// goroutineを開始する前に、プロジェクトのインスタンスを解決してください。
			projectForPath, err := l.projectInformation.GetProjectForPath(ws.path)
			if err != nil {
				return nil, err
			}
			localProject = projectForPath
		}
		actionCache := actionCacheFactory.GetCache(localProject) //[173]
		reusableWorkflowCache := reusableWorkflowCacheFactory.GetCache(localProject)

		errorGroups.Go(func() error {
			source, err := os.ReadFile(ws.path)
			if err != nil {
				return fmt.Errorf("%q could not read workflow file: %w", ws.path, err)
			}
			if currentDir != "" {
				if relPath, err := filepath.Rel(currentDir, ws.path); err == nil {
					ws.path = relPath //相対パスの活用
				}
			}
			errors, err := l.validate(ws.path, source, localProject, proc, actionCache, reusableWorkflowCache)
			if err != nil {
				return fmt.Errorf("occur error when check %s: %w", ws.path, err)
			}
			ws.source = source
			ws.errors = errors
			return nil
		})
    }

	proc.Wait()
	if err := errorGroups.Wait(); err != nil {
		return nil, err
	}

	totalErrors := 0
	for i := range workspaces {
		totalErrors += len(workspaces[i].errors)
	}

	allErrors := make([]*LintingError, 0, totalErrors)
		if l.errorFormatter != nil {
			templateFields := make([]*TemplateFields, 0, totalErrors)
			for i := range workspaces{
				wanda := &workspaces[i]
				for _, err := range wanda.errors {
					templateFields = append(templateFields, err.ExtractTemplateFields(wanda.source))
				}
				allErrors = append(allErrors, wanda.errors...)
			}
			if err := l.errorFormatter.Print(l.errorOutput, templateFields); err != nil{
				return nil, err
			}
		} else {
			for i := range workspaces {
				ws := &workspaces[i]
				l.displayErrors(ws.errors, ws.source)
				allErrors = append(allErrors, ws.errors...)
			}
		}
		l.log("Detected", totalErrors, "errors in", fileCount, "files checked")

	return allErrors, nil
}

//LintFileは、指定されたyaml workflowをlintしてエラーを返す
//projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) LintFile(file string, project *Project) ([]*LintingError, error) {
	if project == nil {
		pa, err := l.projectInformation.GetProjectForPath(file)
		if err != nil {
			return nil, err
		}
		project = pa
	}
	source, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read %q workflow file: %w", file, err)
	}
	if l.currentWorkingDirectory != "" {
		if r, err := filepath.Rel(l.currentWorkingDirectory, file); err == nil {
			file = r
		}
	}
	//todo: process.go
	proc := NewConcurrentExecutor(runtime.NumCPU())
	//todo: action_metadata.go
	localActions := NewLocalActionsMetadataCache(project, l.debugWriter())
	//todo: reusing-workflows.go
	localReusableWorkflow := NewLocalReusableWorkflowCache(project, l.currentWorkingDirectory, l.debugWriter())
	errors, err := l.validate(file, source, project, proc, localActions, localReusableWorkflow)
	proc.Wait()

	if err != nil {
		return nil, err
	}
	if l.errorFormatter != nil {
		l.errorFormatter.PrintErrors(l.errorOutput, errors, source)
	} else {
		l.displayErrors(errors, source)
	}
	return errors, nil
}

//Lintはbyteのスライスとして与えられたyaml workflowをlintしてエラーを返す
//pathパラメタは、コンテンツがどこからきたのかを示すfilepathとして使用
//pathパラメタに<stdin>を入力すると出力がSTDINから来たことを示す
//projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) Lint(filepath string, content []byte, project *Project) ([]*LintingError, error) {
	if project == nil && filepath != "<stdin>" {
		if _, err := os.Stat(filepath); !errors.Is(err, fs.ErrNotExist) {
			p, err := l.projectInformation.GetProjectForPath(filepath)
			if err != nil {
				return nil, err
			}
			project = p
		}
	}

	proc := NewConcurrentExecutor(runtime.NumCPU())
	localActions := NewLocalActionsMetadataCache(project, l.debugWriter())
	localReusableWorkflow := NewLocalReusableWorkflowCache(project, l.currentWorkingDirectory, l.debugWriter())
	errors, err := l.validate(filepath, content, project, proc, localActions, localReusableWorkflow)
	proc.Wait()
	if err != nil {
		return nil, err
	}

	if l.errorFormatter != nil {
		l.errorFormatter.PrintErrors(l.errorOutput, errors, content)
	} else {
		l.displayErrors(errors, content)
	}
	return errors, nil
}

func (l *Linter) validate(
	filePath string,
	content []byte,
	project *Project,
	proc *ConcurrentExecutor,
	localActions *LocalActionsMetadataCache,
	localReusableWorkflow *LocalReusableWorkflowCache,
) ([]*LintingError, error) {

	var validationStart time.Time
	if l.loggingLevel >= LogLevelDetailedOutput {
		validationStart = time.Now()
	}

	l.log("validating workflow..." , filePath)
	if project != nil {
		l.log("Detected project:", project.RootDirectory())
	}

	var cfg *Config
	if l.defaultConfiguration != nil {
		cfg = l.defaultConfiguration
	} else if project != nil {
		cfg = project.ProjectConfig()
	}
	if cfg != nil {
		l.debug("setting configration: %#v", cfg)
	} else {
		l.debug("no configuration file")
	}

	parsedWorkflow, allErrors := Parse(content)

	if l.loggingLevel >= LogLevelDetailedOutput {
		elapsed := time.Since(validationStart)
		l.log("parsed workflow in", len(allErrors), elapsed.Milliseconds(), "ms", filePath)
	}

	if parsedWorkflow != nil {
		dbg :=l.debugWriter()

		rules := []Rule{
			/* MatrixRule(),
			CredentialsRule(),
			ShellNameRule(),
			RunnerLabelRule(),
			EventsRule(),
			JobDependenciesRule(),
			ActionRule(localActions),*/
			EnvironmentVariableRule(),
			IDRule(),
			/*GlobPatternRule(),
			PermissionsRule(),
			WorkflowCallRule(path, localReusableWorkflows),
			ExpressionRule(localActions, localReusableWorkflows),
			DeprecatedCommandsRule(),
			ConditionalRule(), */
		}

		v := NewSyntaxTreeVisitor()
		for _, rule := range rules {
			v.AddVisitor(rule)
		}

		if dbg != nil {
			v.EnableDebugOutput(dbg)
			for _, rule := range rules {
				rule.EnableDebugOutput(dbg)
			}
		}
		if cfg != nil {
			for _, rule := range rules {
				rule.UpdateConfig(cfg)
			}
		}
		if err := v.VisitTree(parsedWorkflow); err != nil {
			l.debug("error occurred while visiting syntax tree: %v", err)
			return nil, err
		}

		for _, rule := range rules {
			errs := rule.Errors()
			l.debug("%s found %d errors", rule.RuleNames(), len(errs))
			allErrors = append(allErrors, errs...)
		}

		for l.errorFormatter != nil {
			for _, rule := range rules {
				l.errorFormatter.RegisterRule(rule)
			}
		}
	}

	l.filterAndLogErrors(filePath, &allErrors, validationStart)

	return allErrors, nil
}

func (l *Linter) filterAndLogErrors(filePath string, allErrors *[]*LintingError, validationStart time.Time) {
	if len(l.errorIgnorePatterns) > 0 {
		filtered := make([]*LintingError, 0, len(*allErrors))
		for _, err := range *allErrors {
			ignored := false
			for _, pattern := range l.errorIgnorePatterns {
				if pattern.MatchString(err.Description) {
					ignored = true
					break
				}
			}
			if !ignored {
				filtered = append(filtered, err)
			}
		}
		*allErrors = filtered
	}
	for _, err := range *allErrors {
		err.FilePath = filePath
	}

	sort.Stable(ByRuleErrorPosition(*allErrors))

	if l.loggingLevel >= LogLevelDetailedOutput {
		elapsed := time.Since(validationStart)
		l.log(len(*allErrors), "errors found in", elapsed.Milliseconds(), "found in ms", filePath)
	}
}

//displayErrorsは、指定されたエラーを出力する
func (l *Linter) displayErrors(errors []*LintingError, source []byte) {
	if l.oneLineOutputEnabled {
		source = nil
	}
	for _, err := range errors {
		err.DisplayError(l.errorOutput, source)
	}
}
