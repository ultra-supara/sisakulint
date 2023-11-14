package core

import (
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// バージョンとインストール情報を保持する変数
var (
	versionInfo       = ""
	installationMethod = "installed by building from source"
)

const (
	// ExitStatusSuccessNoProblem はコマンドが成功し、問題が見つからなかった場合の終了ステータス
	ExitStatusSuccessNoProblem = 0
	// ExitStatusSuccessProblemFound はコマンドが成功し、問題が見つかった場合の終了ステータス
	ExitStatusSuccessProblemFound = 1
	// ExitStatusInvalidCommandOption はコマンドラインオプションの解析に失敗した場合の終了ステータス
	ExitStatusInvalidCommandOption = 2
	// ExitStatusFailure はワークフローをチェック中に何らかの致命的なエラーが発生してコマンドが停止した場合の終了ステータス
	ExitStatusFailure = 3
)

const commandUsageHeader = `Usage: sisakulint [FLAGS]

  sisakulint is a static and fast-executing linter for {.github/workflows/*.yaml or .*yml} files.

  To verify all YAML files in the current repository, simply execute sisakulint without any parameters.
  It will auto-detect the closest '.github/workflows' directory for you.

    $ sisakulint

  # "Note: You can enable the debug mode by running sisakulint with the -debug argument.
  # This will provide a detailed output of the syntax tree traversal,
  # including the analysis of each node and additional logs,
  # helping you to understand the internal workings and diagnose any issues."

    $ sisakulint -debug

Flags:`

func getCommandVersion() string {
	if versionInfo != "" {
		return versionInfo
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown" //sisakulint packageがmoduleの外部でbuildされた場合にのみ到達
	}

	return info.Main.Version
}

// Commandは全体のsisakulintコマンドを表します。与えられたstdin/stdout/stderrは入出力に使用
type Command struct {
	// Stdinはstdinから入力を読み込むためのリーダーです
	Stdin io.Reader
	// Stdoutはstdoutに出力を書き込むためのライターです
	Stdout io.Writer
	// Stderrはstderrに出力を書き込むためのライターです
	Stderr io.Writer
}

//todo: linterを実行して結果を返すメソッド
func (cmd *Command) runLint(args []string, linterOpts *LinterOptions, initConfig bool, generateBoilerplate bool) ([]*LintingError, error) {
	l, err := NewLinter(cmd.Stdout, linterOpts)
	if err != nil {
		return nil, err
	}

	if initConfig {
		return nil, l.GenerateDefaultConfig(".")
	}

	if generateBoilerplate {
		return nil, l.GenerateBoilerplate(".")
	}

	if len(args) == 0 {
		return l.LintRepository(".")
	}

	return l.LintFiles(args, nil)
}

type ignorePatternFlags []string

func (i *ignorePatternFlags) String() string {
	return "option for ignore patterns"
}
func (i *ignorePatternFlags) Set(v string) error {
	*i = append(*i, v)
	return nil
}

//todo: sisakulintのmain関数
func (cmd *Command) Main(args []string) int {
	var showVersion bool
	var linterOpts LinterOptions
	var ignorePats ignorePatternFlags
	var initConfig bool
	var generateBoilerplate bool

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(cmd.Stderr)
	flags.Var(&ignorePats, "ignore", "Regular expression matching to error messages you want to ignore. This flag is repeatable")
	flags.StringVar(&linterOpts.ShellcheckExecutable, "shellcheck", "shellcheck", "Command name or file path of \"shellcheck\" external command. If empty, shellcheck integration will be disabled")
	flags.BoolVar(&generateBoilerplate, "boilerplate", false, "Generate a costomized template file for GitHub Actions workflow")
	flags.StringVar(&linterOpts.CustomErrorMessageFormat, "format", "", "Custom template to format error messages in Go template syntax.")
	flags.StringVar(&linterOpts.ConfigurationFilePath, "config-file", "", "File path to config file")
	flags.BoolVar(&initConfig, "init", false, "Generate default config file at .github/sisaku.yaml in current project")
	//flags.BoolVar(&opa, "opa", false, "Enable Open Policy Agent (OPA) rules evaluation. When set, the tool will use OPA for additional policy checks or custom rule evaluations.")
	//flags.BoolVar(&disableColor, "never-color", false, "Disable colorful output")
	flags.BoolVar(&linterOpts.IsVerboseOutputEnabled, "verbose", false, "Enable verbose output")
	flags.BoolVar(&linterOpts.IsDebugOutputEnabled, "debug", false, "Enable debug output (for development)")
	flags.BoolVar(&showVersion, "version", false, "Show version and how this binary was installed")
	flags.StringVar(&linterOpts.StdinInputFileName, "stdin-filename", "", "File name when reading input from stdin")
	flags.Usage = func() {
		fmt.Fprintln(cmd.Stderr, commandUsageHeader)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			// -h or -help
			return ExitStatusSuccessNoProblem
		}
		return ExitStatusInvalidCommandOption
	}

	if showVersion {
		fmt.Fprintf(
			cmd.Stdout,
			"%s\n %s\n built with %s compiler for %s/%s\n",
			getCommandVersion(),
			installationMethod,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH,
		)
		return ExitStatusSuccessNoProblem
	}

	linterOpts.ErrorIgnorePatterns = ignorePats
	linterOpts.LogOutputDestination = cmd.Stderr

	errs, err := cmd.runLint(flags.Args(), &linterOpts, initConfig, generateBoilerplate)
	if err != nil {
		fmt.Fprintln(cmd.Stderr, err.Error())
		return ExitStatusFailure
	}
	if len(errs) > 0 {
		return ExitStatusSuccessProblemFound
		//問題があった場合、ここでlinterが指摘してくれる！やったね！
	}

	return ExitStatusSuccessNoProblem
}
