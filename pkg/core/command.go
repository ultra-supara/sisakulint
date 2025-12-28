package core

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"gopkg.in/yaml.v3"
)

// バージョンとインストール情報を保持する変数
var (
	versionInfo = ""
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

func printingUsageHeader(out io.Writer) {
	fmt.Fprintf(out, `Usage: sisakulint [FLAGS] [FILES...] [OPTIONS]

sisakulint is a static and fast-executing linter for {.github/workflows/*.yaml or .*yml} files.

To verify all YAML files in the current repository, simply execute sisakulint without any parameters.
It will auto-detect the closest '.github/workflows' directory for you.

$ sisakulint

# "Note: You can enable the debug mode by running sisakulint with the -debug argument.
# This will provide a detailed output of the syntax tree traversal,
# including the analysis of each node and additional logs,
# helping you to understand the internal workings and diagnose any issues."

$ sisakulint -debug

# "Note": it can be used in reviewdog by supporting sarif output,

$ sisakulint -format "{{sarif .}}"

# Documents
- https://sisaku-security.github.io/lint/

# Poster
- https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf

Flags:
`)
}

func getCommandVersion() string {
	var buildInfos []byte
	toolVersion := "unknown"
	if versionInfo != "" {
		toolVersion = "v" + versionInfo
	}
	buildInfos = fmt.Appendf(buildInfos, "Tool version: %s\n", toolVersion)
	buildInfos = fmt.Appendf(buildInfos, "Go version: %s\n", runtime.Version())
	buildInfos = fmt.Appendf(buildInfos, "OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	info, ok := debug.ReadBuildInfo()
	if ok {
		buildInfos = fmt.Appendf(buildInfos, "Build info:\n")
		for _, setting := range info.Settings {
			if setting.Key == "-buildmode" || setting.Key == "-compiler" ||
				strings.HasPrefix(setting.Key, "GO") ||
				strings.HasPrefix(setting.Key, "vcs") {
				buildInfos = fmt.Appendf(buildInfos, "%s=%s\n", setting.Key, setting.Value)
			}
		}
	}

	return string(buildInfos)
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

// todo: linterを実行して結果を返すメソッド
func (cmd *Command) runLint(args []string, linterOpts *LinterOptions, initConfig bool, generateBoilerplate bool) ([]*ValidateResult, error) {
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

func (cmd *Command) runAutofix(results []*ValidateResult, isDryRun bool) {
	for _, res := range results {
		if len(res.AutoFixers) == 0 {
			continue
		}
		for _, fixer := range res.AutoFixers {
			if err := fixer.Fix(); err != nil {
				var lintErr *LintingError
				if errors.As(err, &lintErr) {
					lintErr.FilePath = res.FilePath
					lintErr.DisplayError(cmd.Stderr, res.Source)
				} else {
					fmt.Fprintf(cmd.Stderr, "Error while fixing %s: %v\n", fixer.RuleName(), err)
				}
			}
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		err := enc.Encode(res.ParsedWorkflow.BaseNode)
		if err != nil {
			fmt.Fprintf(cmd.Stderr, "Error while marshaling the fixed workflow: %v\n", err)
		}
		data := buf.Bytes()
		if isDryRun {
			fmt.Fprintf(cmd.Stdout, "Fixed workflow %s:\n%s\n", res.FilePath, string(data))
		} else {
			err := os.WriteFile(res.FilePath, data, 0644)
			if err != nil {
				fmt.Fprintf(cmd.Stderr, "Error while writing the fixed workflow: %v\n", err)
				err := os.WriteFile(res.FilePath, res.Source, 0644) // restore the original file
				if err != nil {
					fmt.Fprintf(cmd.Stderr, "Error while restoring the original workflow: %v\n", err)
				}
			} else {
				fmt.Fprintf(cmd.Stdout, "Fixed workflow %s\n", res.FilePath)
			}
		}
	}
}

type ignorePatternFlags []string

func (i *ignorePatternFlags) String() string {
	return "option for ignore patterns"
}
func (i *ignorePatternFlags) Set(v string) error {
	*i = append(*i, v)
	return nil
}

// todo: sisakulintのmain関数
func (cmd *Command) Main(args []string) int {
	var showVersion bool
	var linterOpts LinterOptions
	var ignorePats ignorePatternFlags
	var initConfig bool
	var generateBoilerplate bool
	var autoFixMode string

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(cmd.Stderr)
	flags.Var(&ignorePats, "ignore", "Regular expression matching to error messages you want to ignore. This flag is repeatable")
	flags.BoolVar(&generateBoilerplate, "boilerplate", false, "Generate a costomized template file for GitHub Actions workflow")
	flags.StringVar(&linterOpts.CustomErrorMessageFormat, "format", "", "Custom template to format error messages in Go template syntax.")
	flags.StringVar(&linterOpts.ConfigurationFilePath, "config-file", "", "File path to config file")
	flags.BoolVar(&initConfig, "init", false, "Generate default config file at .github/action.yaml in current project. see : https://docs.github.com/ja/actions/creating-actions/metadata-syntax-for-github-actions#github-actions%E3%81%AEyaml%E6%A7%8B%E6%96%87%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6")
	flags.BoolVar(&linterOpts.IsVerboseOutputEnabled, "verbose", false, "Enable verbose output")
	flags.BoolVar(&linterOpts.IsDebugOutputEnabled, "debug", false, "Enable debug output (for development)")
	flags.BoolVar(&showVersion, "version", false, "Show version and how this binary was installed")
	flags.StringVar(&linterOpts.StdinInputFileName, "stdin-filename", "", "File name when reading input from stdin")
	flags.StringVar(&autoFixMode, "fix", "off", "Enable auto-fix mode. Available options: off, on, dry-run")

	flags.Usage = func() {
		printingUsageHeader(cmd.Stderr)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h or -help
			return ExitStatusSuccessNoProblem
		}
		return ExitStatusInvalidCommandOption
	}

	if autoFixMode != "off" && autoFixMode != "on" && autoFixMode != FileFixDryRun {
		fmt.Fprintf(cmd.Stderr, "Invalid value for -fix: %s\n", autoFixMode)
		return ExitStatusInvalidCommandOption
	}

	if showVersion {
		fmt.Fprintf(
			cmd.Stdout,
			"%s",
			getCommandVersion(),
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
		enableAutofix := autoFixMode == "on" || autoFixMode == FileFixDryRun
		if enableAutofix {
			cmd.runAutofix(errs, autoFixMode == FileFixDryRun)
		}
		return ExitStatusSuccessProblemFound
		//問題があった場合、ここでlinterが指摘してくれる！やったね！
	}

	return ExitStatusSuccessNoProblem
}
