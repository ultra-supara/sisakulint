# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Building and Running

```bash
# Build the project
go build ./cmd/sisakulint

# Run tests
go test ./...

# Run specific test
go test ./pkg/core/[test_file_test.go]

# Install dependencies
go mod tidy
```

### Development Commands

```bash
# Run sisakulint without parameters (auto-detect .github/workflows)
sisakulint

# Run with debug output
sisakulint -debug

# Output in SARIF format (for reviewdog)
sisakulint -format "{{sarif .}}"

# Generate default config
sisakulint -init

# Generate boilerplate template
sisakulint -boilerplate

# Auto-fix issues
sisakulint -fix on

# Dry-run auto-fix (preview changes without applying)
sisakulint -fix dry-run

# Analyze remote GitHub repository
sisakulint -remote <github-repo-url>
```

### Testing Commands

```bash
# Run all tests with verbose output
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/core

# Run a specific test
go test -v ./pkg/core -run TestSpecificFunction

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run tests with race detection
go test -race ./...
```

### Release Process

```bash
# Create a new release tag
git tag v[version]
git push origin v[version]

# GitHub Actions will automatically:
# - Build binaries for multiple platforms
# - Create a GitHub release
# - Upload release artifacts
```

## Code Architecture

sisakulint is a static analysis tool for GitHub Actions workflow files (.github/workflows/*.yml or .yaml). It analyzes these files for security issues and best practices.

### Key Components

1. **Command Structure**:
   - Entry point is in `cmd/sisakulint/main.go`
   - Core command handling in `pkg/core/command.go`

2. **Linting Engine**:
   - `pkg/core/linter.go` - Main linting logic
   - `pkg/core/validate.go` - Workflow validation

3. **Rules System**:
   - Each rule is implemented in a separate file (all implementing the `Rule` interface):
     - `pkg/core/idrule.go` - **RuleID**: ID collision detection for jobs and environment variables
     - `pkg/core/credential.go` - **CredentialRule**: Hardcoded credentials detection
     - `pkg/core/permissionrule.go` - **PermissionRule**: Permissions scope and value validation
     - `pkg/core/commitsha.go` - **CommitSHARule**: Validates commit SHA usage in actions (not visible in struct grep but exists)
     - `pkg/core/workflowcall.go` - **RuleWorkflowCall**: Reusable workflow call validation
     - `pkg/core/timeout_minutes.go` - **TimeoutMinutesRule**: Ensures timeout-minutes is set
     - `pkg/core/environmentvariablerule.go` - **EnvironmentVariableRule**: Environment variable name formatting (not visible in struct grep but exists)
     - `pkg/core/exprrule.go` - **ExprRule**: GitHub Actions expression syntax validation
     - `pkg/core/conditionalrule.go` - **ConditionalRule**: Conditional expression validation
     - `pkg/core/issueinjection.go` - **IssueInjection**: Script injection and untrusted input detection
     - `pkg/core/untrustedcheckout.go` - **UntrustedCheckoutRule**: Detects checkout of untrusted PR code in privileged workflow contexts (pull_request_target, issue_comment, workflow_run)
     - `pkg/core/duprecate_commands_pattern.go` - **RuleDeprecatedCommands**: Deprecated workflow commands detection
     - `pkg/core/actionlist.go` - **ActionList**: Action whitelist/blacklist enforcement
     - `pkg/core/rule_add_temp_normal.go` - **AddRule**: Template rule for adding new rules

4. **AST Processing**:
   - `pkg/ast/ast_type.go` - AST node type definitions (Workflow, Job, Step, etc.)
   - `pkg/ast/ast_func.go` - AST utility functions
   - `pkg/core/visitor.go` - **SyntaxTreeVisitor**: Orchestrates tree traversal with depth-first order
   - `pkg/core/visit.go` - Visit helper functions
   - `pkg/core/parse_main.go` - Main workflow file parsing
   - `pkg/core/parse_sub.go` - Sub-component parsing (jobs, steps, etc.)
   - `pkg/core/parse_sbom.go` - SBOM (Software Bill of Materials) parsing

5. **Expression Handling**:
   - `pkg/expressions/parser.go` - Expression parser for `${{ }}` syntax
   - `pkg/expressions/expression.go` - Expression evaluation logic
   - `pkg/expressions/semantic.go` - Semantic analysis
   - `pkg/expressions/tokenizer.go` - Tokenization of expressions
   - `pkg/expressions/ast.go` - Expression AST nodes
   - `pkg/expressions/anti_untrustedchecker.go` - Untrusted input detection
   - `pkg/expressions/anti_untrustedmap.go` - Mapping of untrusted contexts
   - `pkg/core/exprchecker.go` - Expression validation logic
   - `pkg/core/needs.go` - Job dependency (needs) validation

6. **Output Handling**:
   - `pkg/core/errorformatter.go` - Formatting error output
   - `pkg/core/sarif.go` - SARIF output support for reviewdog integration

7. **Auto-fixing**:
   - `pkg/core/autofixer.go` - Auto-fixing framework with three fixer types:
     - **AutoFixer** interface - Base interface for all fixers
     - **StepFixer** interface - Fixes issues at the step level
     - **JobFixer** interface - Fixes issues at the job level
     - **funcFixer** - Generic function-based fixer
   - Rules implementing auto-fix: TimeoutMinutesRule, CommitSHARule, CredentialRule

8. **Remote Analysis**:
   - `pkg/remote/fetcher.go` - GitHub API integration for fetching workflows
   - `pkg/remote/scanner.go` - Remote repository scanning logic
   - `pkg/remote/input.go` - Input parsing for remote repository specifications
   - Supports multiple input formats:
     - `owner/repo` - Single repository
     - `org:organization` - All repositories in an organization
     - With flags for recursive scanning and depth control

### Data Flow

1. The tool scans a directory for GitHub Actions workflow files
2. Files are parsed into AST representation
3. Rules are applied to the AST
4. Issues are collected and reported
5. Auto-fix is applied if requested

## Configuration

The tool can be configured using a `.github/action.yaml` file (created using `sisakulint -init`).

## Project Structure

```
.
├── cmd/sisakulint/        # Command line tool entry point
│   └── main.go
│
├── pkg/                   # Core code
│   ├── ast/               # Abstract Syntax Tree representation
│   ├── core/              # Core functionality
│   │   ├── linter.go      # Main linting logic
│   │   ├── rule.go        # Base rule interface and BaseRule struct
│   │   ├── command.go     # CLI command handling
│   │   ├── config.go      # Configuration management
│   │   ├── autofixer.go   # Auto-fixing framework
│   │   ├── *rule.go       # Individual rule implementations
│   │   ├── parse_*.go     # Parsing logic for workflows
│   │   └── ...
│   ├── expressions/       # GitHub Actions expression parser
│   └── remote/            # Remote repository analysis
│
├── script/                # Utility scripts
└── .github/
    └── workflows/         # Example workflows for testing
```

## Key Files to Know

- **`cmd/sisakulint/main.go`** - Entry point, sets up the Command struct with stdin/stdout/stderr
- **`pkg/core/command.go`** - CLI command parsing, flag handling, and main execution flow
  - Exit codes: 0 (success, no problems), 1 (success, problems found), 2 (invalid options), 3 (failure)
- **`pkg/core/linter.go`** - Main linting engine with `LinterOptions` for configuration
  - LogLevel control (NoOutput, DetailedOutput, AllOutputIncludingDebug)
  - OutputColorBehavior (AutoColor, AlwaysColor, NeverColor)
  - Orchestrates rule execution and result collection
- **`pkg/core/rule.go`** - `Rule` interface and `BaseRule` struct that all rules implement
- **`pkg/core/visitor.go`** - `SyntaxTreeVisitor` for depth-first AST traversal
- **`pkg/core/process.go`** - Workflow file processing and validation coordination
- **`pkg/core/config.go`** - Configuration file handling (`.github/action.yaml`)
- **`pkg/core/autofixer.go`** - AutoFixer interfaces (AutoFixer, StepFixer, JobFixer)
- **`pkg/core/metadata.go`** - Workflow metadata management
- **`pkg/core/constants.go`** - Constants for rule names, scopes, and validation
- **`pkg/core/boilerplate.go`** - Boilerplate template generation
- **`pkg/ast/ast_type.go`** - AST node type definitions (Workflow, Job, Step, etc.)
- **`pkg/ast/ast_func.go`** - AST utility functions

## Adding a New Rule

To add a new rule to sisakulint:

1. Create a new file in `pkg/core/` (e.g., `myrule.go`)
2. Define a struct that embeds `BaseRule`:
   ```go
   type MyRule struct {
       BaseRule
   }
   ```
3. Implement the `TreeVisitor` interface methods you need:
   - `VisitWorkflowPre(*Workflow) error` - Called before visiting workflow
   - `VisitWorkflowPost(*Workflow) error` - Called after visiting workflow
   - `VisitJobPre(*Job) error` - Called before visiting each job
   - `VisitJobPost(*Job) error` - Called after visiting each job
   - `VisitStep(*Step) error` - Called for each step
4. Register the rule in the linter by adding it to the rules list
5. Add tests in a corresponding `*_test.go` file
6. Optionally implement the `AutoFixer` interface for auto-fix support:
   ```go
   func (rule *MyRule) AddAutoFixer(fixer AutoFixer) {
       rule.BaseRule.AddAutoFixer(fixer)
   }
   ```

## Important Interfaces

### Rule Interface
All rules must implement the `Rule` interface defined in `pkg/core/rule.go`:
```go
type Rule interface {
    TreeVisitor                      // Embeds TreeVisitor for AST traversal
    Errors() []*LintingError        // Returns collected errors
    RuleNames() string              // Returns the rule name (e.g., "id", "permissions")
    RuleDescription() string        // Returns rule description
    EnableDebugOutput(io.Writer)    // Enables debug logging
    UpdateConfig(*Config)           // Updates rule with user configuration
    AddAutoFixer(AutoFixer)        // Adds an auto-fixer
    AutoFixers() []AutoFixer       // Returns list of auto-fixers
}
```

**BaseRule** provides default implementations for most methods. New rules should embed `BaseRule` and only override necessary methods.

### TreeVisitor Interface
Defines methods for traversing the workflow AST in depth-first order:
```go
type TreeVisitor interface {
    VisitStep(node *ast.Step) error           // Called for each step
    VisitJobPre(node *ast.Job) error          // Called before visiting job's children
    VisitJobPost(node *ast.Job) error         // Called after visiting job's children
    VisitWorkflowPre(node *ast.Workflow) error    // Called before visiting workflow's children
    VisitWorkflowPost(node *ast.Workflow) error   // Called after visiting workflow's children
}
```

**SyntaxTreeVisitor** orchestrates the traversal, calling each rule's visitor methods in order. The Pre/Post pattern allows rules to:
- Collect information during Pre phase
- Validate collected data during Post phase
- Control traversal by returning errors

### AutoFixer Interface
Rules can provide auto-fixers to automatically correct issues:
```go
type AutoFixer interface {
    RuleName() string    // Rule name that provides this fixer
    Fix() error         // Applies the fix
}
```

**Helper constructors:**
- `NewStepFixer(step, fixer)` - Creates fixer for step-level issues
- `NewJobFixer(job, fixer)` - Creates fixer for job-level issues
- `NewFuncFixer(ruleName, func)` - Creates fixer from arbitrary function

Changes are applied to the AST and written back to YAML files using `yaml.v3` encoder.

## Common Patterns

### Error Reporting
```go
// Simple error
rule.Error(node.Pos, "error message")

// Formatted error
rule.Errorf(node.Pos, "found %s, expected %s", actual, expected)
```

### Debug Logging
```go
// Debug output (only shown with -debug flag)
rule.Debug("checking node: %v", node)
```

### Configuration Access
```go
// Access user configuration
if rule.userConfig != nil {
    // Use configuration values
    // Example from ActionList rule:
    for _, pattern := range rule.userConfig.actionListRegex {
        if pattern.MatchString(actionRef) {
            return true, ""
        }
    }
}
```

### Creating AutoFixers
```go
// Example from TimeoutMinutesRule
func (rule *TimeoutMinutesRule) VisitJobPre(node *ast.Job) error {
    if node.TimeoutMinutes == nil {
        rule.Errorf(node.Pos, "timeout-minutes is not set for job %s", node.ID.Value)

        // Add auto-fixer
        fixer := NewJobFixer(node, rule)
        rule.AddAutoFixer(fixer)
    }
    return nil
}

// Implement JobFixer interface
func (rule *TimeoutMinutesRule) FixJob(job *ast.Job) error {
    // Set default timeout to 5 minutes
    job.TimeoutMinutes = &ast.IntNode{Value: 5}
    return nil
}
```

### Expression Parsing
```go
// Extract expressions from strings (e.g., run scripts)
// IssueInjection rule example:
value := "${{ github.event.issue.title }}"
start := strings.Index(value, "${{")
end := strings.Index(value[start:], "}}")
exprContent := value[start+3 : start+end]

// Parse the expression using pkg/expressions
parsed, err := expressions.Parse(exprContent)

// Check for untrusted input patterns
if expressions.IsUntrusted(parsed) {
    rule.Error(pos, "untrusted input detected")
}
```

## Development Workflow

### Making Changes

1. **Write code** - Implement your feature or fix
2. **Write tests** - Add tests in `*_test.go` files
3. **Run tests** - `go test ./...`
4. **Build** - `go build ./cmd/sisakulint`
5. **Test locally** - Run sisakulint on test workflows in `.github/workflows/`
6. **Debug** - Use `sisakulint -debug` to see detailed output

### Testing Your Rule

Create a test workflow file in `.github/workflows/` or use an existing one:
```yaml
# test-workflow.yaml
name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
```

Then run sisakulint:
```bash
./sisakulint -debug
```

### Rule Testing Pattern

Most rules follow this testing pattern (12 test files exist in the codebase):
```go
func TestMyRule(t *testing.T) {
    tests := []struct {
        name    string
        yaml    string
        wantErr bool
    }{
        {
            name: "valid case",
            yaml: `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"`,
            wantErr: false,
        },
        {
            name: "invalid case",
            yaml: `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    # Missing required field
    steps:
      - run: echo "test"`,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // 1. Parse the YAML
            workflow, err := parseWorkflowYAML(tt.yaml)
            if err != nil {
                t.Fatal(err)
            }

            // 2. Create rule instance
            rule := NewMyRule()

            // 3. Visit the workflow
            visitor := NewSyntaxTreeVisitor()
            visitor.AddVisitor(rule)
            if err := visitor.VisitTree(workflow); err != nil {
                t.Fatal(err)
            }

            // 4. Check errors
            errs := rule.Errors()
            if tt.wantErr && len(errs) == 0 {
                t.Error("expected error but got none")
            }
            if !tt.wantErr && len(errs) > 0 {
                t.Errorf("unexpected error: %v", errs)
            }
        })
    }
}
```

See existing test files for examples:
- `pkg/core/idrule_test.go`
- `pkg/core/permissionrule_test.go`
- `pkg/core/exprrule_test.go`
- `pkg/core/issueinjection_test.go`
- etc.

## Troubleshooting

### Common Issues

1. **Parse errors** - Check YAML syntax in test files
   - Ensure proper indentation (2 spaces)
   - Verify YAML anchors and aliases are correct
   - Use `yaml.v3` position tracking for accurate error locations

2. **Rule not running** - Ensure rule is registered in linter
   - Check that the rule is added to the rules list in `linter.go`
   - Verify the rule's `RuleNames()` returns the correct identifier

3. **Tests failing** - Check that test fixtures match expected format
   - Run `go test -v` for detailed output
   - Verify AST node structure matches expectations
   - Check that position information is correctly set

4. **Debug not showing** - Make sure to use `-debug` flag
   - Debug output goes to the configured `io.Writer` (usually stderr)
   - Use `rule.Debug()` method, not `fmt.Println()`

5. **Auto-fix not working**
   - Verify the rule implements the appropriate fixer interface (StepFixer/JobFixer)
   - Check that `AddAutoFixer()` is called during rule execution
   - Ensure AST modifications are done before YAML encoding

6. **Expression parsing errors**
   - Expressions must use single quotes for string literals, not double quotes
   - Check for proper `${{ }}` delimiters
   - Verify expression syntax matches GitHub Actions specification

### Useful Debug Commands

```bash
# Full debug output
sisakulint -debug

# Test specific workflow file
sisakulint -debug path/to/workflow.yml

# Check what would be fixed
sisakulint -fix dry-run -debug
```

## Dependencies

Key dependencies from `go.mod`:
- **github.com/fatih/color** - Colored terminal output
- **github.com/google/go-github/v68** - GitHub API client for remote scanning
- **github.com/haya14busa/go-sarif** - SARIF format output generation
- **github.com/mattn/go-colorable** - Cross-platform colored output
- **golang.org/x/sync** - Concurrency primitives (errgroup for parallel linting)
- **gopkg.in/yaml.v3** - YAML parsing and encoding with position tracking

## CI/CD Workflows

The project includes several GitHub Actions workflows in `.github/workflows/`:
- **CI.yaml** - Continuous integration testing
- **release.yml** - Automated release builds for multiple platforms
- **reviewdog.yaml** - Integration with reviewdog for PR reviews
- **codeql.yml** - Security scanning with CodeQL

## Exit Codes

sisakulint uses specific exit codes for different scenarios:
- **0** (`ExitStatusSuccessNoProblem`) - Success, no problems found
- **1** (`ExitStatusSuccessProblemFound`) - Success, but problems found
- **2** (`ExitStatusInvalidCommandOption`) - Invalid command-line options
- **3** (`ExitStatusFailure`) - Fatal error during execution

This allows CI/CD pipelines to distinguish between "clean" runs and runs with findings.

## Performance Considerations

- **Parallel Processing**: Uses `golang.org/x/sync/errgroup` for concurrent file processing
- **Depth-First Traversal**: AST traversal is optimized for minimal memory usage
- **Debug Timing**: When `-debug` is enabled, timing information is logged for each visitor phase
- **YAML Position Tracking**: Uses `yaml.v3`'s position tracking for accurate error locations

## Security Features

sisakulint implements OWASP Top 10 CI/CD Security Risks checks:
- **CICD-SEC-1**: Insufficient Flow Control Mechanisms (permissions rule)
- **CICD-SEC-4**: Poisoned Pipeline Execution (issue-injection rule)
- **CICD-SEC-5**: Insufficient PBAC (permissions rule)
- **CICD-SEC-7**: Insecure System Configuration (timeout-minutes rule)
- **CICD-SEC-8**: Ungoverned Usage of 3rd Party Services (commitsha, action-list rules)

## Remote Scanning Features

The `-remote` flag supports multiple input formats:
```bash
# Single repository
sisakulint -remote owner/repo

# Organization (all repos)
sisakulint -remote "org:kubernetes"

# With recursive scanning and depth control
sisakulint -remote owner/repo -r -D 5
```

Rate limiting: Uses GitHub API (60 req/hour unauthenticated, 5000/hour with token)

## Best Practices for Rule Development

1. **Always embed BaseRule**
   ```go
   type MyRule struct {
       BaseRule
       // Additional fields if needed
   }
   ```

2. **Use appropriate visitor methods**
   - Use `VisitJobPre` for collecting information about a job
   - Use `VisitJobPost` for validation after all steps are visited
   - Use `VisitStep` for step-level validation
   - Use `VisitWorkflowPre/Post` for workflow-level validation

3. **Provide clear error messages**
   - Include the reason for the error
   - Suggest how to fix it
   - Reference official documentation when applicable
   ```go
   rule.Errorf(
       node.Pos,
       "timeout-minutes is not set for job %s; see https://docs.github.com/... for more details",
       job.ID.Value,
   )
   ```

4. **Add debug logging**
   - Log important decisions or state changes
   - Include context information (node type, position, etc.)
   ```go
   rule.Debug("checking job %s at line %d", job.ID.Value, job.Pos.Line)
   ```

5. **Test thoroughly**
   - Write tests for both valid and invalid cases
   - Test edge cases (empty values, nil pointers, etc.)
   - Use table-driven tests for multiple scenarios

6. **Consider performance**
   - Avoid unnecessary allocations in visitor methods
   - Use `strings.Builder` for string concatenation
   - Cache expensive computations in rule fields

7. **Document your rule**
   - Add comments explaining the purpose and behavior
   - Reference GitHub documentation or security standards
   - Include examples of violations and fixes

## Language and Code Style

- **Code comments**: Mix of Japanese and English (Japanese for implementation details, English for interfaces/exports)
- **Variable naming**: Use descriptive names (e.g., `errorIgnorePatterns`, not `patterns`)
- **Error handling**: Always check errors and provide context
- **Testing**: Maintain test coverage for all rules (currently 12 test files)
- **Go version**: Requires Go 1.24.0 or later

## Additional Resources

- **Main Documentation**: https://sisaku-security.github.io/lint/
- **GitHub Actions Docs**: https://docs.github.com/en/actions
- **OWASP CI/CD Security**: https://owasp.org/www-project-top-10-ci-cd-security-risks/
- **SARIF Format**: https://sarifweb.azurewebsites.net/
- **BlackHat Arsenal 2025 Presentation**: https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions
- **Project Poster (SecHack365)**: https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf
- **GitHub Repository**: https://github.com/ultra-supara/sisakulint
- **Homebrew Tap**: https://github.com/ultra-supara/homebrew-sisakulint