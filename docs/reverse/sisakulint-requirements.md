# Sisakulint Requirements Document

## Document Information
- **Project**: sisakulint - Static Analysis Tool for GitHub Actions Workflows
- **Document Type**: Reverse-engineered Requirements using EARS notation
- **Version**: 1.0
- **Generated**: 2025-08-19

## 1. System Overview and Purpose

Sisakulint is a static analysis tool designed to analyze GitHub Actions workflow files (.github/workflows/*.yml or .yaml) for security issues, best practices violations, and configuration errors. The tool provides comprehensive linting capabilities with auto-fixing features and supports various output formats including SARIF for integration with development tools.

### 1.1 Core Objectives
- Enhance security posture of GitHub Actions workflows
- Enforce best practices and coding standards
- Provide automated issue detection and remediation
- Support CI/CD integration through multiple output formats
- Enable configuration-driven customization of validation rules

## 2. User Stories

### US-001: Basic Workflow Validation
**As a** developer  
**I want** to validate my GitHub Actions workflow files for syntax and security issues  
**So that** I can ensure my CI/CD pipelines are secure and follow best practices

### US-002: Auto-fix Capability
**As a** developer  
**I want** the tool to automatically fix common issues in my workflow files  
**So that** I can quickly remediate problems without manual intervention

### US-003: Configuration Management
**As a** DevOps engineer  
**I want** to configure the linting rules according to my organization's policies  
**So that** I can enforce custom standards across all projects

### US-004: CI/CD Integration
**As a** CI/CD engineer  
**I want** to integrate sisakulint into automated pipelines with SARIF output  
**So that** I can provide actionable feedback to developers through code review tools

### US-005: Project Auto-detection
**As a** developer  
**I want** the tool to automatically detect GitHub Actions projects  
**So that** I can run the linter without specifying complex file paths

## 3. Functional Requirements (EARS Notation)

### 3.1 Command Line Interface Requirements

**REQ-CLI-001**: WHEN the user executes sisakulint without parameters, the system SHALL automatically detect the nearest .github/workflows directory and analyze all YAML files within it.

**REQ-CLI-002**: WHEN the user provides the `-debug` flag, the system SHALL output detailed debug information including syntax tree traversal and rule analysis logs.

**REQ-CLI-003**: WHEN the user provides the `-format` flag with a template, the system SHALL format error output according to the specified Go template syntax.

**REQ-CLI-004**: WHEN the user provides the `-init` flag, the system SHALL generate a default configuration file at .github/action.yaml in the current project.

**REQ-CLI-005**: WHEN the user provides the `-boilerplate` flag, the system SHALL generate a boilerplate template file for GitHub Actions workflows.

**REQ-CLI-006**: WHEN the user provides the `-fix` flag with value "on", the system SHALL automatically apply fixes to detected issues and modify the workflow files.

**REQ-CLI-007**: WHEN the user provides the `-fix` flag with value "dry-run", the system SHALL display the fixes that would be applied without modifying any files.

**REQ-CLI-008**: WHEN the user provides the `-version` flag, the system SHALL display version information, Go version, OS/Architecture, and build details.

**REQ-CLI-009**: WHEN the user provides the `-ignore` flag with a regular expression, the system SHALL exclude errors matching that pattern from the output.

**REQ-CLI-010**: WHEN the user provides the `-config-file` flag with a path, the system SHALL use the specified configuration file instead of auto-detecting one.

### 3.2 Project Detection and File Processing Requirements

**REQ-PROJ-001**: WHEN analyzing a directory, the system SHALL recursively search for a .github/workflows directory containing .yml or .yaml files.

**REQ-PROJ-002**: WHEN a .github/workflows directory is found, the system SHALL verify the presence of a .git directory at the project root to confirm it's a valid Git repository.

**REQ-PROJ-003**: WHEN processing multiple files, the system SHALL process them concurrently using the number of available CPU cores for optimal performance.

**REQ-PROJ-004**: WHEN encountering a file path, the system SHALL convert it to a relative path from the current working directory IF possible for cleaner output.

**REQ-PROJ-005**: WHEN caching project information, the system SHALL reuse previously loaded project instances to avoid redundant filesystem operations.

### 3.3 Parsing and AST Requirements

**REQ-AST-001**: WHEN parsing a YAML workflow file, the system SHALL create a complete Abstract Syntax Tree representation preserving position information for all nodes.

**REQ-AST-002**: WHEN parsing fails, the system SHALL collect all syntax errors and continue processing other files rather than terminating immediately.

**REQ-AST-003**: WHEN processing expressions containing ${{ }} syntax, the system SHALL parse and validate the expression content using the built-in expression parser.

**REQ-AST-004**: WHEN encountering YAML mapping nodes, the system SHALL convert keys to lowercase WHERE the GitHub Actions specification requires case-insensitive matching.

### 3.4 Rule Engine Requirements

**REQ-RULE-001**: WHEN validating workflows, the system SHALL apply the following rules by default:
- ID collision detection and naming convention validation
- Hardcoded credentials detection in container configurations
- Permission scope validation for GITHUB_TOKEN
- Commit SHA validation for action references
- Timeout minutes validation for jobs and steps
- Environment variable naming validation
- Job dependency cycle detection
- Deprecated commands pattern detection
- Conditional expression validation
- Action whitelist/blacklist enforcement

**REQ-RULE-002**: WHEN the ID rule detects duplicate step IDs within a job, the system SHALL report an error indicating the duplicate ID and the location of the previous definition.

**REQ-RULE-003**: WHEN the ID rule validates naming conventions, the system SHALL ensure job and step IDs start with a letter or underscore and contain only alphanumeric characters, hyphens, or underscores.

**REQ-RULE-004**: WHEN the credentials rule detects hardcoded passwords in container configurations, the system SHALL report a security violation and provide auto-fix capability to remove the hardcoded value.

**REQ-RULE-005**: WHEN the permissions rule validates permission scopes, the system SHALL check against the official list of GitHub Actions permission scopes and validate that permission values are 'read', 'write', or 'none'.

**REQ-RULE-006**: WHEN the permissions rule encounters 'write-all' permission, the system SHALL issue a warning recommending specific scope permissions instead.

**REQ-RULE-007**: WHEN the commit SHA rule validates action references, the system SHALL verify that third-party actions use full-length commit SHAs (40 hexadecimal characters) for security.

**REQ-RULE-008**: WHEN the timeout minutes rule validates jobs and steps, the system SHALL ensure timeout-minutes is specified and provide auto-fix to add a default 5-minute timeout.

**REQ-RULE-009**: WHEN the environment variable rule validates env sections, the system SHALL ensure variable names do not contain prohibited characters ('&', '=', or spaces).

**REQ-RULE-010**: WHEN the needs rule validates job dependencies, the system SHALL detect cyclic dependencies using directed acyclic graph algorithms and report the cycle path.

**REQ-RULE-011**: WHEN the action list rule is enabled, the system SHALL enforce whitelist/blacklist patterns for action references using configurable regular expressions.

### 3.5 Configuration Requirements

**REQ-CONFIG-001**: WHEN loading configuration, the system SHALL search for sisakulint.yaml or sisakulint.yml in the .github directory of the project root.

**REQ-CONFIG-002**: WHEN no configuration file is found, the system SHALL use default settings that enable all rules with standard parameters.

**REQ-CONFIG-003**: WHEN configuration includes self-hosted-runner labels, the system SHALL validate that workflow runner specifications match the configured labels.

**REQ-CONFIG-004**: WHEN configuration includes config-variables settings, the system SHALL validate that workflow variable references match the declared configuration variables.

**REQ-CONFIG-005**: WHEN configuration includes action-list settings, the system SHALL compile the patterns into regular expressions and apply whitelist/blacklist validation.

**REQ-CONFIG-006**: WHEN configuration parsing fails, the system SHALL provide a descriptive error message indicating the file path and specific parsing issue.

### 3.6 Auto-fixing Requirements

**REQ-FIX-001**: WHEN auto-fix mode is enabled, the system SHALL apply fixes only to issues that have associated auto-fixers implemented.

**REQ-FIX-002**: WHEN fixing credential issues, the system SHALL remove hardcoded password fields from container configurations while preserving other credential fields.

**REQ-FIX-003**: WHEN fixing timeout issues, the system SHALL insert timeout-minutes fields with a default value of 5 minutes in the appropriate YAML structure location.

**REQ-FIX-004**: WHEN fixing commit SHA issues, the system SHALL fetch the current commit SHA from GitHub API and replace version tags with full commit SHAs, preserving the original tag as a comment.

**REQ-FIX-005**: WHEN fixing action list violations, the system SHALL remove non-compliant action steps from the workflow while maintaining valid YAML structure.

**REQ-FIX-006**: WHEN auto-fix encounters an error, the system SHALL restore the original file content and report the error without leaving the file in a corrupted state.

**REQ-FIX-007**: WHEN dry-run mode is enabled, the system SHALL output the proposed fixes to stdout without modifying any files.

### 3.7 Output and Reporting Requirements

**REQ-OUT-001**: WHEN reporting errors in default mode, the system SHALL display file path, line number, column number, error description, and rule name in a structured format.

**REQ-OUT-002**: WHEN displaying errors, the system SHALL include a code snippet showing the problematic line with visual indicators pointing to the error location.

**REQ-OUT-003**: WHEN custom error formatting is specified, the system SHALL apply the Go template to error data including support for JSON serialization and string manipulation functions.

**REQ-OUT-004**: WHEN SARIF output format is requested, the system SHALL generate valid SARIF 2.1.0 format compatible with GitHub security tabs and other SARIF consumers.

**REQ-OUT-005**: WHEN verbose mode is enabled, the system SHALL output detailed progress information including file counts, processing times, and rule statistics.

**REQ-OUT-006**: WHEN debug mode is enabled, the system SHALL output AST traversal information, rule execution details, and internal processing logs.

**REQ-OUT-007**: WHEN processing multiple files, the system SHALL sort errors by file path, then by line number, then by column number for consistent output ordering.

### 3.8 Error Handling Requirements

**REQ-ERR-001**: WHEN file reading fails, the system SHALL report the specific file path and reason for failure without terminating the entire process.

**REQ-ERR-002**: WHEN YAML parsing encounters syntax errors, the system SHALL collect all parsing errors and continue processing other files.

**REQ-ERR-003**: WHEN rule execution encounters unexpected errors, the system SHALL log the error and continue with remaining rules rather than terminating analysis.

**REQ-ERR-004**: WHEN network operations fail during commit SHA validation, the system SHALL report the network error and continue with other validations.

**REQ-ERR-005**: WHEN configuration file parsing fails, the system SHALL provide specific error details including line numbers and error descriptions.

## 4. Non-Functional Requirements

### 4.1 Performance Requirements

**REQ-PERF-001**: WHEN processing multiple workflow files, the system SHALL utilize concurrent processing with goroutines equal to the number of CPU cores.

**REQ-PERF-002**: WHEN analyzing large workflows, the system SHALL complete validation within 2 minutes for files up to 10MB in size.

**REQ-PERF-003**: WHEN caching metadata, the system SHALL reuse action metadata and reusable workflow caches to minimize redundant API calls and file operations.

### 4.2 Reliability Requirements

**REQ-REL-001**: WHEN encountering errors in individual rules, the system SHALL continue processing with other rules to ensure comprehensive analysis.

**REQ-REL-002**: WHEN auto-fixing fails, the system SHALL restore original file content to prevent data loss.

**REQ-REL-003**: WHEN processing large numbers of files, the system SHALL handle memory efficiently without causing out-of-memory conditions.

### 4.3 Usability Requirements

**REQ-USE-001**: WHEN run without parameters, the system SHALL provide intuitive auto-detection behavior requiring no configuration for basic use cases.

**REQ-USE-002**: WHEN displaying help information, the system SHALL provide clear usage examples and flag descriptions.

**REQ-USE-003**: WHEN reporting errors, the system SHALL use color-coded output to enhance readability in terminal environments.

### 4.4 Compatibility Requirements

**REQ-COMP-001**: WHEN processing YAML files, the system SHALL support both .yml and .yaml file extensions.

**REQ-COMP-002**: WHEN integrating with CI systems, the system SHALL return appropriate exit codes (0 for success, 1 for issues found, 2 for invalid options, 3 for fatal errors).

**REQ-COMP-003**: WHEN generating SARIF output, the system SHALL produce output compatible with GitHub security tabs and reviewdog integration.

### 4.5 Security Requirements

**REQ-SEC-001**: WHEN validating action references, the system SHALL enforce security best practices by requiring full commit SHAs for third-party actions.

**REQ-SEC-002**: WHEN detecting hardcoded credentials, the system SHALL identify and flag potential security vulnerabilities in container configurations.

**REQ-SEC-003**: WHEN validating permissions, the system SHALL enforce principle of least privilege by warning against overly broad permission scopes.

## 5. Edge Cases and Error Handling Requirements

### 5.1 File System Edge Cases

**REQ-EDGE-001**: WHEN the .github/workflows directory is empty, the system SHALL report "no yaml files found" rather than crashing.

**REQ-EDGE-002**: WHEN file permissions prevent reading, the system SHALL report a permission error with the specific file path.

**REQ-EDGE-003**: WHEN symbolic links are encountered, the system SHALL follow them if they point to valid YAML files.

**REQ-EDGE-004**: WHEN very large files (>100MB) are encountered, the system SHALL either process them with appropriate memory management or report a size limitation error.

### 5.2 YAML Parsing Edge Cases

**REQ-EDGE-005**: WHEN YAML files contain invalid UTF-8 encoding, the system SHALL report encoding errors with line number information.

**REQ-EDGE-006**: WHEN YAML files are empty or contain only comments, the system SHALL handle them gracefully without reporting false errors.

**REQ-EDGE-007**: WHEN YAML files contain deeply nested structures exceeding reasonable limits, the system SHALL prevent stack overflow conditions.

### 5.3 Network and API Edge Cases

**REQ-EDGE-008**: WHEN GitHub API rate limits are exceeded during commit SHA validation, the system SHALL report the rate limit error and continue with other validations.

**REQ-EDGE-009**: WHEN network connectivity is unavailable, the system SHALL gracefully degrade commit SHA validation and report the connectivity issue.

**REQ-EDGE-010**: WHEN GitHub repositories are private or deleted, the system SHALL handle 404 errors appropriately during action metadata fetching.

### 5.4 Configuration Edge Cases

**REQ-EDGE-011**: WHEN configuration files contain invalid regular expressions, the system SHALL report compilation errors with pattern details.

**REQ-EDGE-012**: WHEN configuration references non-existent files or directories, the system SHALL provide clear error messages about missing resources.

**REQ-EDGE-013**: WHEN configuration values are outside expected ranges or formats, the system SHALL validate and report specific constraint violations.

## 6. Acceptance Criteria

### 6.1 Basic Functionality Acceptance Criteria

**AC-001**: Given a valid GitHub Actions workflow file with security issues, when sisakulint is executed, then it SHALL detect and report all applicable rule violations with accurate line and column information.

**AC-002**: Given a workflow file with fixable issues, when sisakulint is executed with `-fix on`, then it SHALL successfully apply fixes and produce a valid, improved workflow file.

**AC-003**: Given a project with a .github/workflows directory, when sisakulint is executed without parameters, then it SHALL automatically detect and analyze all workflow files in the directory.

**AC-004**: Given a configuration file with custom rules, when sisakulint is executed, then it SHALL apply the custom configuration and enforce the specified policies.

**AC-005**: Given the `-format` flag with a SARIF template, when sisakulint is executed, then it SHALL produce valid SARIF 2.1.0 output that can be consumed by GitHub security features.

### 6.2 Error Handling Acceptance Criteria

**AC-006**: Given a workflow file with syntax errors, when sisakulint is executed, then it SHALL report the syntax errors and continue processing other files without crashing.

**AC-007**: Given network connectivity issues during commit SHA validation, when sisakulint is executed, then it SHALL report network errors and continue with other rule validations.

**AC-008**: Given insufficient file permissions, when sisakulint is executed, then it SHALL report permission errors with specific file paths and continue processing accessible files.

### 6.3 Performance Acceptance Criteria

**AC-009**: Given a repository with 50 workflow files totaling 5MB, when sisakulint is executed, then it SHALL complete analysis within 30 seconds on standard hardware.

**AC-010**: Given concurrent processing of multiple files, when sisakulint is executed, then it SHALL utilize available CPU cores efficiently and maintain stable memory usage.

### 6.4 Integration Acceptance Criteria

**AC-011**: Given integration with CI/CD pipelines, when sisakulint is executed, then it SHALL return appropriate exit codes enabling proper pipeline flow control.

**AC-012**: Given reviewdog integration requirements, when sisakulint is executed with SARIF output, then the output SHALL be successfully consumed by reviewdog for code review annotations.

### 6.5 Usability Acceptance Criteria

**AC-013**: Given a new user with no configuration, when sisakulint is executed on a GitHub Actions project, then it SHALL provide immediate value with zero configuration required.

**AC-014**: Given error output in terminal environments, when sisakulint is executed, then it SHALL provide color-coded, readable error messages with helpful context and suggestions.

**AC-015**: Given the need for help information, when sisakulint is executed with `-h` or invalid parameters, then it SHALL provide clear usage instructions and examples.

## 7. System Constraints and Assumptions

### 7.1 System Constraints

- The tool is designed specifically for GitHub Actions workflow files and does not support other CI/CD systems
- Network access is required for commit SHA validation and action metadata fetching
- The tool requires Go runtime environment for execution
- YAML parsing is limited to files that fit within available system memory
- Concurrent processing is bounded by available CPU cores and system resources

### 7.2 Assumptions

- Users have appropriate file system permissions to read workflow files
- GitHub API remains accessible and maintains current response formats
- YAML files follow standard GitHub Actions workflow syntax
- Network connectivity is available for enhanced validation features
- Target systems have sufficient memory and CPU resources for concurrent processing

## 8. Conclusion

This requirements document captures the comprehensive functionality of sisakulint as implemented in the codebase. The tool provides robust static analysis capabilities for GitHub Actions workflows with emphasis on security, best practices, and developer productivity. The EARS notation ensures clear, testable requirements that can guide future development and validation efforts.

The requirements demonstrate sisakulint's evolution from a basic linting tool to a comprehensive workflow validation platform with auto-fixing capabilities, extensive configuration options, and seamless CI/CD integration support.