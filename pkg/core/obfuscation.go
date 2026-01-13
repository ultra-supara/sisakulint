package core

import (
	"path"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// ObfuscationRule detects obfuscated workflow patterns that may be used to evade security scanners.
// This rule checks for:
// - Obfuscated uses: paths (containing ., .., or empty components)
// - shell: cmd usage (difficult to parse)
type ObfuscationRule struct {
	BaseRule
}

// NewObfuscationRule creates a new ObfuscationRule instance.
func NewObfuscationRule() *ObfuscationRule {
	return &ObfuscationRule{
		BaseRule: CreateBaseRule(
			"obfuscation",
			"Detects obfuscated workflow patterns that may be used to evade security scanners",
		),
	}
}

// pathObfuscationAnnotation represents a detected path obfuscation issue.
type pathObfuscationAnnotation struct {
	reason   string
	position *ast.Position
}

// checkUsesPathObfuscation checks if a uses: path contains obfuscation patterns.
// Returns a list of annotations describing the obfuscation issues found.
func checkUsesPathObfuscation(usesValue string) []string {
	// Extract the path part (before @)
	// Format: owner/repo/subpath@ref or owner/repo@ref
	atIndex := strings.LastIndex(usesValue, "@")
	if atIndex == -1 {
		return nil
	}

	pathPart := usesValue[:atIndex]

	// Split by / to check each component
	components := strings.Split(pathPart, "/")
	if len(components) < 2 {
		return nil
	}

	var annotations []string

	// Check components after owner/repo (the subpath)
	for i, component := range components {
		// Skip owner and repo parts
		if i < 2 {
			continue
		}

		switch component {
		case ".":
			annotations = append(annotations, "contains '.' (current directory reference)")
		case "..":
			annotations = append(annotations, "contains '..' (parent directory traversal)")
		case "":
			annotations = append(annotations, "contains empty path component (consecutive slashes)")
		}
	}

	return annotations
}

// normalizeUsesPath normalizes a uses: path by removing obfuscation.
// Returns the normalized path or empty string if the path cannot be normalized.
func normalizeUsesPath(usesValue string) string {
	// Extract parts
	atIndex := strings.LastIndex(usesValue, "@")
	if atIndex == -1 {
		return ""
	}

	pathPart := usesValue[:atIndex]
	ref := usesValue[atIndex+1:]

	// Split and extract owner/repo
	parts := strings.SplitN(pathPart, "/", 3)
	if len(parts) < 2 {
		return ""
	}

	owner := parts[0]
	repo := parts[1]

	// If there's no subpath, just return as-is (already normalized)
	if len(parts) < 3 || parts[2] == "" {
		// Check if the owner/repo part itself has issues
		if owner == "" || repo == "" {
			return ""
		}
		return owner + "/" + repo + "@" + ref
	}

	// Normalize the subpath using path.Clean
	subpath := parts[2]
	cleanedSubpath := path.Clean(subpath)

	// path.Clean returns "." for empty paths, which we should remove
	// Also handle the case where path.Clean returns "/" for paths like "///"
	if cleanedSubpath == "." || cleanedSubpath == "/" {
		return owner + "/" + repo + "@" + ref
	}

	// Remove leading slash if present (path.Clean can return "/foo" for "///foo")
	cleanedSubpath = strings.TrimPrefix(cleanedSubpath, "/")
	if cleanedSubpath == "" {
		return owner + "/" + repo + "@" + ref
	}

	// Check if the path tries to escape (starts with ..)
	if strings.HasPrefix(cleanedSubpath, "..") {
		// Cannot normalize - path escapes the repo
		return ""
	}

	return owner + "/" + repo + "/" + cleanedSubpath + "@" + ref
}

// isPathObfuscated checks if a uses: path is obfuscated.
func isPathObfuscated(usesValue string) bool {
	annotations := checkUsesPathObfuscation(usesValue)
	return len(annotations) > 0
}

// VisitStep checks each step for obfuscation patterns.
func (rule *ObfuscationRule) VisitStep(step *ast.Step) error {
	// Check uses: path obfuscation
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		if action.Uses != nil {
			usesValue := action.Uses.Value
			annotations := checkUsesPathObfuscation(usesValue)
			if len(annotations) > 0 {
				rule.Errorf(action.Uses.Pos,
					"obfuscated 'uses' path detected in step '%s': %s. This may indicate an attempt to evade security scanning. Consider normalizing the path.",
					step.String(),
					strings.Join(annotations, ", "))
				rule.AddAutoFixer(NewStepFixer(step, rule))
			}
		}
	}

	// Check shell: cmd usage
	if execRun, ok := step.Exec.(*ast.ExecRun); ok {
		if execRun.Shell != nil {
			shellValue := strings.ToLower(execRun.Shell.Value)
			if shellValue == "cmd" {
				rule.Errorf(execRun.Shell.Pos,
					"'shell: cmd' detected in step '%s'. Windows CMD shell is difficult to analyze for security issues and may be used to obfuscate malicious commands. Consider using PowerShell or bash instead.",
					step.String())
			}
		}
	}

	return nil
}

// VisitJobPre checks job-level defaults for obfuscation patterns.
func (rule *ObfuscationRule) VisitJobPre(job *ast.Job) error {
	// Check job-level defaults.run.shell
	if job.Defaults != nil && job.Defaults.Run != nil && job.Defaults.Run.Shell != nil {
		shellValue := strings.ToLower(job.Defaults.Run.Shell.Value)
		if shellValue == "cmd" {
			rule.Errorf(job.Defaults.Run.Shell.Pos,
				"'shell: cmd' detected in job '%s' defaults. Windows CMD shell is difficult to analyze for security issues and may be used to obfuscate malicious commands. Consider using PowerShell or bash instead.",
				job.ID.Value)
		}
	}

	// Check workflow call uses: path obfuscation
	if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil {
		usesValue := job.WorkflowCall.Uses.Value
		annotations := checkUsesPathObfuscation(usesValue)
		if len(annotations) > 0 {
			rule.Errorf(job.WorkflowCall.Uses.Pos,
				"obfuscated 'uses' path detected in workflow call '%s': %s. This may indicate an attempt to evade security scanning. Consider normalizing the path.",
				job.ID.Value,
				strings.Join(annotations, ", "))
			rule.AddAutoFixer(NewJobFixer(job, rule))
		}
	}

	return nil
}

// VisitWorkflowPre checks workflow-level defaults for obfuscation patterns.
func (rule *ObfuscationRule) VisitWorkflowPre(workflow *ast.Workflow) error {
	// Check workflow-level defaults.run.shell
	if workflow.Defaults != nil && workflow.Defaults.Run != nil && workflow.Defaults.Run.Shell != nil {
		shellValue := strings.ToLower(workflow.Defaults.Run.Shell.Value)
		if shellValue == "cmd" {
			rule.Errorf(workflow.Defaults.Run.Shell.Pos,
				"'shell: cmd' detected in workflow defaults. Windows CMD shell is difficult to analyze for security issues and may be used to obfuscate malicious commands. Consider using PowerShell or bash instead.")
		}
	}
	return nil
}

// FixStep normalizes obfuscated uses: paths in steps.
func (rule *ObfuscationRule) FixStep(step *ast.Step) error {
	if action, ok := step.Exec.(*ast.ExecAction); ok {
		if action.Uses != nil && action.Uses.BaseNode != nil {
			usesValue := action.Uses.Value
			if isPathObfuscated(usesValue) {
				normalized := normalizeUsesPath(usesValue)
				if normalized != "" && normalized != usesValue {
					action.Uses.BaseNode.Value = normalized
					action.Uses.Value = normalized
				}
			}
		}
	}
	return nil
}

// FixJob normalizes obfuscated uses: paths in workflow calls.
func (rule *ObfuscationRule) FixJob(job *ast.Job) error {
	if job.WorkflowCall != nil && job.WorkflowCall.Uses != nil && job.WorkflowCall.Uses.BaseNode != nil {
		usesValue := job.WorkflowCall.Uses.Value
		if isPathObfuscated(usesValue) {
			normalized := normalizeUsesPath(usesValue)
			if normalized != "" && normalized != usesValue {
				job.WorkflowCall.Uses.BaseNode.Value = normalized
				job.WorkflowCall.Uses.Value = normalized
			}
		}
	}
	return nil
}

// isDockerRef checks if the uses: value is a Docker reference.
func isDockerRef(usesValue string) bool {
	return strings.HasPrefix(usesValue, "docker://")
}

// isLocalAction checks if the uses: value is a local action reference.
func isLocalAction(usesValue string) bool {
	return strings.HasPrefix(usesValue, "./") || strings.HasPrefix(usesValue, "../")
}

// actionRefPattern matches standard action references (owner/repo@ref).
var actionRefPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(/[^@]*)?@.+$`)

// isValidActionRef checks if the uses: value is a valid action reference.
func isValidActionRef(usesValue string) bool {
	if isDockerRef(usesValue) {
		return true
	}
	if isLocalAction(usesValue) {
		return true
	}
	return actionRefPattern.MatchString(usesValue)
}
