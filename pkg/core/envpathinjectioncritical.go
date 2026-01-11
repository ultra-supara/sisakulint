package core

// EnvPathInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvPathInjectionRule
type EnvPathInjectionCritical = EnvPathInjectionRule

// EnvPathInjectionCriticalRule creates a rule for detecting PATH injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making PATH injection critical severity
func EnvPathInjectionCriticalRule() *EnvPathInjectionRule {
	return newEnvPathInjectionRule("critical", true)
}
