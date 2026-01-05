package core

// CodeInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in CodeInjectionRule
type CodeInjectionMedium = CodeInjectionRule

// CodeInjectionMediumRule creates a rule for detecting code injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making code injection medium severity
func CodeInjectionMediumRule() *CodeInjectionRule {
	return newCodeInjectionRule("medium", false)
}
