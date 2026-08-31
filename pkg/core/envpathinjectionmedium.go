package core

// EnvPathInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvPathInjectionRule
type EnvPathInjectionMedium = EnvPathInjectionRule

// EnvPathInjectionMediumRule creates a rule for detecting PATH injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making PATH injection medium severity
func EnvPathInjectionMediumRule() *EnvPathInjectionRule {
	return newEnvPathInjectionRule("medium", false)
}
