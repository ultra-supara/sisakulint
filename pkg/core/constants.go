package core

// String constants for expression types
const (
	// Expression checker constants
	ExprNullValue  = "null"
	ExprTrueValue  = "true"
	ExprFalseValue = "false"

	// Parse SBOM constants
	SBOMDescription = "description"
	SBOMRequired    = "required"
	SBOMString      = "string"
	SBOMNumber      = "number"
	SBOMBoolean     = "boolean"
	SBOMShell       = "shell"
	SBOMUses        = "uses"
	SBOMWith        = "with"
	SBOMRun         = "run"

	// Parse sub constants
	SubWorkflowDispatch   = "workflow_dispatch"
	SubRepositoryDispatch = "repository_dispatch"
	SubSchedule           = "schedule"
	SubWorkflowCall       = "workflow_call"

	// Available constants
	AvailableEnv         = "env"
	AvailableConcurrency = "concurrency"

	// Parse main constants
	MainName = "name"

	// File action constants
	FileFixDryRun = "dry-run"

	// Parse SBOM tag constants
	SBOMNullTag  = "!!null"
	SBOMStrTag   = "!!str"
	SBOMIntTag   = "!!int"
	SBOMFloatTag = "!!float"
)
