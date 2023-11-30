package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/src/ast"
	"github.com/ultra-supara/sisakulint/src/expressions"
)

type typedExpression struct {
	typ expressions.ExprType
	pos ast.Position
}

// ExprRule
//* https://docs.github.com/en/actions/learn-github-actions/contexts
//* https://docs.github.com/en/actions/learn-github-actions/expressions
type ExprRule struct {
	BaseRule
	MatrixType           *expressions.ObjectType
	StepsType            *expressions.ObjectType
	NeedsType            *expressions.ObjectType
	SecretsType          *expressions.ObjectType
	InputsType           *expressions.ObjectType
	DispatchInputsType   *expressions.ObjectType
	JobsType             *expressions.ObjectType
	WorkflowDefinition   *ast.Workflow
	LocalActionsCache    *LocalActionsMetadataCache
	LocalWorkflowsCache  *LocalReusableWorkflowCache
}

// ExpressionRule creates a new ExprRule instance.
func ExpressionRule(actionsCache *LocalActionsMetadataCache, workflowsCache *LocalReusableWorkflowCache) *ExprRule {
	return &ExprRule{
		BaseRule: BaseRule {
			RuleName: "expression",
			RuleDesc: "Checks for syntax errors in expressions ${{ }} syntax",
		},
		MatrixType:     nil,
		StepsType:      nil,
		NeedsType:      nil,
		SecretsType:    nil,
		InputsType:     nil,
		DispatchInputsType: nil,
		JobsType:       nil,
		WorkflowDefinition: nil,
		LocalActionsCache: actionsCache,
		LocalWorkflowsCache: workflowsCache,
	}
}

//VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
func (rule *ExprRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.checkString(node.Name, "")
	for _, env := range node.On {
		switch env := env.(type) {
		case *ast.ScheduledEvent:
			rule.checkStrings(env.Cron, "")
		case *ast.WebhookEvent:
			rule.checkStrings(env.Types, "")
			rule.checkWebhookEventFilter(env.Branches)
			rule.checkWebhookEventFilter(env.BranchesIgnore)
			rule.checkWebhookEventFilter(env.Tags)
			rule.checkWebhookEventFilter(env.TagsIgnore)
			rule.checkWebhookEventFilter(env.Paths)
			rule.checkWebhookEventFilter(env.PathsIgnore)
			rule.checkStrings(env.Workflows, "")
		case *ast.WorkflowDispatchEvent:
			inputTypeMap := expressions.NewEmptyStrictObjectType()
			for inputID, inputDetails := range env.Inputs {
				rule.checkString(inputDetails.Description, "")
				rule.checkBool(inputDetails.Required, "")
				rule.checkString(inputDetails.Default, "")
				rule.checkStrings(inputDetails.Options, "")

				var inputType expressions.ExprType
				switch inputDetails.Type {
				case ast.WorkflowDispatchEventInputTypeBoolean:
					inputType = expressions.BoolType{}
				case ast.WorkflowDispatchEventInputTypeNumber:
					inputType = expressions.NumberType{}
				case ast.WorkflowDispatchEventInputTypeString:
					inputType = expressions.StringType{}
				case ast.WorkflowDispatchEventInputTypeChoice:
					inputType = expressions.StringType{}
				case ast.WorkflowDispatchEventInputTypeEnvironment:
					inputType = expressions.StringType{}
				default:
					inputType = expressions.UnknownType{}
				}
				inputTypeMap.Props[inputID] = inputType
			}
			rule.DispatchInputsType = inputTypeMap
		case *ast.RepositoryDispatchEvent:
			rule.checkStrings(env.Types, "")
		case *ast.WorkflowCallEvent:
			inputTypeMap := expressions.NewEmptyStrictObjectType()
			rule.InputsType = inputTypeMap

			for _, input := range env.Inputs {
				rule.checkString(input.Description, "")
				ts := rule.checkString(input.Default, "on.workflow_call.inputs.<inputs_id>.default")

				var inputType expressions.ExprType
				switch input.Type {
				case ast.WorkflowCallEventInputTypeString:
					inputType = expressions.StringType{}
				case ast.WorkflowCallEventInputTypeBoolean:
					inputType = expressions.BoolType{}
					if len(ts) == 1 && input.Default.IsExpressionAssigned() {
						switch ts[0].typ.(type) {
						case expressions.BoolType:
						case expressions.UnknownType:
						default:
							rule.Errorf(
								input.Default.Pos,
								"Expected boolean type for input '%q', but found '%s' type instead.",
								input.Name.Value,
								ts[0].typ.String(),
							)
						}
					}
				case ast.WorkflowCallEventInputTypeNumber:
					inputType = expressions.NumberType{}
					if len(ts) == 1 && input.Default.IsExpressionAssigned() {
						switch ts[0].typ.(type) {
						case expressions.NumberType:
						case expressions.UnknownType:
						default:
							rule.Errorf(
								input.Default.Pos,
								"Expected number type for input '%q', but found '%s' type instead.",
								input.Name.Value,
								ts[0].typ.String(),
							)
						}
					}
				default:
					inputType = expressions.UnknownType{}
				}
				inputTypeMap.Props[input.ID] = inputType
			}
			// シークレットが渡されない場合、シークレットはワークフローの呼び出し元から継承される可能性があります。
			// そのため、`secrets` コンテキストは { string => string } として型付けされる必要があります。
			//`e.Secrets` は `secrets:` が存在しない場合に nil になります。
			// `e.Secrets` が空のマップの場合、`secrets:` は存在しますが、子nodeは存在しません。
			// この場合、`secrets` は `{}` として型付けされます。
			if env.Secrets != nil {
				sty := expressions.NewEmptyObjectType()
				for id, str := range env.Secrets {
					sty.Props[id] = expressions.StringType{}
					rule.checkString(str.Description, "")
				}
				rule.SecretsType = sty
			}
			for _, object := range env.Outputs {
				rule.checkString(object.Description, "")
			}
		}
	}
	rule.checkString(node.RunName, "run-name")
	rule.checkEnv(node.Env, "env")
	rule.checkDefaults(node.Defaults, "defaults")
	rule.checkConcurrency(node.Concurrency, "concurrency")
	rule.WorkflowDefinition = node
	return nil
}

//VisitWorkflowPost is callback when visiting Workflow node after visiting its children.
func (rule *ExprRule) VisitWorkflowPost(node *ast.Workflow) error {
	if env , ok := node.FindWorkflowCallEvent(); ok {
		rule.checkWorkflowCallOutputs(env.Outputs, node.Jobs)
	}
	rule.WorkflowDefinition = nil
	return nil
}

func (rule *ExprRule) VisitJobPre(n *ast.Job) error {
	//`needs` コンテキストはマトリックス設定で使用される可能性があるため、
	//マトリックスの型を解決する前に `needs` の型を解決する必要があります
	rule.NeedsType = rule.calcNeedsType(n)
	//   jobs:
	//     foo:
	//       strategy:
	//         matrix:
	//           os: [ubuntu-latest, macos-latest, windows-latest]
	//       runs-on: ${{ matrix.os }}
	if n.Strategy != nil && n.Strategy.Matrix != nil {
		// Check and guess type of the matrix
		rule.MatrixType = rule.checkMatrix(n.Strategy.Matrix)
	}

	rule.checkString(n.Name, "jobs.<job_id>.name")
	rule.checkStrings(n.Needs, "")

	if n.RunsOn != nil {
		if n.RunsOn.LabelsExpr != nil {
			if ty := rule.checkOneExpression(n.RunsOn.LabelsExpr, "runner label at \"runs-on\" section", "jobs.<job_id>.runs-on"); ty != nil {
				switch ty.(type) {
				case *expressions.ArrayType:
				case expressions.StringType:
				case expressions.UnknownType:
				default:
					rule.Errorf(n.RunsOn.LabelsExpr.Pos, "type of expression at \"runs-on\" must be string or array but found type %q", ty.String())
				}
			}
		} else {
			for _, l := range n.RunsOn.Labels {
				rule.checkString(l, "jobs.<job_id>.runs-on")
			}
		}
		rule.checkString(n.RunsOn.Group, "jobs.<job_id>.runs-on")
	}

	rule.checkConcurrency(n.Concurrency, "jobs.<job_id>.concurrency")

	rule.checkEnv(n.Env, "jobs.<job_id>.env")

	rule.checkDefaults(n.Defaults, "jobs.<job_id>.defaults.run")
	rule.checkIfCondition(n.If, "jobs.<job_id>.if")

	if n.Strategy != nil {
		// "jobs.<job_id>.strategy.matrix" 内の型は `checkMatrix` でチェックされました。
		rule.checkBool(n.Strategy.FailFast, "jobs.<job_id>.strategy")
		rule.checkInt(n.Strategy.MaxParallel, "jobs.<job_id>.strategy")
	}

	rule.checkBool(n.ContinueOnError, "jobs.<job_id>.continue-on-error")
	rule.checkFloat(n.TimeoutMinutes, "jobs.<job_id>.timeout-minutes")
	rule.checkContainer(n.Container, "jobs.<job_id>.container", "")

	for _, s := range n.Services {
		rule.checkContainer(s.Container, "jobs.<job_id>.services", "<service_id>")
	}

	rule.checkWorkflowCall(n.WorkflowCall)

	rule.StepsType = expressions.NewEmptyStrictObjectType()

	return nil
}


func (rule *ExprRule) VisitJobPost(n *ast.Job) error {
	// 'environment' および 'outputs' セクションは、すべてのステップが実行された後に評価されます。
	if n.Environment != nil {
		rule.checkString(n.Environment.Name, "jobs.<job_id>.environment")
		rule.checkString(n.Environment.URL, "jobs.<job_id>.environment.url")
	}
	for _, output := range n.Outputs {
		rule.checkString(output.Value, "jobs.<job_id>.outputs.<output_id>")
	}

	rule.MatrixType = nil
	rule.StepsType = nil
	rule.NeedsType = nil

	return nil
}

// VisitStep is callback when visiting Step node.
func (rule *ExprRule) VisitStep(n *ast.Step) error {
	rule.checkString(n.Name, "jobs.<job_id>.steps.name")
	rule.checkIfCondition(n.If, "jobs.<job_id>.steps.if")

	var spec *ast.String
	switch e := n.Exec.(type) {
	case *ast.ExecRun:
		rule.checkScriptString(e.Run, "jobs.<job_id>.steps.run")
		rule.checkString(e.Shell, "")
		rule.checkString(e.WorkingDirectory, "jobs.<job_id>.steps.working-directory")
	case *ast.ExecAction:
		rule.checkString(e.Uses, "")
		for n, i := range e.Inputs {
			if e.Uses != nil && strings.HasPrefix(e.Uses.Value, "actions/github-script@") && n == "script" {
				rule.checkScriptString(i.Value, "jobs.<job_id>.steps.with")
			} else {
				rule.checkString(i.Value, "jobs.<job_id>.steps.with")
			}
		}
		rule.checkString(e.Entrypoint, "")
		rule.checkString(e.Args, "")
		spec = e.Uses
	}

	rule.checkEnv(n.Env, "jobs.<job_id>.steps.env") // env: at step level can refer 'env' context (#158)
	rule.checkBool(n.ContinueOnError, "jobs.<job_id>.steps.continue-on-error")
	rule.checkFloat(n.TimeoutMinutes, "jobs.<job_id>.steps.timeout-minutes")

	if n.ID != nil {
		if n.ID.ContainsExpression() {
			rule.checkString(n.ID, "")
			rule.StepsType.Loose()
		}
		// Step ID is case insensitive
		id := strings.ToLower(n.ID.Value)
		rule.StepsType.Props[id] = expressions.NewStrictObjectType(map[string]expressions.ExprType{
			"outputs":    rule.getActionOutputsType(spec),
			"conclusion": expressions.StringType{},
			"outcome":    expressions.StringType{},
		})
	}

	return nil
}

// Get type of `outputs.<output name>`
func (rule *ExprRule) getActionOutputsType(spec *ast.String) *expressions.ObjectType {
	if spec == nil {
		return expressions.NewMapObjectType(expressions.StringType{})
	}

	if strings.HasPrefix(spec.Value, "./") {
		meta, err := rule.LocalActionsCache.FindMetadata(spec.Value)
		if err != nil {
			rule.Error(spec.Pos, err.Error())
			return expressions.NewMapObjectType(expressions.StringType{})
		}
		if meta == nil {
			return expressions.NewMapObjectType(expressions.StringType{})
		}

		return typeOfActionOutputs(meta)
	}

	// github-script アクションは、`core.setOutput` を直接呼び出すことで任意の出力を設定することができます。
	// そのため、どんな `outputs.*` プロパティも受け入れられるべきです (#104)
	if strings.HasPrefix(spec.Value, "actions/github-script@") {
		return expressions.NewEmptyObjectType()
	}

	return expressions.NewMapObjectType(expressions.StringType{})
}

func (rule *ExprRule) getWorkflowCallOutputsType(call *ast.WorkflowCall) *expressions.ObjectType {
	if call.Uses == nil {
		return expressions.NewMapObjectType(expressions.StringType{})
	}

	m, err := rule.LocalWorkflowsCache.FindMetadata(call.Uses.Value)
	if err != nil {
		rule.Error(call.Uses.Pos, err.Error())
		return expressions.NewMapObjectType(expressions.StringType{})
	}
	if m == nil {
		return expressions.NewMapObjectType(expressions.StringType{})
	}

	p := make(map[string]expressions.ExprType, len(m.Outputs))
	for n := range m.Outputs {
		p[n] = expressions.StringType{}
	}
	return expressions.NewStrictObjectType(p)
}
