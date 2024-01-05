package core

// WorkflowKeyAvailability は、指定されたワークフローキーのコンテキストと特別な関数の可用性を返します。
// 最初の戻り値は、どのようなコンテキストが利用可能であるかを示します。 空のスライスは、任意のコンテキストが使用可能であることを意味します。
// 2番目の戻り値は、どのような特別な関数が使用できるかを示します。 空のスライスは、特別な機能が使用できないことを意味します。
// 'key' パラメータは、jobs.<job_id>.concurrencyのようなワークフローキーを表す必要があります。
//
// * https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability.
func WorkflowKeyAvailability(key string) ([]string, []string) {
	switch key {
	case "jobs.<job_id>.outputs.<output_id>":
		return []string{"env", "github", "inputs", "job", "matrix", "needs", "runner", "secrets", "steps", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.steps.continue-on-error", "jobs.<job_id>.steps.env", "jobs.<job_id>.steps.name", "jobs.<job_id>.steps.run", "jobs.<job_id>.steps.timeout-minutes", "jobs.<job_id>.steps.with", "jobs.<job_id>.steps.working-directory":
		return []string{"env", "github", "inputs", "job", "matrix", "needs", "runner", "secrets", "steps", "strategy", "vars"}, []string{"hashfiles"}
	case "jobs.<job_id>.container.env.<env_id>", "jobs.<job_id>.services.<service_id>.env.<env_id>":
		return []string{"env", "github", "inputs", "job", "matrix", "needs", "runner", "secrets", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.environment.url":
		return []string{"env", "github", "inputs", "job", "matrix", "needs", "runner", "steps", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.steps.if":
		return []string{"env", "github", "inputs", "job", "matrix", "needs", "runner", "steps", "strategy", "vars"}, []string{"always", "canceled", "failure", "hashfiles", "success"}
	case "jobs.<job_id>.container.credentials", "jobs.<job_id>.services.<service_id>.credentials":
		return []string{"env", "github", "inputs", "matrix", "needs", "secrets", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.defaults.run":
		return []string{"env", "github", "inputs", "matrix", "needs", "strategy", "vars"}, []string{}
	case "on.workflow_call.outputs.<output_id>.value":
		return []string{"github", "inputs", "jobs", "vars"}, []string{}
	case "jobs.<job_id>.env", "jobs.<job_id>.secrets.<secrets_id>":
		return []string{"github", "inputs", "matrix", "needs", "secrets", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.concurrency", "jobs.<job_id>.container", "jobs.<job_id>.container.image", "jobs.<job_id>.continue-on-error", "jobs.<job_id>.environment", "jobs.<job_id>.name", "jobs.<job_id>.runs-on", "jobs.<job_id>.services", "jobs.<job_id>.timeout-minutes", "jobs.<job_id>.with.<with_id>":
		return []string{"github", "inputs", "matrix", "needs", "strategy", "vars"}, []string{}
	case "jobs.<job_id>.strategy":
		return []string{"github", "inputs", "needs", "vars"}, []string{}
	case "jobs.<job_id>.if":
		return []string{"github", "inputs", "needs", "vars"}, []string{"always", "canceled", "failure", "success"}
	case "env":
		return []string{"github", "inputs", "secrets", "vars"}, []string{}
	case "concurrency", "on.workflow_call.inputs.<inputs_id>.default", "run-name":
		return []string{"github", "inputs", "vars"}, []string{}
	default:
		return nil, nil
	}
}
