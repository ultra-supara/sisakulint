package core

import (
	"strconv"
	"strings"

	"github.com/ultra-supara/sisakulint/src/ast"
	"github.com/ultra-supara/sisakulint/src/expressions"
)

// checkOneExpression は単一の式をチェックします。
func (rule *ExprRule) checkOneExpression(str *ast.String, what, workflowKey string) expressions.ExprType {
	// checkString は文字列に埋め込まれた値の型をチェックするため、利用できません
	if str == nil {
		return nil
	}

	ts, ok := rule.checkExprsIn(str.Value, str.Pos, str.Quoted, false, workflowKey)
	if !ok {
		return nil
	}

	if len(ts) != 1 {
		// このケースは到達不可能であるべきです。パーサーによって一つの ${{ }} が含まれていることがチェックされます
		//rule.Errorf(str.Pos, "one ${{ }} expression should be included in %q value but got %d expressions", what, len(ts))
		return nil
	}

	return ts[0].typ
}

// checkObjectTy は式の型がオブジェクトかどうかをチェックします。
func (rule *ExprRule) checkObjectTy(ty expressions.ExprType, pos *ast.Position, what string) expressions.ExprType {
	if ty == nil {
		return nil
	}
	switch ty.(type) {
	case *expressions.ObjectType, expressions.UnknownType:
		return ty
	default:
		rule.Errorf(pos, "type of expression at %q must be object but found type %s", what, ty.String())
		return nil
	}
}

// checkArrayTy は式の型が配列かどうかをチェックします。
func (rule *ExprRule) checkArrayTy(ty expressions.ExprType, pos *ast.Position, what string) expressions.ExprType {
	if ty == nil {
		return nil
	}
	switch ty.(type) {
	case *expressions.ArrayType, expressions.UnknownType:
		return ty
	default:
		rule.Errorf(pos, "type of expression at %q must be array but found type %s", what, ty.String())
		return nil
	}
}

// checkNumberTy は式の型が数値かどうかをチェックします。
func (rule *ExprRule) checkNumberTy(ty expressions.ExprType, pos *ast.Position, what string) expressions.ExprType {
	if ty == nil {
		return nil
	}
	switch ty.(type) {
	case expressions.NumberType, expressions.UnknownType:
		return ty
	default:
		rule.Errorf(pos, "type of expression at %q must be number but found type %s", what, ty.String())
		return nil
	}
}

// checkObjectExpression はオブジェクト型の式をチェックします。
func (rule *ExprRule) checkObjectExpression(s *ast.String, what, workflowKey string) expressions.ExprType {
	ty := rule.checkOneExpression(s, what, workflowKey)
	if ty == nil {
		return nil
	}
	return rule.checkObjectTy(ty, s.Pos, what)
}

// checkArrayExpression は配列型の式をチェックします。
func (rule *ExprRule) checkArrayExpression(s *ast.String, what, workflowKey string) expressions.ExprType {
	ty := rule.checkOneExpression(s, what, workflowKey)
	if ty == nil {
		return nil
	}
	return rule.checkArrayTy(ty, s.Pos, what)
}

// checkNumberExpression は数値型の式をチェックします。
func (rule *ExprRule) checkNumberExpression(s *ast.String, what, workflowKey string) expressions.ExprType {
	ty := rule.checkOneExpression(s, what, workflowKey)
	if ty == nil {
		return nil
	}
	return rule.checkNumberTy(ty, s.Pos, what)
}

// checkEnv は環境変数をチェックします。
func (rule *ExprRule) checkEnv(env *ast.Env, workflowKey string) {
	if env == nil {
		return
	}

	if env.Vars != nil {
		for _, e := range env.Vars {
			rule.checkString(e.Name, workflowKey)
			rule.checkString(e.Value, workflowKey)
		}
		return
	}

	// "env: ${{...}}" の形式
	rule.checkObjectExpression(env.Expression, "env", workflowKey)
}

// checkContainer はコンテナをチェックします。
func (rule *ExprRule) checkContainer(c *ast.Container, workflowKey, childWorkflowKeyPrefix string) {
	if c == nil {
		return
	}
	childWorkflowKey := workflowKey
	if childWorkflowKeyPrefix != "" {
		childWorkflowKey += "." + childWorkflowKeyPrefix
	}
	rule.checkString(c.Image, workflowKey)
	if c.Credentials != nil {
		k := childWorkflowKey + ".credentials" // 例: jobs.<job_id>.container.credentials
		rule.checkString(c.Credentials.Username, k)
		rule.checkString(c.Credentials.Password, k)
	}
	rule.checkEnv(c.Env, workflowKey+".env.<env_id>") // 例: jobs.<job_id>.container.env.<env_id>
	rule.checkStrings(c.Ports, workflowKey)
	rule.checkStrings(c.Volumes, workflowKey)
	rule.checkString(c.Options, workflowKey)
}

// checkConcurrency は並行処理をチェックします。
func (rule *ExprRule) checkConcurrency(c *ast.Concurrency, workflowKey string) {
	if c == nil {
		return
	}
	rule.checkString(c.Group, workflowKey)
	rule.checkBool(c.CancelInProgress, workflowKey)
}

// checkDefaults はデフォルト設定をチェックします。
func (rule *ExprRule) checkDefaults(d *ast.Defaults, workflowKey string) {
	if d == nil || d.Run == nil {
		return
	}
	rule.checkString(d.Run.Shell, workflowKey)
	rule.checkString(d.Run.WorkingDirectory, workflowKey)
}

// checkWorkflowCall はワークフローコールをチェックします。
func (rule *ExprRule) checkWorkflowCall(c *ast.WorkflowCall) {
	if c == nil || c.Uses == nil {
		return
	}

	rule.checkString(c.Uses, "")

	m, err := rule.LocalWorkflowsCache.FindMetadata(c.Uses.Value)
	if err != nil {
		rule.Error(c.Uses.Pos, err.Error())
	}

	for n, i := range c.Inputs {
		ts := rule.checkString(i.Value, "jobs.<job_id>.with.<with_id>")

		if m == nil {
			continue
		}

		mi, ok := m.Inputs[n]
		if !ok || mi == nil {
			continue
		}
		if _, ok := mi.Type.(expressions.UnknownType); ok {
			continue
		}

		v := strings.TrimSpace(i.Value.Value)

		var ty expressions.ExprType = expressions.StringType{}
		switch len(ts) {
		case 0:
			switch v {
			case "null":
				ty = expressions.NullType{}
			case "true", "false":
				ty = expressions.BoolType{}
			default:
				if _, err := strconv.ParseFloat(v, 64); err == nil {
					ty = expressions.NumberType{}
				}
			}
		case 1:
			if i.Value.IsExpressionAssigned() {
				ty = ts[0].typ
			}
		}

		if !mi.Type.Assignable(ty) {
			rule.Errorf(
				i.Value.Pos,
				"input %q is typed as %s by reusable workflow %q. %s value cannot be assigned",
				mi.Name,
				mi.Type.String(),
				c.Uses.Value,
				ty.String(),
			)
		}
	}

	for _, s := range c.Secrets {
		rule.checkString(s.Value, "jobs.<job_id>.secrets.<secrets_id>")
	}
}

// checkWebhookEventFilter はWebhookイベントフィルターをチェックします。
func (rule *ExprRule) checkWebhookEventFilter(f *ast.WebhookEventFilter) {
	if f == nil {
		return
	}
	rule.checkStrings(f.Values, "")
}

// checkStrings は複数の文字列をチェックします。
func (rule *ExprRule) checkStrings(ss []*ast.String, workflowKey string) {
	for _, s := range ss {
		rule.checkString(s, workflowKey)
	}
}

func (rule *ExprRule) checkIfCondition(str *ast.String, workflowKey string) {
	if str == nil {
		return
	}

	//* https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idif
	// if 条件式で式を使用する場合、演算子を含まない限り、${{ }} を省略できます。
	// GitHub Actionsは、式に演算子が含まれていない場合、if 条件式を自動的に式として評価します。
	// 式に演算子が含まれている場合は、式を明示的に評価するために、式を ${{ }} で囲む必要があります。
	// しかし、このドキュメントは誤りです。$ {{ }} で囲まれていない任意の文字列は評価されます。
	// 例えば、次のような文字列は、if 条件式として評価されます。
	// - run: echo 'run'
	//   if: '!false'  if: '!false'は、'false'の否定であるため、このコマンドは実行されます。
	// - run: echo 'not run'
	//   if: '!true'   if: '!true'は、'true'の否定であるため、このコマンドは実行されません。
	// - run: echo 'run'
	//   if: false || true  if: false || trueは、'false'または'true'が真である場合に実行されます。この場合、'true'が真であるため、コマンドは実行されます。
	// - run: echo 'run'
	//   if: true && true  if: true && trueは、'true'かつ'true'が真である場合に実行されます。この場合、'true'かつ'true'が真であるため、コマンドは実行されます。
	// - run: echo 'not run'
	//   if: true && false if: true && falseは、'true'かつ'false'が真である場合に実行されます。この場合、'false'が偽であるため、コマンドは実行されません。

	var condTy expressions.ExprType
	if str.ContainsExpression() {
		ts := rule.checkString(str, workflowKey)

		if len(ts) == 1 {
			if str.IsExpressionAssigned() {
				condTy = ts[0].typ
			}
		}
	} else {
		src := str.Value + "}}" // }} is necessary since lexer lexes it as end of tokens
		line, col := str.Pos.Line, str.Pos.Col

		p := expressions.NewMiniParser()
		exset := expressions.NewTokenizer(src)
		expr, err := p.Parse(exset)
		if err != nil {
			rule.exprError(err, line, col)
			return
		}

		if ty, ok := rule.checkSemanticsOfExprNode(expr, line, col, false, workflowKey); ok {
			condTy = ty
		}
	}

	if condTy != nil && !(expressions.BoolType{}).Assignable(condTy) {
		rule.Errorf(str.Pos, "\"if\" condition should be type \"bool\" but got type %q", condTy.String())
	}
}

// checkTemplateEvaluatedType はテンプレート内で評価されるべきでない型（オブジェクト、配列、null）をチェックします。
func (rule *ExprRule) checkTemplateEvaluatedType(ts []typedExpression) {
	for _, t := range ts {
		switch t.typ.(type) {
		case *expressions.ObjectType, *expressions.ArrayType, expressions.NullType:
			rule.Errorf(&t.pos, "object, array, and null values should not be evaluated in template with ${{ }} but evaluating the value of type %s", t.typ)
		}
	}
}

// checkString は文字列内の式をチェックします。
func (rule *ExprRule) checkString(str *ast.String, workflowKey string) []typedExpression {
	if str == nil {
		return nil
	}

	ts, ok := rule.checkExprsIn(str.Value, str.Pos, str.Quoted, false, workflowKey)
	if !ok {
		return nil
	}

	rule.checkTemplateEvaluatedType(ts)
	return ts
}

// checkScriptString はスクリプト文字列内の式をチェックします。
func (rule *ExprRule) checkScriptString(str *ast.String, workflowKey string) {
	if str == nil {
		return
	}

	ts, ok := rule.checkExprsIn(str.Value, str.Pos, str.Quoted, true, workflowKey)
	if !ok {
		return
	}

	rule.checkTemplateEvaluatedType(ts)
}

// checkBool はブール値の式をチェックします。
func (rule *ExprRule) checkBool(b *ast.Bool, workflowKey string) {
	if b == nil || b.Expression == nil {
		return
	}

	ty := rule.checkOneExpression(b.Expression, "bool value", workflowKey)
	if ty == nil {
		return
	}

	switch ty.(type) {
	case expressions.BoolType:
	case expressions.UnknownType:
	default:
		rule.Errorf(b.Expression.Pos, "type of expression must be bool but found type %s", ty.String())
	}
}

// checkInt は整数値の式をチェックします。
func (rule *ExprRule) checkInt(i *ast.Int, workflowKey string) {
	if i == nil {
		return
	}
	rule.checkNumberExpression(i.Expression, "integer value", workflowKey)
}

// checkFloat は浮動小数点数の式をチェックします。
func (rule *ExprRule) checkFloat(f *ast.Float, workflowKey string) {
	if f == nil {
		return
	}
	rule.checkNumberExpression(f.Expression, "float number value", workflowKey)
}

// checkExprsIn は文字列内の式をチェックし、型付けされた式のリストを返します。
func (rule *ExprRule) checkExprsIn(s string, pos *ast.Position, quoted, checkUntrusted bool, workflowKey string) ([]typedExpression, bool) {
	// 文字列に改行が含まれる場合、行番号は正しくありません。
	Line, Col := pos.Line, pos.Col
	if quoted {
		Col++ // 文字列が 'foo' や "foo" のように引用符で囲まれている場合、列はインクリメントされるべきです
	}
	offset := 0
	ts := []typedExpression{}
	for {
		idx := strings.Index(s, "${{")
		if idx == -1 {
			break
		}

		start := idx + 3 // 3 は "${{" を取り除くため
		s = s[start:]
		offset += start
		col := Col + offset

		ty, offsetAfter, ok := rule.checkSemantics(s, Line, col, checkUntrusted, workflowKey)
		if !ok {
			return nil, false
		}
		if ty == nil || offsetAfter == 0 {
			return nil, true
		}
		ts = append(ts, typedExpression{ty, ast.Position{Line: Line, Col: Col - 3}})

		s = s[offsetAfter:]
		offset += offsetAfter
	}

	return ts, true
}

// exprError は式のエラーを処理します。
func (rule *ExprRule) exprError(err *expressions.ExprError, lineBase, colBase int) {
	pos := convertExprLineColToPos(err.Line, err.Column, lineBase, colBase)
	rule.Error(pos, err.Message)
}

// checkSemanticsOfExprNode は式ノードのセマンティクスをチェックします。
func (rule *ExprRule) checkSemanticsOfExprNode(expr expressions.ExprNode, line, col int, checkUntrusted bool, workflowKey string) (expressions.ExprType, bool) {
	var v []string
	if rule.userConfig != nil {
		v = rule.userConfig.ConfigVariables
	}
	c := expressions.NewExprSemanticsChecker(checkUntrusted, v)
	if rule.MatrixType != nil {
		c.UpdateMatrix(rule.MatrixType)
	}
	if rule.StepsType != nil {
		c.UpdateSteps(rule.StepsType)
	}
	if rule.NeedsType != nil {
		c.UpdateNeeds(rule.NeedsType)
	}
	if rule.SecretsType != nil {
		c.UpdateSecrets(rule.SecretsType)
	}
	if rule.InputsType != nil {
		c.UpdateInputs(rule.InputsType)
	}
	if rule.DispatchInputsType != nil {
		c.UpdateDispatchInputs(rule.DispatchInputsType)
	}
	if rule.JobsType != nil {
		c.UpdateJobs(rule.JobsType)
	}
	if workflowKey != "" {
		ctx, sp := WorkflowKeyAvailability(workflowKey)
		if len(ctx) == 0 {
			rule.Debug("WorkflowKeyAvailability: %q", workflowKey)
		}
		c.SetContextAvailability(ctx)
		c.SetSpecialFunctionAvailability(sp)
	}

	ty, errs := c.Check(expr)
	for _, err := range errs {
		rule.exprError(err, line, col)
	}

	return ty, len(errs) == 0
}

// todo: checkSemantics は式のセマンティクスをチェックします。
func (rule *ExprRule) checkSemantics(src string, line, col int, checkUntrusted bool, workflowKey string) (expressions.ExprType, int, bool) {
	l := expressions.NewTokenizer(src)
	p := expressions.NewMiniParser()
	expr, err := p.Parse(l)
	if err != nil {
		rule.exprError(err, line, col)
		return nil, l.GetCurrentOffset(), false
	}
	t, ok := rule.checkSemanticsOfExprNode(expr, line, col, checkUntrusted, workflowKey)
	return t, l.GetCurrentOffset(), ok
}

// calcNeedsType はジョブの 'needs' コンテキストの型を計算します。
func (rule *ExprRule) calcNeedsType(job *ast.Job) *expressions.ObjectType {
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#needs-context
	obj := expressions.NewEmptyStrictObjectType()
	rule.populateDependantNeedsTypes(obj, job, job)
	return obj
}

// populateDependantNeedsTypes は依存するジョブの 'needs' コンテキストの型を埋めます。
func (rule *ExprRule) populateDependantNeedsTypes(out *expressions.ObjectType, job *ast.Job, root *ast.Job) {
	for _, id := range job.Needs {
		i := strings.ToLower(id.Value) // IDは大文字小文字を区別しません
		if i == root.ID.Value {
			continue // 循環依存が存在する場合。通常は発生しません。
		}
		if _, ok := out.Props[i]; ok {
			continue // 既に追加されています
		}

		j, ok := rule.WorkflowDefinition.Jobs[i]
		if !ok {
			continue
		}

		var outputs *expressions.ObjectType
		if j.WorkflowCall == nil {
			outputs = expressions.NewEmptyStrictObjectType()
			for name := range j.Outputs {
				outputs.Props[name] = expressions.StringType{}
			}
		} else {
			outputs = rule.getWorkflowCallOutputsType(j.WorkflowCall)
		}

		out.Props[i] = expressions.NewStrictObjectType(map[string]expressions.ExprType{
			"outputs": outputs,
			"result":  expressions.StringType{},
		})
	} // (#151)
}

// checkMatrixExpression はマトリックス式をチェックします。
func (rule *ExprRule) checkMatrixExpression(expr *ast.String) *expressions.ObjectType {
	ty := rule.checkObjectExpression(expr, "matrix", "jobs.<job_id>.strategy")
	if ty == nil {
		return expressions.NewEmptyObjectType()
	}
	matrixType, ok := ty.(*expressions.ObjectType)
	if !ok {
		return expressions.NewEmptyObjectType()
	}

	// 'include' セクションの要素のプロパティを考慮する。'include' セクションはマトリックスの値を追加する。
	includeType, includeExists := matrixType.Props["include"]
	if includeExists {
		delete(matrixType.Props, "include")
		if includeArray, isArray := includeType.(*expressions.ArrayType); isArray {
			if includeObject, isObject := includeArray.Elem.(*expressions.ObjectType); isObject {
				for propName, propValue := range includeObject.Props {
					existingType, exists := matrixType.Props[propName]
					if !exists {
						matrixType.Props[propName] = propValue
						continue
					}
					matrixType.Props[propName] = existingType.Merge(propValue)
				}
			}
		}
	}
	delete(matrixType.Props, "exclude")

	return matrixType
}

func (rule *ExprRule) checkMatrix(m *ast.Matrix) *expressions.ObjectType {
	if m.Expression != nil {
		return rule.checkMatrixExpression(m.Expression)
	}

	// Check types of "exclude" but they are not used to guess type of matrix
	if m.Exclude != nil {
		if m.Exclude.Expression != nil {
			if ty, ok := rule.checkArrayExpression(m.Exclude.Expression, "exclude", "jobs.<job_id>.strategy").(*expressions.ArrayType); ok {
				rule.checkObjectTy(ty.Elem, m.Exclude.Expression.Pos, "exclude")
			}
		} else {
			for _, combi := range m.Exclude.Combinations {
				if combi.Expression != nil {
					rule.checkObjectExpression(combi.Expression, "exclude", "jobs.<job_id>.strategy")
					continue
				}
				for _, a := range combi.Assigns {
					rule.checkRawYAMLValue(a.Value)
				}
			}
		}
	}

	objectType := expressions.NewEmptyStrictObjectType()

	// マトリックスの各行をチェック
	for rowName, matrixRow := range m.Rows {
		objectType.Props[rowName] = rule.checkMatrixRow(matrixRow)
	}

	// 'include' セクションがない場合は、ここで終了
	if m.Include == nil {
		return objectType
	}

	// 'include' セクションの式をチェック
	if m.Include.Expression != nil {
		arrayType, isValidArrayType := rule.checkOneExpression(m.Include.Expression, "include", "jobs.<job_id>.strategy").(*expressions.ArrayType)
		if isValidArrayType {
			mergedObjectType, isObjectType := objectType.Merge(arrayType.Elem).(*expressions.ObjectType)
			if isObjectType {
				return mergedObjectType
			}
		}
		return expressions.NewEmptyObjectType()
	}

	// 'include' セクションの組み合わせをチェック
	for _, combination := range m.Include.Combinations {
		if combination.Expression != nil {
			typeChecked := rule.checkOneExpression(m.Include.Expression, "matrix combination at element of include section", "jobs.<job_id>.strategy")
			if typeChecked == nil {
				continue
			}
			mergedObjectType, isObjectType := objectType.Merge(typeChecked).(*expressions.ObjectType)
			if isObjectType {
				objectType = mergedObjectType
			} else {
				objectType.Loose()
			}
			continue
		}

		for propName, assignment := range combination.Assigns {
			typeChecked := rule.checkRawYAMLValue(assignment.Value)
			if existingType, exists := objectType.Props[propName]; exists {
				// マトリックスセクションに組み合わせが存在する場合、既存の型とマージ
				typeChecked = existingType.Merge(typeChecked)
			}
			objectType.Props[propName] = typeChecked
		}
	}
	return objectType
}

// checkMatrixRow はマトリックス行の式をチェックし、その型を返します。
func (rule *ExprRule) checkMatrixRow(r *ast.MatrixRow) expressions.ExprType {
	if r.Expression != nil {
		if a, ok := rule.checkArrayExpression(r.Expression, "matrix row", "jobs.<job_id>.strategy").(*expressions.ArrayType); ok {
			return a.Elem
		}
		return expressions.UnknownType{}
	}

	var ty expressions.ExprType
	for _, v := range r.Values {
		t := rule.checkRawYAMLValue(v)
		if ty == nil {
			ty = t
		} else {
			ty = ty.Merge(t)
		}
	}

	if ty == nil {
		return expressions.UnknownType{} // 要素がない場合
	}

	return ty
}

// checkWorkflowCallOutputs はワークフローコールの出力をチェックします。
func (rule *ExprRule) checkWorkflowCallOutputs(workflowCallOutputs map[string]*ast.WorkflowCallEventOutput, jobDefinitions map[string]*ast.Job) {
	if len(workflowCallOutputs) == 0 || len(jobDefinitions) == 0 {
		return
	}

	jobProps := make(map[string]expressions.ExprType, len(jobDefinitions))
	for jobName, job := range jobDefinitions {
		var outputsType *expressions.ObjectType
		if job.WorkflowCall != nil {
			// reusable workflow callの場合、jobs.<job_id> セクションで outputs は定義されない。
			outputsType = expressions.NewEmptyObjectType()
		} else {
			outputProps := make(map[string]expressions.ExprType, len(job.Outputs))
			for outputName := range job.Outputs {
				outputProps[outputName] = expressions.StringType{}
			}
			outputsType = expressions.NewStrictObjectType(outputProps)
		}
		jobProps[jobName] = expressions.NewStrictObjectType(map[string]expressions.ExprType{
			"outputs": outputsType,
		})
	}
	rule.JobsType = expressions.NewStrictObjectType(jobProps)

	for _, output := range workflowCallOutputs {
		rule.checkString(output.Value, "on.workflow_call.outputs.<output_id>.value")
	}
}

// checkRawYAMLValue はYAMLの原生値をチェックし、その型を返します。
func (rule *ExprRule) checkRawYAMLValue(v ast.RawYAMLValue) expressions.ExprType {
	switch v := v.(type) {
	case *ast.RawYAMLObject:
		m := make(map[string]expressions.ExprType, len(v.Props))
		for k, p := range v.Props {
			m[k] = rule.checkRawYAMLValue(p)
		}
		return expressions.NewStrictObjectType(m)
	case *ast.RawYAMLArray:
		if len(v.Elems) == 0 {
			return &expressions.ArrayType{Elem: expressions.UnknownType{}, Deref: false}
		}
		elem := rule.checkRawYAMLValue(v.Elems[0])
		for _, v := range v.Elems[1:] {
			elem = elem.Merge(rule.checkRawYAMLValue(v))
		}
		return &expressions.ArrayType{Elem: elem, Deref: false}
	case *ast.RawYAMLString:
		return rule.checkRawYAMLString(v)
	default:
		panic("unreachable")
	}
}

// checkRawYAMLString はYAMLの文字列値をチェックし、その型を返します。
func (rule *ExprRule) checkRawYAMLString(y *ast.RawYAMLString) expressions.ExprType {
	ts, ok := rule.checkExprsIn(y.Value, y.Pos(), false, false, "jobs.<job_id>.strategy")

	if ast.IsExprAssigned(y.Value) {
		if !ok || len(ts) == 1 {
			return expressions.UnknownType{}
		}
		return ts[0].typ
	}

	s := strings.TrimSpace(y.Value)
	// キーワードは大文字小文字を区別します。TRUE, FALSE, NULL は無効な名前付き値です。
	if s == "true" || s == "false" {
		return expressions.BoolType{}
	}
	if s == "null" {
		return expressions.NullType{}
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return expressions.NumberType{}
	}
	return expressions.StringType{}
}

// convertExprLineColToPos は式のエラーの行と列を位置情報に変換します。
func convertExprLineColToPos(line, col, lineBase, colBase int) *ast.Position {
	// ExprError内の行と列は1ベースです
	return &ast.Position{
		Line: line - 1 + lineBase,
		Col:  col - 1 + colBase,
	}
}

// typeOfActionOutputs はアクションの出力の型を計算します。
func typeOfActionOutputs(meta *ActionMetadata) *expressions.ObjectType {
	// 一部のアクションは動的に出力を設定します。これらの出力は action.yml に定義されていません。
	// actionlint はこれらの出力を静的にチェックできないため、任意のプロパティを許可します。
	if meta.SkipOutputs {
		return expressions.NewEmptyObjectType()
	}
	props := make(map[string]expressions.ExprType, len(meta.Outputs))
	for n := range meta.Outputs {
		props[strings.ToLower(n)] = expressions.StringType{}
	}
	return expressions.NewStrictObjectType(props)
}
