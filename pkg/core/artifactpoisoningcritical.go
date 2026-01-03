package core

import (
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

type ArtifactPoisoning struct {
	BaseRule
}

func ArtifactPoisoningRule() *ArtifactPoisoning {
	return &ArtifactPoisoning{
		BaseRule: BaseRule{
			RuleName: "artifact-poisoning-critical",
			RuleDesc: "Detects unsafe artifact downloads that may allow artifact poisoning attacks. Artifacts should be extracted to a temporary folder to prevent overwriting existing files and should be treated as untrusted content.",
		},
	}
}

func (rule *ArtifactPoisoning) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	if !strings.HasPrefix(action.Uses.Value, "actions/download-artifact@") {
		return nil
	}

	pathInput, hasPath := action.Inputs["path"]
	if !hasPath || pathInput == nil || pathInput.Value == nil || pathInput.Value.Value == "" {
		rule.Errorf(
			step.Pos,
			"artifact is downloaded without specifying a safe extraction path at step %q. This may allow artifact poisoning where malicious files overwrite existing files. Consider extracting to a temporary folder like '${{ runner.temp }}/artifacts' to prevent overwriting existing files. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/",
			step.String(),
		)
		rule.AddAutoFixer(NewStepFixer(step, rule))
	}

	return nil
}

func (rule *ArtifactPoisoning) FixStep(step *ast.Step) error {
	action := step.Exec.(*ast.ExecAction)

	if action.Inputs == nil {
		action.Inputs = make(map[string]*ast.Input)
	}

	action.Inputs["path"] = &ast.Input{
		Name: &ast.String{
			Value: "path",
			Pos:   step.Pos,
		},
		Value: &ast.String{
			Value: "${{ runner.temp }}/artifacts",
			Pos:   step.Pos,
		},
	}

	addPathToWith(step.BaseNode)
	return nil
}

func addPathToWith(node *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}

	withIndex := -1
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "with" {
			withIndex = i
			break
		}
	}

	pathKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "path"}
	pathValue := &yaml.Node{Kind: yaml.ScalarNode, Value: "${{ runner.temp }}/artifacts"}

	if withIndex >= 0 {
		withNode := node.Content[withIndex+1]
		if withNode.Kind == yaml.MappingNode {
			for i := 0; i < len(withNode.Content); i += 2 {
				if withNode.Content[i].Value == "path" {
					return
				}
			}
			withNode.Content = append(withNode.Content, pathKey, pathValue)
		}
		return
	}

	usesIndex := -1
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "uses" {
			usesIndex = i
			break
		}
	}

	withKey := &yaml.Node{Kind: yaml.ScalarNode, Value: "with"}
	withValue := &yaml.Node{
		Kind:    yaml.MappingNode,
		Content: []*yaml.Node{pathKey, pathValue},
	}

	if usesIndex >= 0 {
		insertIndex := usesIndex + 2
		node.Content = append(
			node.Content[:insertIndex],
			append([]*yaml.Node{withKey, withValue}, node.Content[insertIndex:]...)...,
		)
	} else {
		node.Content = append(node.Content, withKey, withValue)
	}
}
