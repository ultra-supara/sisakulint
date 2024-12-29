package core

import "github.com/ultra-supara/sisakulint/pkg/ast"

type AutoFixer interface {
	RuleName() string
	Fix() error
}

type BaseAutoFixer struct {
	ruleName string
}

func (b *BaseAutoFixer) RuleName() string {
	return b.ruleName
}

func (b *BaseAutoFixer) Fix() error {
	return nil
}

type StepFixer interface {
	RuleNames() string
	FixStep(node *ast.Step) error
}
type stepFixer struct {
	BaseAutoFixer
	step  *ast.Step
	fixer StepFixer
}

func (s *stepFixer) Fix() error {
	return s.fixer.FixStep(s.step)
}

func NewStepFixer(step *ast.Step, fixer StepFixer) AutoFixer {
	return &stepFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: fixer.RuleNames()},
		step:          step,
	}
}
