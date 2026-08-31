package core

import "github.com/sisaku-security/sisakulint/pkg/ast"

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

// This is a dummy implementation of the Fix method
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
		fixer:         fixer,
	}
}

type JobFixer interface {
	RuleNames() string
	FixJob(node *ast.Job) error
}

type jobFixer struct {
	BaseAutoFixer
	job   *ast.Job
	fixer JobFixer
}

func (j *jobFixer) Fix() error {
	return j.fixer.FixJob(j.job)
}

func NewJobFixer(job *ast.Job, fixer JobFixer) AutoFixer {
	return &jobFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: fixer.RuleNames()},
		job:           job,
		fixer:         fixer,
	}
}

// arbitrary function fixer
type funcFixer struct {
	BaseAutoFixer
	fixer func() error
}

func (f *funcFixer) Fix() error {
	return f.fixer()
}

func NewFuncFixer(ruleName string, fixer func() error) AutoFixer {
	return &funcFixer{
		BaseAutoFixer: BaseAutoFixer{ruleName: ruleName},
		fixer:         fixer,
	}
}
