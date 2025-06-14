package core

import (
	"fmt"
	"io"
	"time"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// TreeVisitorはworkflowのsyntax'streeをトラバースするためのinterface
type TreeVisitor interface {
	VisitStep(node *ast.Step) error
	VisitJobPre(node *ast.Job) error
	VisitJobPost(node *ast.Job) error
	VisitWorkflowPre(node *ast.Workflow) error
	VisitWorkflowPost(node *ast.Workflow) error
}

// SyntaxTreeVisitorはworkflowのsyntax'streeをトラバースするためのinterface
type SyntaxTreeVisitor struct {
	passes []TreeVisitor
	debugW io.Writer
}

// NewSyntaxTreeVisitorはSyntaxTreeVisitorを生成する
func NewSyntaxTreeVisitor() *SyntaxTreeVisitor {
	return &SyntaxTreeVisitor{}
}

// AddVisitorはvisitorを追加する
func (s *SyntaxTreeVisitor) AddVisitor(visitor TreeVisitor) {
	s.passes = append(s.passes, visitor)
}

// AddRuleはルールをvisitorとして追加する
func (s *SyntaxTreeVisitor) AddRule(rule Rule) {
	s.passes = append(s.passes, rule)
}

// EnableDebugOutputはdebug出力を有効にする
func (s *SyntaxTreeVisitor) EnableDebugOutput(writer io.Writer) {
	s.debugW = writer
}

// logElapsedTimeは経過時間を出力する
func (s *SyntaxTreeVisitor) logreportElapsedTime(task string, startTime time.Time) {
	if s.debugW != nil {
		duration := time.Since(startTime).Milliseconds()
		fmt.Fprintf(s.debugW, "[SyntaxTreeVisitor] %s took %v ms\n", task, duration)
	}
}

// visits given syntax tree in depth-first order
func (s *SyntaxTreeVisitor) VisitTree(node *ast.Workflow) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitWorkflowPre(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitWorkflowPre", startTime)
		startTime = time.Now()
	}

	for _, job := range node.Jobs {
		if err := s.visitJob(job); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitJob was tooking %d jobs", len(node.Jobs))
		defer s.logreportElapsedTime(msg, startTime)
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitWorkflowPost(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitWorkflowPost", startTime)
	}

	return nil
}

// visitJobはjobを訪問する
func (s *SyntaxTreeVisitor) visitJob(node *ast.Job) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitJobPre(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitJobPre", startTime)
		startTime = time.Now()
	}

	for _, step := range node.Steps {
		if err := s.visitStep(step); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitStep was tooking %d steps", len(node.Steps))
		defer s.logreportElapsedTime(msg, startTime)
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitJobPost(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitJobPost was tooking %d jobs, at job %q", len(node.Steps), node.ID.Value)
		defer s.logreportElapsedTime(msg, startTime)
	}

	return nil
}

// visitStepはstepを訪問する
func (s *SyntaxTreeVisitor) visitStep(node *ast.Step) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitStep(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitStep was tooking %s steps, at step %q", node.Pos, startTime)
		defer s.logreportElapsedTime(msg, startTime)
	}

	return nil
}
