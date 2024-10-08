package core

import (
	"github.com/ultra-supara/sisakulint/pkg/ast"
)

// VisitStep is callback when visiting Step node.
func (r *BaseRule) VisitStep(node *ast.Step) error { return nil }

// VisitJobPre is callback when visiting Job node before visiting its children.
func (r *BaseRule) VisitJobPre(node *ast.Job) error { return nil }

// VisitJobPost is callback when visiting Job node after visiting its children.
func (r *BaseRule) VisitJobPost(node *ast.Job) error { return nil }

// VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
func (r *BaseRule) VisitWorkflowPre(node *ast.Workflow) error { return nil }

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children.
func (r *BaseRule) VisitWorkflowPost(node *ast.Workflow) error { return nil }
