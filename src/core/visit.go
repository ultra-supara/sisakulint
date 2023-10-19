package core

import (
	"github.com/ultra-supara/sisakulint/src/analysis"
)

// VisitStep is callback when visiting Step node.
func (r *BaseRule) VisitStep(node *analysis.Step) error { return nil }

// VisitJobPre is callback when visiting Job node before visiting its children.
func (r *BaseRule) VisitJobPre(node *analysis.Job) error { return nil }

// VisitJobPost is callback when visiting Job node after visiting its children.
func (r *BaseRule) VisitJobPost(node *analysis.Job) error { return nil }

// VisitWorkflowPre is callback when visiting Workflow node before visiting its children.
func (r *BaseRule) VisitWorkflowPre(node *analysis.Workflow) error { return nil }

// VisitWorkflowPost is callback when visiting Workflow node after visiting its children.
func (r *BaseRule) VisitWorkflowPost(node *analysis.Workflow) error { return nil }
