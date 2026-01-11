package core

import (
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestNewConditionalRule(t *testing.T) {
	tests := []struct {
		name string
		want *ConditionalRule
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewConditionalRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConditionalRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConditionalRule_VisitStep(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Step
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitStep(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitStep() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_VisitJobPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Job
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_VisitJobPost(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Job
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPost(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.VisitJobPost() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionalRule_checkcond(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.String
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &ConditionalRule{
				BaseRule: tt.fields.BaseRule,
			}
			rule.checkcond(tt.args.n)
		})
	}
}

func TestStripExpressionWrappers(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single wrapper at start",
			input:    "${{ steps.previous.outputs.status }} == 'success'",
			expected: "steps.previous.outputs.status  == 'success'",
		},
		{
			name:     "multiple wrappers",
			input:    "${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}",
			expected: "github.event.repository.owner.id  ==  github.event.sender.id",
		},
		{
			name:     "wrapper at end",
			input:    "github.ref == ${{ 'refs/heads/main' }}",
			expected: "github.ref ==  'refs/heads/main'",
		},
		{
			name:     "no wrappers",
			input:    "github.ref == 'refs/heads/main'",
			expected: "github.ref == 'refs/heads/main'",
		},
		{
			name:     "complex expression with multiple wrappers",
			input:    "${{ github.event_name }} == 'pull_request' && ${{ github.base_ref }} == 'main'",
			expected: "github.event_name  == 'pull_request' &&  github.base_ref  == 'main'",
		},
		{
			name:     "wrapper with spaces",
			input:    "${{  github.event.repository.owner.id  }} == ${{  github.event.sender.id  }}",
			expected: "github.event.repository.owner.id   ==   github.event.sender.id",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "only wrappers",
			input:    "${{ }}",
			expected: "",
		},
		{
			name:     "nested-like pattern",
			input:    "${{ matrix.os }} == 'ubuntu-latest' && ${{ matrix.version }} == '1.0'",
			expected: "matrix.os  == 'ubuntu-latest' &&  matrix.version  == '1.0'",
		},
		{
			name:     "string literal with multiple spaces",
			input:    "${{ steps.test.outputs.msg }} == 'test  value'",
			expected: "steps.test.outputs.msg  == 'test  value'",
		},
		{
			name:     "string literal with leading/trailing spaces",
			input:    "${{ github.event.name }} == '  spaces  '",
			expected: "github.event.name  == '  spaces  '",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripExpressionWrappers(tt.input)
			if got != tt.expected {
				t.Errorf("stripExpressionWrappers() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConditionalRule_FixStep(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "fix step with single wrapper",
			input:    "${{ steps.previous.outputs.status }} == 'success'",
			expected: "steps.previous.outputs.status  == 'success'",
			wantErr:  false,
		},
		{
			name:     "fix step with multiple wrappers",
			input:    "${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}",
			expected: "github.event.repository.owner.id  ==  github.event.sender.id",
			wantErr:  false,
		},
		{
			name:     "step without expression",
			input:    "always()",
			expected: "always()",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewConditionalRule()
			baseNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.input,
			}
			step := &ast.Step{
				If: &ast.String{
					BaseNode: baseNode,
					Value:    tt.input,
				},
			}

			err := rule.FixStep(step)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.FixStep() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if step.If != nil && step.If.BaseNode.Value != tt.expected {
				t.Errorf("ConditionalRule.FixStep() = %q, want %q", step.If.BaseNode.Value, tt.expected)
			}
		})
	}
}

func TestConditionalRule_FixJob(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "fix job with single wrapper",
			input:    "${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}",
			expected: "github.event.repository.owner.id  ==  github.event.sender.id",
			wantErr:  false,
		},
		{
			name:     "fix job with wrapper at end",
			input:    "github.ref == ${{ 'refs/heads/main' }}",
			expected: "github.ref ==  'refs/heads/main'",
			wantErr:  false,
		},
		{
			name:     "job without expression",
			input:    "success()",
			expected: "success()",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewConditionalRule()
			baseNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.input,
			}
			job := &ast.Job{
				If: &ast.String{
					BaseNode: baseNode,
					Value:    tt.input,
				},
			}

			err := rule.FixJob(job)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConditionalRule.FixJob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if job.If != nil && job.If.BaseNode.Value != tt.expected {
				t.Errorf("ConditionalRule.FixJob() = %q, want %q", job.If.BaseNode.Value, tt.expected)
			}
		})
	}
}

func TestConditionalRule_FixStep_NilIf(t *testing.T) {
	rule := NewConditionalRule()
	step := &ast.Step{
		If: nil,
	}

	err := rule.FixStep(step)
	if err != nil {
		t.Errorf("ConditionalRule.FixStep() with nil If should not error, got: %v", err)
	}
}

func TestConditionalRule_FixJob_NilIf(t *testing.T) {
	rule := NewConditionalRule()
	job := &ast.Job{
		If: nil,
	}

	err := rule.FixJob(job)
	if err != nil {
		t.Errorf("ConditionalRule.FixJob() with nil If should not error, got: %v", err)
	}
}
