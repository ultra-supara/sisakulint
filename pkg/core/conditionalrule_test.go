package core

import (
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
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
	tests := []struct {
		name      string
		condition string
		wantError bool
	}{
		// Valid conditions - should NOT produce error
		{
			name:      "single expression block",
			condition: "${{ github.event_name == 'push' }}",
			wantError: false,
		},
		{
			name:      "multiple expression blocks with comparison",
			condition: "${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}",
			wantError: false,
		},
		{
			name:      "expression block with external comparison and function",
			condition: "${{ steps.disk.outputs.status }} == 'success' && !canceled()",
			wantError: false,
		},
		{
			name:      "expression block with external comparison",
			condition: "${{ env.PACKAGED_STATUS }} == 'success' && !canceled()",
			wantError: false,
		},
		{
			name:      "parenthesized canceled function",
			condition: "(!canceled())",
			wantError: false,
		},
		{
			name:      "success function expression",
			condition: "${{ success() }}",
			wantError: false,
		},
		{
			name:      "always function expression",
			condition: "${{ always() }}",
			wantError: false,
		},
		{
			name:      "expression with != operator outside block",
			condition: "${{ steps.test.outputs.result }} != 'failure'",
			wantError: false,
		},
		{
			name:      "expression with || operator outside block",
			condition: "${{ steps.a.outputs.done }} || ${{ steps.b.outputs.done }}",
			wantError: false,
		},
		// Note: The following are edge cases - expressions like "${{ true }}" or "${{ false }}"
		// are intentionally NOT flagged as errors because they are valid expressions
		// The rule only flags malformed conditions that are clearly broken
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewConditionalRule()
			astString := &ast.String{
				Value: tt.condition,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}
			rule.checkcond(astString)
			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("checkcond() expected error for condition %q but got none", tt.condition)
				} else {
					t.Errorf("checkcond() unexpected error for condition %q: %v", tt.condition, rule.Errors())
				}
			}
		})
	}
}

func TestRemoveExpressionBlocks(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single block",
			input: "${{ github.event_name }}",
			want:  "",
		},
		{
			name:  "two blocks with operator",
			input: "${{ a }} == ${{ b }}",
			want:  " == ",
		},
		{
			name:  "block with trailing text",
			input: "${{ steps.foo.outputs.result }} == 'success'",
			want:  " == 'success'",
		},
		{
			name:  "no blocks",
			input: "success()",
			want:  "success()",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := removeExpressionBlocks(tt.input)
			if got != tt.want {
				t.Errorf("removeExpressionBlocks(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestContainsOperator(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "contains ==",
			input: " == 'success'",
			want:  true,
		},
		{
			name:  "contains !=",
			input: " != 'failure'",
			want:  true,
		},
		{
			name:  "contains &&",
			input: " && !canceled()",
			want:  true,
		},
		{
			name:  "contains ||",
			input: " || ",
			want:  true,
		},
		{
			name:  "contains !",
			input: "!canceled()",
			want:  true,
		},
		{
			name:  "contains >=",
			input: " >= 5",
			want:  true,
		},
		{
			name:  "no operators",
			input: "success()",
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsOperator(tt.input)
			if got != tt.want {
				t.Errorf("containsOperator(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
