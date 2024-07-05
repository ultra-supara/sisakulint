package core

import (
	"fmt"
	"strings"

	"github.com/ultra-supara/sisakulint/pkg/ast"
)

type nodeStatus int

const (
	// nodeStatusNewは、ノードが新しいことを示します。
	nodeStatusNew nodeStatus = iota
	// nodeStatusActiveは、ノードがアクティブであることを示します。
	nodeStatusActive
	// nodeStatusInactiveは、ノードがノンアクティブであることを示します。
	nodeStatusInactive
)

type jobNode struct {
	id       string
	needs    []string
	resolved []*jobNode
	status   nodeStatus
	pos      *ast.Position
}

type edge struct {
	from *jobNode
	to   *jobNode
}

// JobNeeds is a rule to check needs field in each job configuration.
// * https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idneeds
type JobNeeds struct {
	BaseRule
	nodes map[string]*jobNode
}

// JobNeedsRule creates a new JobNeedsRule.
func JobNeedsRule() *JobNeeds {
	return &JobNeeds{
		BaseRule: BaseRule{
			RuleName: "needs",
			RuleDesc: "Job needs is not defined correctly.",
		},
		nodes: map[string]*jobNode{},
	}
}

func contains(heystack []string, needle string) bool {
	for _, h := range heystack {
		if h == needle {
			return true
		}
	}
	return false
}

// VisitJobPre is a callback function to be called when visiting each job node before visiting its children.
func (rule *JobNeeds) VisitJobPre(node *ast.Job) error {
	needs := make([]string, 0, len(node.Needs))
	for _, j := range node.Needs {
		id := strings.ToLower(j.Value)
		if contains(needs, id) {
			rule.Errorf(j.Pos, "job ID %q duplicates in needs section", j.Value)
			continue
		}
		if id != "" {
			needs = append(needs, id)
		}
	}

	id := strings.ToLower(node.ID.Value)
	if id == "" {
		return nil
	}
	if prev, ok := rule.nodes[id]; ok {
		rule.Errorf(node.Pos, "job ID %q is already defined at %s", node.ID.Value, prev.pos.String())
	}
	rule.nodes[id] = &jobNode{
		id:     id,
		needs:  needs,
		status: nodeStatusNew,
		pos:    node.ID.Pos,
	}
	return nil
}

// VisitWorkflowPost is a callback function to be called when visiting each workflow node after visiting its children.
func (rule *JobNeeds) VisitWorkflowPost(node *ast.Workflow) error {
	// resolve needs
	valid := true
	for id, node := range rule.nodes {
		node.resolved = make([]*jobNode, 0, len(node.needs))
		for _, dep := range node.needs {
			n, ok := rule.nodes[dep]
			if !ok {
				rule.Errorf(node.pos, "job ID %q needs job %q is not defined", id, dep)
				valid = false
				continue
			}
			node.resolved = append(node.resolved, n)
		}
	}
	if !valid {
		return nil
	}

	if edge := CheckCyclicDependency(rule.nodes); edge != nil {
		edges := map[string]string{edge.from.id: edge.to.id}
		collectCyclicFunc(edge.to, edges)

		description := make([]string, 0, len(edges))
		for from, to := range edges {
			description = append(description, fmt.Sprintf("%q -> %q", from, to))
		}
		rule.Errorf(edge.from.pos, "cyclic dependency in needs section found: %s is detected cycle", strings.Join(description, ", "))
	}
	return nil
}

func collectCyclicFunc(src *jobNode, edges map[string]string) bool {
	for _, dest := range src.resolved {
		if dest.status != nodeStatusActive {
			continue
		}
		edges[src.id] = dest.id
		if _, ok := edges[dest.id]; ok {
			return true
		}
		if collectCyclicFunc(dest, edges) {
			return true
		}
		delete(edges, src.id)
	}
	return false
}

// Check cyclic dependency poewred by 有向非巡回グラフ (directed acyclic graph, DAG)
func CheckCyclicDependency(nodes map[string]*jobNode) *edge {
	for _, v := range nodes {
		if v.status == nodeStatusNew {
			if e := CheckCyclicNode(v); e != nil {
				return e
			}
		}
	}
	return nil
}

// Check CyclicNode
func CheckCyclicNode(v *jobNode) *edge {
	v.status = nodeStatusActive
	for _, w := range v.resolved {
		switch w.status {
		case nodeStatusActive:
			return &edge{v, w}
		case nodeStatusNew:
			if e := CheckCyclicNode(w); e != nil {
				return e
			}
		}
	}
	v.status = nodeStatusInactive
	return nil
}
