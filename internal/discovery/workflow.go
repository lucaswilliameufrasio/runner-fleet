package discovery

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"strings"
)

type Job struct {
	ID       string   `json:"id"`
	Labels   []string `json:"labels"`
	Group    string   `json:"group"`
	Status   string   `json:"status"`
	Reason   string   `json:"reason"`
	Reusable string   `json:"reusable,omitempty"`
	Line     int      `json:"line"`
	EndLine  int      `json:"end_line"`
	Source   string   `json:"source"`
}

func Analyze(content string) ([]Job, error) {
	var doc yaml.Node
	if e := yaml.Unmarshal([]byte(content), &doc); e != nil {
		return nil, e
	}
	if len(doc.Content) == 0 {
		return []Job{}, nil
	}
	jobs := field(doc.Content[0], "jobs")
	a := []Job{}
	if jobs == nil {
		return a, nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		key, n := jobs.Content[i], jobs.Content[i+1]
		j := Job{ID: key.Value, Labels: []string{}, Status: "unresolved", Reason: "runs-on ausente"}
		if u := field(n, "uses"); u != nil {
			j.Reusable = u.Value
			j.Reason = "workflow reutilizável; verificar arquivo referenciado"
		}
		r := field(n, "runs-on")
		if r != nil {
			j.Line = r.Line
			j.EndLine = r.Line
			j.Source = sourceLines(content, r.Line)
			collect := func(v *yaml.Node) {
				if v == nil {
					return
				}
				if v.Kind == yaml.SequenceNode {
					for _, x := range v.Content {
						j.Labels = append(j.Labels, x.Value)
						j.EndLine = x.Line
					}
				} else if v.Kind == yaml.ScalarNode {
					j.Labels = append(j.Labels, v.Value)
				}
			}
			if r.Kind == yaml.MappingNode {
				if g := field(r, "group"); g != nil {
					j.Group = g.Value
				}
				collect(field(r, "labels"))
				j.EndLine = endLine(r)
			} else {
				collect(r)
			}
			j.Status = "migration"
			j.Reason = "destino precisa ser validado e migrado"
			for _, l := range j.Labels {
				if strings.EqualFold(l, "self-hosted") {
					j.Status = "self-hosted"
					j.Reason = "elegível se labels e acesso forem compatíveis"
				}
			}
			if j.Group != "" {
				j.Status = "group"
				j.Reason = "verificar grupo e acesso"
			}
			for idx, l := range j.Labels {
				if strings.Contains(l, "${{") {
					axis := matrixAxis(l)
					values := field(field(field(n, "strategy"), "matrix"), axis)
					if axis != "" && values != nil && values.Kind == yaml.SequenceNode {
						j.Status = "matrix"
						j.Reason = "matriz literal; destinos listados"
						j.Labels = append(j.Labels[:idx], j.Labels[idx+1:]...)
						for _, v := range values.Content {
							j.Labels = append(j.Labels, v.Value)
						}
					} else {
						j.Status = "unresolved"
						j.Reason = "expressão dinâmica não resolvida"
					}
					break
				}
			}
		}
		a = append(a, j)
	}
	return a, nil
}
func field(n *yaml.Node, k string) *yaml.Node {
	if n == nil {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == k {
			return n.Content[i+1]
		}
	}
	return nil
}
func endLine(n *yaml.Node) int {
	v := n.Line
	for _, c := range n.Content {
		if x := endLine(c); x > v {
			v = x
		}
	}
	return v
}
func sourceLines(s string, line int) string {
	a := strings.Split(s, "\n")
	if line < 1 || line > len(a) {
		return ""
	}
	return a[line-1]
}
func matrixAxis(s string) string {
	t := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "${{"), "}}"))
	if strings.HasPrefix(t, "matrix.") && !strings.ContainsAny(t, " ()[]") {
		return strings.TrimPrefix(t, "matrix.")
	}
	return ""
}

// Patch only a scalar static runs-on. Complex nodes are deliberately refused.
func Patch(content, jobID string, labels []string) (string, error) {
	if len(labels) == 0 {
		return "", fmt.Errorf("labels required")
	}
	jobs, e := Analyze(content)
	if e != nil {
		return "", e
	}
	for _, j := range jobs {
		if j.ID != jobID {
			continue
		}
		if j.Line == 0 || j.EndLine != j.Line || j.Status == "unresolved" || j.Status == "matrix" || j.Group != "" {
			return "", fmt.Errorf("complex destination: manual review required")
		}
		lines := strings.Split(content, "\n")
		old := lines[j.Line-1]
		indent := old[:len(old)-len(strings.TrimLeft(old, " \t"))]
		quoted := make([]string, len(labels))
		for i, l := range labels {
			quoted[i] = fmt.Sprintf("%q", l)
		}
		comment := ""
		if p := strings.Index(old, " #"); p >= 0 {
			comment = old[p:]
		}
		lines[j.Line-1] = indent + "runs-on: [" + strings.Join(quoted, ", ") + "]" + comment
		result := strings.Join(lines, "\n")
		if _, e := Analyze(result); e != nil {
			return "", fmt.Errorf("destination rewrite would invalidate YAML: %w", e)
		}
		return result, nil
	}
	return "", fmt.Errorf("job not found")
}
