package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/discovery"
	"runnerfleet/internal/security"
	"strings"
	"time"
)

func number(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	}
	return 0
}
func text(v any) string           { x, _ := v.(string); return x }
func object(v any) map[string]any { x, _ := v.(map[string]any); return x }
func (s *Server) refreshInstallations(ctx context.Context) error {
	c, e := s.gh()
	if e != nil {
		return e
	}
	a, e := c.Installations(ctx)
	if e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, v := range a {
		id := fmt.Sprint(number(v["id"]))
		account := object(v["account"])
		v["owner"] = account["login"]
		v["scope_type"] = account["type"]
		v["active"] = true
		s.Store.Put("installation", id, v)
		seen[id] = true
	}
	old, _ := s.Store.List("installation")
	for _, b := range old {
		var v map[string]any
		json.Unmarshal(b, &v)
		id := fmt.Sprint(number(v["id"]))
		if !seen[id] {
			v["active"] = false
			s.Store.Put("installation", id, v)
		}
	}
	return nil
}
func (s *Server) scanInstallation(ctx context.Context, id int64) error {
	c, e := s.gh()
	if e != nil {
		return e
	}
	scanID := fmt.Sprint(id)
	pageStart := 1
	var previous map[string]any
	if s.Store.Read("scan", scanID, &previous) == nil && text(previous["state"]) == "running" {
		if n := number(previous["next_page"]); n > 1 {
			pageStart = int(n)
		}
	}
	report := map[string]any{"id": scanID, "installation": id, "state": "running", "started": time.Now().Unix(), "errors": []string{}, "repositories": 0, "jobs": 0}
	s.Store.Put("scan", scanID, report)
	errs := []string{}
	count, jobs := 0, 0
	defer func() {
		report["state"] = "completed"
		if len(errs) > 0 {
			report["state"] = "partial"
		}
		report["errors"] = errs
		report["repositories"] = count
		report["jobs"] = jobs
		report["finished"] = time.Now().Unix()
		s.Store.Put("scan", scanID, report)
	}()
	for page := pageStart; ; page++ {
		var v struct {
			Repositories []map[string]any `json:"repositories"`
		}
		if e = c.Do(ctx, id, "GET", fmt.Sprintf("/installation/repositories?per_page=100&page=%d", page), nil, &v); e != nil {
			errs = append(errs, e.Error())
			return e
		}
		for _, repo := range v.Repositories {
			if e = ctx.Err(); e != nil {
				return e
			}
			count++
			name := text(repo["full_name"])
			repo["installation"] = id
			repo["observed_at"] = time.Now().Unix()
			s.Store.Put("repository", fmt.Sprint(number(repo["id"])), repo)
			var files []map[string]any
			path := "/repos/" + name + "/contents/.github/workflows?ref=" + url.QueryEscape(text(repo["default_branch"]))
			if e = c.Do(ctx, id, "GET", path, nil, &files); e != nil {
				errs = append(errs, name+": workflows unavailable (may be absent): "+e.Error())
			} else {
				for _, f := range files {
					filename := text(f["path"])
					if !strings.HasSuffix(filename, ".yml") && !strings.HasSuffix(filename, ".yaml") {
						continue
					}
					if e = s.scanFile(ctx, id, name, filename, text(repo["default_branch"]), 0, map[string]bool{}); e != nil {
						errs = append(errs, e.Error())
					}
				}
			}
			rr, e := s.collectPages(ctx, id, "/repos/"+name+"/actions/runners", "runners")
			if e != nil {
				errs = append(errs, name+": runner inventory unavailable: "+e.Error())
			} else {
				s.Store.Put("runner", "repo:"+name, map[string]any{"id": "repo:" + name, "scope": "repo", "target": name, "data": rr, "observed_at": time.Now().Unix()})
			}
			days := 30
			var settings map[string]any
			json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
			if n := number(settings["scan_days"]); n > 0 {
				days = int(n)
			}
			cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Format("2006-01-02")
			for p := 1; ; p++ {
				var runs struct {
					Runs []map[string]any `json:"workflow_runs"`
				}
				if e = c.Do(ctx, id, "GET", fmt.Sprintf("/repos/%s/actions/runs?per_page=100&page=%d&created=%s", name, p, url.QueryEscape(">="+cut)), nil, &runs); e != nil {
					errs = append(errs, e.Error())
					break
				}
				for _, run := range runs.Runs {
					runID := number(run["id"])
					attempt := number(run["run_attempt"])
					if attempt < 1 {
						attempt = 1
					}
					for currentAttempt := int64(1); currentAttempt <= attempt; currentAttempt++ {
						for jp := 1; ; jp++ {
							var jv struct {
								Jobs []map[string]any `json:"jobs"`
							}
							jobPath := fmt.Sprintf("/repos/%s/actions/runs/%d/attempts/%d/jobs?per_page=100&page=%d", name, runID, currentAttempt, jp)
							if e = c.Do(ctx, id, "GET", jobPath, nil, &jv); e != nil {
								errs = append(errs, e.Error())
								break
							}
							for _, j := range jv.Jobs {
								j["repository"] = name
								j["installation"] = id
								j["run_attempt"] = currentAttempt
								s.putJob(j)
								jobs++
							}
							if len(jv.Jobs) < 100 {
								break
							}
						}
					}
				}
				if len(runs.Runs) < 100 {
					break
				}
			}
		}
		report["next_page"] = page + 1
		report["repositories"] = count
		report["jobs"] = jobs
		s.Store.Put("scan", scanID, report)
		if len(v.Repositories) < 100 {
			break
		}
	}
	var inst map[string]any
	s.Store.Read("installation", scanID, &inst)
	if text(inst["scope_type"]) == "Organization" {
		owner := text(inst["owner"])
		for _, kind := range []string{"runners", "runner-groups"} {
			path := "/orgs/" + owner + "/actions/" + kind
			key := kind
			if kind == "runner-groups" {
				key = "runner_groups"
			}
			v, e := s.collectPages(ctx, id, path, key)
			if e != nil {
				errs = append(errs, e.Error())
				continue
			}
			k := "runner"
			if kind == "runner-groups" {
				k = "group"
				if groups, ok := v["runner_groups"].([]any); ok {
					for _, g := range groups {
						group := object(g)
						selected, e := s.collectPages(ctx, id, fmt.Sprintf("/orgs/%s/actions/runner-groups/%d/repositories", owner, number(group["id"])), "repositories")
						if e != nil {
							errs = append(errs, e.Error())
						} else {
							group["selected_repositories"] = selected["repositories"]
						}
					}
				}
			}
			s.Store.Put(k, "org:"+owner, map[string]any{"id": "org:" + owner, "scope": "org", "target": owner, "data": v, "observed_at": time.Now().Unix()})
		}
	}
	return nil
}
func (s *Server) scanFile(ctx context.Context, installation int64, repo, path, ref string, depth int, seen map[string]bool) error {
	key := repo + "/" + path + "@" + ref
	if seen[key] || depth > 5 {
		return fmt.Errorf("reusable workflow cycle/depth: %s", key)
	}
	seen[key] = true
	defer delete(seen, key)
	c, e := s.gh()
	if e != nil {
		return e
	}
	var file struct{ SHA, Content, Encoding string }
	if e = c.Do(ctx, installation, "GET", "/repos/"+repo+"/contents/"+path+"?ref="+url.QueryEscape(ref), nil, &file); e != nil {
		return e
	}
	b, e := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	if e != nil {
		return e
	}
	jobs, e := discovery.Analyze(string(b))
	if e != nil {
		return fmt.Errorf("%s: %w", key, e)
	}
	snapshot := map[string]any{"id": key, "repository": repo, "path": path, "ref": ref, "sha": file.SHA, "content": string(b), "jobs": jobs, "installation": installation, "observed_at": time.Now().Unix(), "depth": depth}
	s.Store.Put("workflow", key, snapshot)
	for _, j := range jobs {
		if j.Reusable == "" {
			continue
		}
		target := j.Reusable
		otherRepo, otherPath, otherRef := repo, "", ref
		if strings.HasPrefix(target, "./") {
			otherPath = strings.TrimPrefix(target, "./")
		} else {
			parts := strings.SplitN(target, "@", 2)
			a := strings.SplitN(parts[0], "/", 3)
			if len(parts) != 2 || len(a) != 3 {
				continue
			}
			otherRepo = a[0] + "/" + a[1]
			otherPath = a[2]
			otherRef = parts[1]
		}
		if e = s.scanFile(ctx, installation, otherRepo, otherPath, otherRef, depth+1, seen); e != nil {
			return e
		}
	}
	return nil
}
func (s *Server) putJob(j map[string]any) {
	id := fmt.Sprint(number(j["id"]))
	j["observed_at"] = time.Now().Unix()
	var old map[string]any
	if s.Store.Read("job", id, &old) == nil {
		rank := map[string]int{"queued": 1, "waiting": 1, "in_progress": 2, "completed": 3}
		if rank[text(j["status"])] < rank[text(old["status"])] {
			return
		}
	}
	labels := []string{}
	if a, ok := j["labels"].([]any); ok {
		for _, v := range a {
			labels = append(labels, text(v))
		}
	}
	pools := s.pools()
	if text(j["status"]) == "queued" {
		j["queue_reason"] = capacity.QueueReason(pools, labels, text(j["repository"]))
	}
	s.Store.Put("job", id, j)
}
func (s *Server) processWebhook(ctx context.Context, kind string, b string) error {
	var v map[string]any
	if e := json.Unmarshal([]byte(b), &v); e != nil {
		return e
	}
	if kind == "webhook:workflow_job" {
		j := object(v["workflow_job"])
		if j == nil {
			return fmt.Errorf("missing workflow_job")
		}
		j["repository"] = object(v["repository"])["full_name"]
		j["installation"] = object(v["installation"])["id"]
		s.putJob(j)
	} else if kind == "webhook:installation" || kind == "webhook:installation_repositories" {
		return s.refreshInstallations(ctx)
	}
	return nil
}
func (s *Server) pools() []capacity.Pool {
	a, _ := s.Store.List("pool")
	p := []capacity.Pool{}
	for _, b := range a {
		var v capacity.Pool
		if json.Unmarshal(b, &v) == nil {
			p = append(p, v)
		}
	}
	return p
}
func (s *Server) migration(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct {
		Workflow string   `json:"workflow"`
		Job      string   `json:"job"`
		Labels   []string `json:"labels"`
		SHA      string   `json:"sha"`
		CreatePR bool     `json:"create_pr"`
	}
	if !decode(w, r, &v) {
		return
	}
	var snap map[string]any
	if s.Store.Read("workflow", v.Workflow, &snap) != nil {
		fail(w, 404, "snapshot not found")
		return
	}
	if v.SHA != text(snap["sha"]) {
		fail(w, 409, "snapshot SHA changed")
		return
	}
	if len(v.Labels) == 0 || !capacity.Match(v.Labels, []string{"self-hosted"}) {
		fail(w, 400, "explicit self-hosted label required")
		return
	}
	patched, e := discovery.Patch(text(snap["content"]), v.Job, v.Labels)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if !v.CreatePR {
		write(w, 200, map[string]any{"before": snap["content"], "after": patched, "sha": v.SHA})
		return
	}
	installation := number(snap["installation"])
	repo, path, ref := text(snap["repository"]), text(snap["path"]), text(snap["ref"])
	c, e := s.gh()
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	var file map[string]any
	if e = c.Do(r.Context(), installation, "GET", "/repos/"+repo+"/contents/"+path+"?ref="+url.QueryEscape(ref), nil, &file); e != nil {
		fail(w, 502, e.Error())
		return
	}
	if text(file["sha"]) != v.SHA {
		fail(w, 409, "GitHub file changed; scan and review again")
		return
	}
	var commit map[string]any
	if e = c.Do(r.Context(), installation, "GET", "/repos/"+repo+"/git/ref/heads/"+url.PathEscape(ref), nil, &commit); e != nil {
		fail(w, 502, e.Error())
		return
	}
	branch := "runner-fleet/" + security.Random(8)
	if e = c.Do(r.Context(), installation, "POST", "/repos/"+repo+"/git/refs", map[string]any{"ref": "refs/heads/" + branch, "sha": object(commit["object"])["sha"]}, nil); e != nil {
		fail(w, 502, e.Error())
		return
	}
	if e = c.Do(r.Context(), installation, "PUT", "/repos/"+repo+"/contents/"+path, map[string]any{"message": "ci: route approved job to self-hosted runners", "content": base64.StdEncoding.EncodeToString([]byte(patched)), "sha": v.SHA, "branch": branch}, nil); e != nil {
		fail(w, 502, e.Error()+"; branch retained: "+branch)
		return
	}
	var pr map[string]any
	e = c.Do(r.Context(), installation, "POST", "/repos/"+repo+"/pulls", map[string]any{"title": "ci: migrate " + v.Job + " to self-hosted runners", "head": branch, "base": ref, "body": "Changes only the reviewed runs-on destination. Validate a canary run before merging. Revert this commit to restore the prior destination."}, &pr)
	if e != nil {
		fail(w, 502, e.Error()+"; branch retained: "+branch)
		return
	}
	s.Store.Audit("admin", "migration.pr", repo, "created "+text(pr["html_url"]))
	write(w, 201, map[string]any{"url": pr["html_url"]})
}
func (s *Server) jobLogs(w http.ResponseWriter, r *http.Request) {
	var j map[string]any
	if s.Store.Read("job", r.PathValue("id"), &j) != nil {
		fail(w, 404, "job not found")
		return
	}
	c, e := s.gh()
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	token, e := c.Token(r.Context(), number(j["installation"]))
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return fmt.Errorf("too many redirects")
		}
		r.Header.Del("Authorization")
		if r.URL.Scheme != "https" {
			return fmt.Errorf("HTTPS required")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://api.github.com/repos/"+text(j["repository"])+"/actions/jobs/"+r.PathValue("id")+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, e := client.Do(req)
	if e != nil {
		fail(w, 502, "logs unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fail(w, 502, "GitHub logs unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	ioCopyLimited(w, resp.Body)
}

func ioCopyLimited(w http.ResponseWriter, r io.Reader) { io.Copy(w, io.LimitReader(r, 8<<20)) }

func (s *Server) collectPages(ctx context.Context, id int64, path, key string) (map[string]any, error) {
	c, e := s.gh()
	if e != nil {
		return nil, e
	}
	all := []any{}
	for page := 1; ; page++ {
		var v map[string]any
		if e = c.Do(ctx, id, "GET", fmt.Sprintf("%s?per_page=100&page=%d", path, page), nil, &v); e != nil {
			return nil, e
		}
		items, _ := v[key].([]any)
		all = append(all, items...)
		if len(items) < 100 {
			break
		}
	}
	return map[string]any{key: all, "total_count": len(all)}, nil
}
func (s *Server) pollJobs(ctx context.Context) {
	last, _ := strconvInt(s.Store.Get("jobs_poll"))
	if time.Now().Unix()-last < 60 {
		return
	}
	s.Store.Set("jobs_poll", fmt.Sprint(time.Now().Unix()))
	c, e := s.gh()
	if e != nil {
		return
	}
	jobs, _ := s.Store.List("job")
	count := 0
	for _, b := range jobs {
		var j map[string]any
		json.Unmarshal(b, &j)
		if text(j["status"]) == "completed" {
			continue
		}
		if count >= 20 {
			break
		}
		count++
		var observed map[string]any
		if e = c.Do(ctx, number(j["installation"]), "GET", fmt.Sprintf("/repos/%s/actions/jobs/%d", text(j["repository"]), number(j["id"])), nil, &observed); e != nil {
			continue
		}
		observed["repository"] = j["repository"]
		observed["installation"] = j["installation"]
		s.putJob(observed)
	}
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	if !s.elevated(w, r) {
		return
	}
	var v struct {
		Installation int64   `json:"installation"`
		Organization string  `json:"organization"`
		Name         string  `json:"name"`
		Repositories []int64 `json:"repositories"`
	}
	if !decode(w, r, &v) {
		return
	}
	if v.Name == "" || len(v.Repositories) == 0 || len(v.Repositories) > 100 {
		fail(w, 400, "name and 1–100 selected repositories required")
		return
	}
	var installation map[string]any
	if s.Store.Read("installation", fmt.Sprint(v.Installation), &installation) != nil || text(installation["owner"]) != v.Organization || text(installation["scope_type"]) != "Organization" {
		fail(w, 400, "organization installation mismatch")
		return
	}
	for _, id := range v.Repositories {
		var repo map[string]any
		if s.Store.Read("repository", fmt.Sprint(id), &repo) != nil || number(repo["installation"]) != v.Installation || !strings.HasPrefix(text(repo["full_name"]), v.Organization+"/") {
			fail(w, 400, "repository outside selected installation")
			return
		}
	}
	c, e := s.gh()
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	var group map[string]any
	e = c.Do(r.Context(), v.Installation, "POST", "/orgs/"+v.Organization+"/actions/runner-groups", map[string]any{"name": v.Name, "visibility": "selected", "selected_repository_ids": v.Repositories, "allows_public_repositories": false}, &group)
	if e != nil {
		fail(w, 502, e.Error())
		return
	}
	s.Store.Audit("admin", "github.group.create", v.Organization, "selected repositories only")
	s.Store.Task(security.Random(12), "scan", map[string]any{"installation": v.Installation})
	write(w, 201, group)
}
