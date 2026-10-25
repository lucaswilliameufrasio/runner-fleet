package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runnerfleet/internal/backups"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/security"
	"runnerfleet/internal/store"
	"sort"
	"strings"
	"time"
)

func (s *Server) Start(ctx context.Context) {
	s.ctx = ctx
	s.Store.RecoverTasks()
	go s.worker(ctx)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reconcile(ctx)
				s.schedule(ctx)
				s.maintenance(ctx)
			}
		}
	}()
}
func (s *Server) worker(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var id, kind, data string
		var attempts int
		e := s.Store.DB.QueryRow(`SELECT id,kind,data,attempts FROM tasks WHERE state='pending' AND next<=? ORDER BY next LIMIT 1`, time.Now().Unix()).Scan(&id, &kind, &data, &attempts)
		if e != nil {
			continue
		}
		s.Store.DB.Exec(`UPDATE tasks SET state='running',attempts=attempts+1 WHERE id=?`, id)
		taskCtx, cancel := context.WithTimeout(ctx, 20*time.Minute)
		switch {
		case kind == "refresh":
			e = s.refreshInstallations(taskCtx)
		case kind == "scan":
			var v struct{ Installation int64 }
			json.Unmarshal([]byte(data), &v)
			e = s.scanInstallation(taskCtx, v.Installation)
		case kind == "backup":
			e = s.runBackup(taskCtx, id)
		case kind == "alert":
			e = s.deliverAlert(taskCtx, data)
		case strings.HasPrefix(kind, "webhook:"):
			e = s.processWebhook(taskCtx, kind, data)
		default:
			e = fmt.Errorf("unknown task")
		}
		cancel()
		state, msg, next := "completed", "", time.Now().Unix()
		if e != nil {
			msg = e.Error()
			state = "pending"
			next = time.Now().Add(time.Duration(1<<min(attempts, 8)) * time.Minute).Unix()
			if attempts >= 4 {
				state = "failed"
				s.alert("task:"+id, "Falha operacional", msg)
			}
		}
		s.Store.DB.Exec(`UPDATE tasks SET state=?,error=?,next=? WHERE id=?`, state, msg, next, id)
	}
}
func (s *Server) runBackup(ctx context.Context, id string) error {
	var c backups.Config
	if e := s.secretGet("backup_config", &c); e != nil {
		return e
	}
	path, e := backups.Run(ctx, s.Store, s.Cfg.DataDir, c)
	v := map[string]any{"id": id, "created": time.Now().Unix(), "location": path, "status": "completed"}
	if e != nil {
		v["status"] = "failed"
		v["error"] = e.Error()
	} else {
		s.Store.Set("last_backup", fmt.Sprint(time.Now().Unix()))
	}
	s.Store.Put("backup", id, v)
	s.Store.Audit("scheduler", "backup.run", id, text(v["status"]))
	return e
}
func (s *Server) alert(id, title, msg string) {
	var old map[string]any
	if s.Store.Read("alert", id, &old) == nil && time.Now().Unix()-number(old["created"]) < 900 {
		return
	}
	v := map[string]any{"id": id, "title": title, "message": msg, "created": time.Now().Unix(), "acknowledged": false}
	s.Store.Put("alert", id, v)
	s.Store.Task(security.Random(12), "alert", v)
}
func (s *Server) deliverAlert(ctx context.Context, data string) error {
	var settings map[string]any
	json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
	target := text(settings["alert_webhook"])
	if target == "" {
		return nil
	}
	var v map[string]any
	json.Unmarshal([]byte(data), &v)
	payload := store.JSON(v)
	if strings.Contains(target, "discord.com/api/webhooks/") {
		payload = store.JSON(map[string]any{"content": fmt.Sprint(v["title"]) + "\n" + fmt.Sprint(v["message"]), "allowed_mentions": map[string]any{"parse": []any{}}})
	}
	req, e := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("webhook HTTP %d", res.StatusCode)
	}
	return nil
}
func (s *Server) schedule(ctx context.Context) {
	pools := s.pools()
	instances, _ := capacity.List(s.Store)
	jobs, _ := s.Store.List("job")
	counts := map[string]int{}
	orgCounts := map[string]int{}
	for _, v := range instances {
		if capacity.Active(v.State) {
			counts[v.Pool]++
			for _, p := range pools {
				if p.ID == v.Pool {
					org := strings.Split(p.Target, "/")[0]
					orgCounts[org]++
					break
				}
			}
		}
	}
	sort.SliceStable(pools, func(i, j int) bool {
		return float64(counts[pools[i].ID])/float64(max(pools[i].Weight, 1)) < float64(counts[pools[j].ID])/float64(max(pools[j].Weight, 1))
	})
	orgMax := 8
	var settings map[string]any
	json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
	if n := number(settings["org_max_slots"]); n > 0 {
		orgMax = int(n)
	}
	for _, p := range pools {
		if !p.Enabled {
			continue
		}
		target := p.Min
		queued := 0
		for _, b := range jobs {
			var j map[string]any
			json.Unmarshal(b, &j)
			repo := text(j["repository"])
			if text(j["status"]) != "queued" || number(j["installation"]) != p.Installation {
				continue
			}
			if p.Target != repo && !(p.Scope == "org" && strings.HasPrefix(repo, p.Target+"/")) {
				continue
			}
			labels := []string{}
			if a, ok := j["labels"].([]any); ok {
				for _, l := range a {
					labels = append(labels, text(l))
				}
			}
			if capacity.Match(p.Labels, labels) {
				queued++
			}
		}
		busyCount := 0
		for _, instance := range instances {
			if instance.Pool == p.ID && instance.State == "busy" {
				busyCount++
			}
		}
		target = min(p.Max, max(target, busyCount+queued))
		org := strings.Split(p.Target, "/")[0]
		if counts[p.ID] >= target || orgCounts[org] >= orgMax {
			continue
		}
		for _, m := range eligibleMachines(s.Store, p) {
			v, e := capacity.Reserve(s.Store, p, m, time.Now())
			if e != nil {
				continue
			}
			counts[p.ID]++
			orgCounts[org]++
			c, e := s.gh()
			if e != nil {
				capacity.Update(s.Store, v.ID, "failed", e.Error())
				continue
			}
			scope, _ := githubScope(p)
			var token struct {
				Token string `json:"token"`
			}
			if e = c.Do(ctx, p.Installation, "POST", scope+"/registration-token", nil, &token); e != nil {
				capacity.Update(s.Store, v.ID, "failed", e.Error())
				s.alert("provision:"+p.ID, "Falha ao registrar runner", e.Error())
				continue
			}
			spec := capacity.Spec{Instance: v, Pool: p, URL: "https://github.com/" + p.Target, Token: token.Token}
			enc, e := security.Seal(s.Key, []byte(store.JSON(spec)))
			if e != nil {
				capacity.Update(s.Store, v.ID, "failed", e.Error())
				continue
			}
			_, e = capacity.Command(s.Store, m.ID, "start", map[string]any{"encrypted": enc, "instance": v.ID})
			if e != nil {
				capacity.Update(s.Store, v.ID, "failed", e.Error())
				continue
			}
			capacity.Update(s.Store, v.ID, "provisioning", "")
			break
		}
	}
	s.reconcileSpot(ctx)
}
func githubScope(p capacity.Pool) (string, error) {
	if p.Scope == "org" {
		return "/orgs/" + p.Target + "/actions/runners", nil
	}
	return "/repos/" + p.Target + "/actions/runners", nil
}
func (s *Server) reconcile(ctx context.Context) {
	s.processDrains(ctx)
	s.pollJobs(ctx)
	machines, _ := s.Store.List("machine")
	for _, b := range machines {
		var m capacity.Machine
		json.Unmarshal(b, &m)
		if m.State == "revoked" || m.State == "terminated" || m.State == "terminating" {
			continue
		}
		if time.Now().Unix()-m.LastSeen > 60 && m.State != "draining" && m.State != "enrolling" {
			if m.State != "offline" {
				s.alert("offline:"+m.ID, "Máquina desconectada", m.Name)
			}
			active, _ := capacity.List(s.Store)
			for _, v := range active {
				if v.Machine == m.ID && v.State == "idle" {
					capacity.Command(s.Store, m.ID, "drain", map[string]any{"instance": v.ID})
				}
			}
			m.State = "offline"
			s.Store.Put("machine", m.ID, m)
		}
	}
	a, _ := capacity.List(s.Store)
	for _, v := range a {
		if v.State != "cleaned" {
			continue
		}
		var p capacity.Pool
		if s.Store.Read("pool", v.Pool, &p) != nil {
			continue
		}
		c, e := s.gh()
		if e != nil {
			continue
		}
		scope, _ := githubScope(p)
		var runners struct {
			Runners []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
				Busy bool   `json:"busy"`
			} `json:"runners"`
		}
		found := false
		failed := false
		for page := 1; ; page++ {
			if e = c.Do(ctx, p.Installation, "GET", fmt.Sprintf("%s?per_page=100&page=%d", scope, page), nil, &runners); e != nil {
				failed = true
				break
			}
			for _, r := range runners.Runners {
				if r.Name == v.Name {
					found = true
					if r.Busy {
						failed = true
						break
					}
					if e = c.Do(ctx, p.Installation, "DELETE", fmt.Sprintf("%s/%d", scope, r.ID), nil, nil); e != nil {
						failed = true
					}
				}
			}
			if failed || len(runners.Runners) < 100 {
				break
			}
		}
		_ = found
		if !failed {
			capacity.Update(s.Store, v.ID, "removed", "")
		}
	}
}
func (s *Server) maintenance(ctx context.Context) {
	now := time.Now()
	last, _ := strconvInt(s.Store.Get("maintenance"))
	if now.Unix()-last < 60 {
		return
	}
	s.Store.Set("maintenance", fmt.Sprint(now.Unix()))
	var c backups.Config
	if s.secretGet("backup_config", &c) == nil && c.Enabled {
		last, _ := strconvInt(s.Store.Get("last_backup"))
		if now.Unix()-last > int64(max(c.IntervalHours, 1))*3600 {
			s.Store.Task("backup:"+now.UTC().Format("20060102T15"), "backup", nil)
		}
	}
	var settings map[string]any
	json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
	hours := int64(6)
	if n := number(settings["scan_hours"]); n > 0 {
		hours = n
	}
	inst, _ := s.Store.List("installation")
	for _, b := range inst {
		var i map[string]any
		json.Unmarshal(b, &i)
		if active, ok := i["active"].(bool); ok && !active {
			continue
		}
		id := number(i["id"])
		var scan map[string]any
		s.Store.Read("scan", fmt.Sprint(id), &scan)
		if now.Unix()-number(scan["finished"]) > hours*3600 {
			s.Store.Task(fmt.Sprintf("scan:%d:%d", id, now.Unix()/(hours*3600)), "scan", map[string]any{"installation": id})
		}
	}
	days := func(k string, d int) int64 {
		n := number(settings[k])
		if n < 1 {
			n = int64(d)
		}
		return n
	}
	s.Store.DB.Exec(`DELETE FROM sessions WHERE expires<?`, now.Unix())
	s.Store.DB.Exec(`DELETE FROM enrollment WHERE expires<?`, now.Add(-24*time.Hour).Unix())
	s.Store.DB.Exec(`DELETE FROM deliveries WHERE created<?`, now.Add(-30*24*time.Hour).Unix())
	s.Store.DB.Exec(`DELETE FROM audit WHERE created<?`, now.Unix()-days("audit_days", 180)*86400)
	s.Store.DB.Exec(`DELETE FROM resources WHERE kind='job' AND json_extract(data,'$.status')='completed' AND updated<?`, now.Unix()-days("history_days", 90)*86400)
	s.Store.DB.Exec(`DELETE FROM tasks WHERE state='completed' AND next<?`, now.Add(-7*24*time.Hour).Unix())
	s.Store.DB.Exec(`DELETE FROM resources WHERE kind='agentlog' AND updated<?`, now.Unix()-days("log_days", 14)*86400)
}
func strconvInt(s string) (int64, error) { var n int64; _, e := fmt.Sscan(s, &n); return n, e }

func (s *Server) processDrains(ctx context.Context) {
	rows, e := s.Store.DB.Query(`SELECT id,data FROM commands WHERE kind='drain' AND state='pending'`)
	if e != nil {
		return
	}
	type request struct{ ID, Instance string }
	requests := []request{}
	for rows.Next() {
		var id, b string
		rows.Scan(&id, &b)
		var data struct {
			Instance string `json:"instance"`
		}
		json.Unmarshal([]byte(b), &data)
		requests = append(requests, request{id, data.Instance})
	}
	rows.Close()
	for _, request := range requests {
		v, e := capacity.Get(s.Store, request.Instance)
		if e != nil {
			continue
		}
		if v.State == "removed" || v.State == "failed" {
			s.Store.DB.Exec(`UPDATE commands SET state='done' WHERE id=?`, request.ID)
			continue
		}
		if v.State == "reserved" || v.State == "provisioning" {
			continue
		}
		var p capacity.Pool
		if s.Store.Read("pool", v.Pool, &p) != nil {
			continue
		}
		c, e := s.gh()
		if e != nil {
			continue
		}
		scope, _ := githubScope(p)
		found := false
		blocked := false
		for page := 1; ; page++ {
			var list struct {
				Runners []struct {
					ID   int64  `json:"id"`
					Name string `json:"name"`
					Busy bool   `json:"busy"`
				} `json:"runners"`
			}
			if e = c.Do(ctx, p.Installation, "GET", fmt.Sprintf("%s?per_page=100&page=%d", scope, page), nil, &list); e != nil {
				blocked = true
				break
			}
			for _, r := range list.Runners {
				if r.Name != v.Name {
					continue
				}
				found = true
				if r.Busy {
					blocked = true
					break
				}
				if e = c.Do(ctx, p.Installation, "DELETE", fmt.Sprintf("%s/%d", scope, r.ID), nil, nil); e != nil {
					blocked = true
				}
			}
			if blocked || found || len(list.Runners) < 100 {
				break
			}
		}
		if blocked {
			continue
		}
		capacity.Command(s.Store, v.Machine, "detach", map[string]any{"instance": v.ID})
		s.Store.DB.Exec(`UPDATE commands SET state='done',result='runner detached from GitHub' WHERE id=?`, request.ID)
		s.Store.Audit("scheduler", "runner.detach", v.ID, "success")
	}
}
