package server

import (
	"encoding/json"
	"math"
	"runnerfleet/internal/capacity"
	"sort"
	"time"
)

func (s *Server) analytics() map[string]any {
	jobs, _ := s.Store.List("job")
	repos, _ := s.Store.List("repository")
	private := map[string]bool{}
	for _, b := range repos {
		var r map[string]any
		json.Unmarshal(b, &r)
		private[text(r["full_name"])], _ = r["private"].(bool)
	}
	stats := map[string]any{"jobs": len(jobs), "completed": 0, "successful": 0, "failed": 0, "hosted_minutes": 0.0, "self_hosted_minutes": 0.0, "estimated_hosted_cost": 0.0, "peak_concurrency": 0, "pricing_note": "configure custo por minuto; estimativa não é fatura"}
	var settings map[string]any
	json.Unmarshal([]byte(s.Store.Get("settings")), &settings)
	price, _ := settings["linux_price_per_minute"].(float64)
	type event struct {
		t     time.Time
		delta int
	}
	events := []event{}
	completed, success, failed := 0, 0, 0
	hosted, self, cost := 0.0, 0.0, 0.0
	instances, _ := capacity.List(s.Store)
	for _, b := range jobs {
		var j map[string]any
		json.Unmarshal(b, &j)
		start, e := time.Parse(time.RFC3339, text(j["started_at"]))
		if e != nil {
			continue
		}
		end, e := time.Parse(time.RFC3339, text(j["completed_at"]))
		if e != nil {
			if text(j["status"]) == "in_progress" {
				end = time.Now()
			} else {
				continue
			}
		}
		if !end.After(start) {
			continue
		}
		events = append(events, event{start, 1}, event{end, -1})
		if text(j["status"]) != "completed" {
			continue
		}
		completed++
		if text(j["conclusion"]) == "success" {
			success++
		} else {
			failed++
		}
		minutes := end.Sub(start).Minutes()
		isSelf := false
		if labels, ok := j["labels"].([]any); ok {
			for _, l := range labels {
				if text(l) == "self-hosted" {
					isSelf = true
				}
			}
		}
		if !isSelf && text(j["runner_name"]) != "" {
			for _, v := range instances {
				if v.Name == text(j["runner_name"]) {
					isSelf = true
					break
				}
			}
		}
		if isSelf {
			self += minutes
		} else {
			hosted += minutes
			if private[text(j["repository"])] {
				cost += math.Ceil(minutes) * price
			}
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].t.Equal(events[j].t) {
			return events[i].delta < events[j].delta
		}
		return events[i].t.Before(events[j].t)
	})
	current, peak := 0, 0
	for _, e := range events {
		current += e.delta
		if current > peak {
			peak = current
		}
	}
	stats["completed"] = completed
	stats["successful"] = success
	stats["failed"] = failed
	stats["hosted_minutes"] = math.Round(hosted*10) / 10
	stats["self_hosted_minutes"] = math.Round(self*10) / 10
	stats["estimated_hosted_cost"] = math.Round(cost*100) / 100
	stats["peak_concurrency"] = peak
	stats["linux_price_per_minute"] = price
	stats["price_reference"] = settings["price_reference"]
	return stats
}
