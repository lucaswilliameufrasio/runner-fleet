package server

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"runnerfleet/internal/capacity"
	"runnerfleet/internal/security"
	"runnerfleet/internal/store"
	"strings"
	"time"
)

type message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func (s *Server) AgentHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /agent", s.channel)
	return m
}
func (s *Server) channel(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		fail(w, 403, "mTLS required")
		return
	}
	cert := r.TLS.PeerCertificates[0]
	id := cert.Subject.CommonName
	var m capacity.Machine
	if s.Store.Read("machine", id, &m) != nil || m.State == "revoked" {
		fail(w, 403, "machine revoked or unknown")
		return
	}
	allowed := false
	for _, serial := range m.Serials {
		if serial == cert.SerialNumber.String() {
			allowed = true
		}
	}
	if !allowed {
		fail(w, 403, "certificate not registered")
		return
	}
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" }}
	conn, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	conn.SetReadLimit(512 << 10)
	s.mu.Lock()
	if old := s.channels[id]; old != nil {
		old.Close()
	}
	s.channels[id] = conn
	s.mu.Unlock()
	defer func() {
		conn.Close()
		s.mu.Lock()
		if s.channels[id] == conn {
			delete(s.channels, id)
		}
		s.mu.Unlock()
	}()
	incoming := make(chan message, 8)
	done := make(chan struct{})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		defer close(done)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			var v message
			if conn.ReadJSON(&v) != nil {
				return
			}
			select {
			case incoming <- v:
			case <-stop:
				return
			}
		}
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	sent := map[string]int64{}
	for {
		select {
		case <-done:
			return
		case v := <-incoming:
			if s.Store.Read("machine", id, &m) != nil || m.State == "revoked" {
				return
			}
			switch v.Type {
			case "heartbeat":
				var data struct {
					Doctor         map[string]any      `json:"doctor"`
					Telemetry      map[string]any      `json:"telemetry"`
					Instances      []capacity.Instance `json:"instances"`
					Logs           map[string]string   `json:"logs"`
					InterruptingAt int64               `json:"interrupting_at"`
				}
				if json.Unmarshal(v.Data, &data) != nil {
					return
				}
				m.LastSeen = time.Now().Unix()
				m.Doctor = data.Doctor
				m.Telemetry = data.Telemetry
				idle := true
				for _, instance := range data.Instances {
					if instance.State == "busy" || instance.State == "provisioning" || instance.State == "cleaning" {
						idle = false
						break
					}
				}
				if idle {
					if m.IdleSince == 0 {
						m.IdleSince = m.LastSeen
					}
				} else {
					m.IdleSince = 0
				}
				if data.InterruptingAt > 0 {
					m.InterruptingAt = data.InterruptingAt
					m.State = "draining"
					s.alert("spot-interruption:"+id, "Interrupção Spot anunciada", m.Name)
				} else if m.State != "draining" && m.State != "revoked" && m.State != "terminated" && m.State != "terminating" {
					m.State = "online"
				}
				s.Store.Put("machine", id, m)
				s.Store.Read("machine", id, &m)
				if m.State == "revoked" {
					return
				}
				for _, v := range data.Instances {
					current, e := capacity.Get(s.Store, v.ID)
					if e != nil || current.Machine != id || !capacity.Active(current.State) || current.State == "cleaned" {
						continue
					}
					switch v.State {
					case "idle", "busy", "cleaning", "cleaned", "provisioning":
						capacity.Update(s.Store, v.ID, v.State, v.Error)
					}
				}
				if data.InterruptingAt > 0 {
					for _, instance := range data.Instances {
						if instance.State == "idle" {
							drainOnce(s.Store, id, instance.ID)
						}
					}
				}
				for instance, log := range data.Logs {
					v, e := capacity.Get(s.Store, instance)
					if e == nil && v.Machine == id {
						if len(log) > 16384 {
							log = log[len(log)-16384:]
						}
						s.Store.Put("agentlog", instance, map[string]any{"id": instance, "machine": id, "log": log, "observed_at": time.Now().Unix()})
					}
				}
				if conn.WriteJSON(map[string]any{"type": "policy", "data": m}) != nil {
					return
				}
				retired := []string{}
				all, _ := capacity.List(s.Store)
				for _, v := range all {
					if v.Machine == id && (v.State == "removed" || v.State == "failed") {
						retired = append(retired, v.ID)
					}
				}
				if len(retired) > 0 {
					if conn.WriteJSON(map[string]any{"type": "retired", "data": retired}) != nil {
						return
					}
				}
			case "ack":
				var a struct {
					ID    string `json:"id"`
					OK    bool   `json:"ok"`
					Error string `json:"error"`
				}
				if json.Unmarshal(v.Data, &a) != nil {
					return
				}
				state := "done"
				if !a.OK {
					state = "failed"
				}
				s.Store.DB.Exec(`UPDATE commands SET state=?,result=? WHERE id=? AND machine=?`, state, a.Error, a.ID, id)
			case "rotate":
				var rotate struct{ CSR string }
				if json.Unmarshal(v.Data, &rotate) != nil {
					return
				}
				cert, serial, e := s.CA.Issue(rotate.CSR, id)
				if e != nil {
					return
				}
				m.Serials = append(m.Serials, serial)
				if len(m.Serials) > 2 {
					m.Serials = m.Serials[len(m.Serials)-2:]
				}
				s.Store.Put("machine", id, m)
				if conn.WriteJSON(map[string]any{"type": "certificate", "data": map[string]any{"cert": cert}}) != nil {
					return
				}
			}
		case <-tick.C:
			if s.Store.Read("machine", id, &m) != nil || m.State == "revoked" {
				return
			}
			rows, e := s.Store.DB.Query(`SELECT id,kind,data,expires FROM commands WHERE machine=? AND state='pending' AND kind!='drain' ORDER BY expires LIMIT 100`, id)
			if e != nil {
				continue
			}
			type cmd struct {
				ID, Kind, Data string
				Expires        int64
			}
			a := []cmd{}
			for rows.Next() {
				var c cmd
				rows.Scan(&c.ID, &c.Kind, &c.Data, &c.Expires)
				a = append(a, c)
			}
			rows.Close()
			for _, c := range a {
				if time.Now().Unix()-sent[c.ID] < 15 {
					continue
				}
				if c.Expires < time.Now().Unix() {
					s.Store.DB.Exec(`UPDATE commands SET state='expired' WHERE id=?`, c.ID)
					var data map[string]any
					json.Unmarshal([]byte(c.Data), &data)
					if instance, ok := data["instance"].(string); ok {
						capacity.Command(s.Store, id, "drain", map[string]any{"instance": instance})
					}
					continue
				}
				var data any
				json.Unmarshal([]byte(c.Data), &data)
				if c.Kind == "start" {
					v, _ := data.(map[string]any)
					raw, e := security.Open(s.Key, text(v["encrypted"]))
					if e != nil {
						continue
					}
					json.Unmarshal(raw, &data)
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if conn.WriteJSON(map[string]any{"type": "command", "data": map[string]any{"id": c.ID, "kind": c.Kind, "payload": data, "expires": c.Expires}}) != nil {
					return
				}
				sent[c.ID] = time.Now().Unix()
			}
		}
	}
}

var _ = strings.Contains
var _ = store.JSON
