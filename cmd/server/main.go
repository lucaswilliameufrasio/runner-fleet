package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runnerfleet/internal/backups"
	"runnerfleet/internal/server"
	"strings"
	"syscall"
	"time"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	data := flag.String("data", "./data", "data directory")
	listen := flag.String("listen", "127.0.0.1:8080", "web bind")
	agentListen := flag.String("agent-listen", ":8443", "mTLS agent bind")
	origin := flag.String("origin", "http://localhost:8080", "public panel origin")
	agentURL := flag.String("agent-url", "wss://localhost:8443/agent", "public agent endpoint")
	web := flag.String("web", "web/build", "static panel directory")
	dev := flag.Bool("dev", false, "allow HTTP browser cookies for loopback development only")
	cert := flag.String("tls-cert", "", "public TLS certificate for agent endpoint")
	key := flag.String("tls-key", "", "public TLS key")
	input := flag.String("input", "", "encrypted backup file")
	output := flag.String("output", "", "restore to new SQLite path")
	flag.Parse()
	if *dev && !strings.Contains(*origin, "localhost") && !strings.Contains(*origin, "127.0.0.1") {
		log.Fatal("dev allowed only on loopback origin")
	}
	if command == "restore" {
		if *input == "" || *output == "" {
			log.Fatal("--input and --output required")
		}
		if _, e := os.Stat(*output); !os.IsNotExist(e) {
			log.Fatal("restore refuses existing destination")
		}
		password, e := os.ReadFile(os.Getenv("RF_BACKUP_PASSWORD_FILE"))
		if e != nil {
			log.Fatal("RF_BACKUP_PASSWORD_FILE required")
		}
		b, e := os.ReadFile(*input)
		if e != nil {
			log.Fatal(e)
		}
		b, e = backups.Decrypt(b, strings.TrimSpace(string(password)))
		if e != nil {
			log.Fatal(e)
		}
		os.MkdirAll(filepath.Dir(*output), 0700)
		if e = os.WriteFile(*output, b, 0600); e != nil {
			log.Fatal(e)
		}
		fmt.Println("Restored isolated SQLite snapshot. Restore recovery keys before starting; invalidate sessions.")
		return
	}
	s, e := server.New(server.Config{DataDir: *data, Origin: strings.TrimRight(*origin, "/"), AgentURL: *agentURL, WebDir: *web, Dev: *dev})
	if e != nil {
		log.Fatal(e)
	}
	defer s.Store.DB.Close()
	switch command {
	case "setup-code":
		code, e := s.SetupCode()
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println(code)
		return
	case "recover":
		code, e := s.Recover()
		if e != nil {
			log.Fatal(e)
		}
		fmt.Println(code)
		return
	case "invalidate-sessions":
		s.Store.DB.Exec(`DELETE FROM sessions`)
		s.Store.DB.Exec(`UPDATE resources SET data=json_set(data,'$.state','draining') WHERE kind='machine'`)
		fmt.Println("sessions invalidated; machines draining")
		return
	case "serve":
	default:
		log.Fatal("unknown command")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s.Start(ctx)
	webServer := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	if *cert != "" && *key != "" {
		agent := &http.Server{Addr: *agentListen, Handler: s.AgentHandler(), TLSConfig: s.AgentTLS(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if e := agent.ListenAndServeTLS(*cert, *key); e != nil && e != http.ErrServerClosed {
				log.Print(e)
				cancel()
			}
		}()
		go func() { <-ctx.Done(); agent.Close() }()
	} else {
		log.Print("agent endpoint disabled: configure --tls-cert and --tls-key")
	}
	go func() {
		if e := webServer.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			log.Print(e)
			cancel()
		}
	}()
	log.Printf("web listening on %s", *listen)
	<-ctx.Done()
	shutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	webServer.Shutdown(shutdown)
	_ = json.Valid
}
