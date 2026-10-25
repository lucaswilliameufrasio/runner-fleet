package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runnerfleet/internal/agent"
	"strings"
	"syscall"
)

func main() {
	command := "run"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	dir := flag.String("state", "/var/lib/runner-fleet-agent", "private state directory")
	server := flag.String("server", "", "public server HTTPS URL")
	name := flag.String("name", "", "machine name")
	codeFile := flag.String("code-file", "", "enrollment code file (never pass code in arguments)")
	cloudInstanceID := flag.String("cloud-instance-id", os.Getenv("RF_CLOUD_INSTANCE_ID"), "EC2 instance ID for cloud enrollment")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch command {
	case "doctor":
		json.NewEncoder(os.Stdout).Encode(agent.Doctor())
	case "enroll":
		b, e := os.ReadFile(*codeFile)
		if e != nil {
			log.Fatal(e)
		}
		if *name == "" {
			*name, _ = os.Hostname()
		}
		if e = agent.Enroll(ctx, *dir, *server, *name, string(b), *cloudInstanceID); e != nil {
			log.Fatal(e)
		}
		fmt.Println("machine enrolled")
	case "run":
		a, e := agent.New(*dir)
		if e != nil {
			log.Fatal(e)
		}
		if e = a.Run(ctx); e != nil {
			log.Fatal(e)
		}
	default:
		log.Fatal("unknown command")
	}
}
