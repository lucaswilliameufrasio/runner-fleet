package bootstrap

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptEmbedsHelper(t *testing.T) {
	root := filepath.Join("..", "..")
	installPath := filepath.Join(root, "scripts", "install.sh")
	helperPath := filepath.Join(root, "scripts", "service-runner.sh")
	downloadPath := filepath.Join(root, "web", "build", "downloads", "install.sh")
	install, err := os.ReadFile(installPath)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	download, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(install, download) {
		t.Fatal("published install.sh drifted from scripts/install.sh")
	}
	marker := []byte("<<'RUNNER_FLEET_HELPER'\n")
	start := bytes.Index(install, marker)
	if start < 0 {
		t.Fatal("service helper heredoc missing")
	}
	start += len(marker)
	end := bytes.Index(install[start:], []byte("\nRUNNER_FLEET_HELPER\n"))
	if end < 0 {
		t.Fatal("service helper heredoc is not closed")
	}
	embedded := install[start : start+end+1]
	if !bytes.Equal(embedded, helper) {
		t.Fatal("embedded service helper drifted from scripts/service-runner.sh")
	}
	for _, path := range []string{installPath, helperPath, filepath.Join(root, "scripts", "uninstall.sh")} {
		if err := exec.Command("sh", "-n", path).Run(); err != nil {
			t.Fatal(path, err)
		}
	}
	text := string(install)
	for _, needle := range []string{"amzn", "liblttng-ust0", "dnf install", "zypper --non-interactive", "curl-minimal", "libopenssl3"} {
		if !strings.Contains(text, needle) {
			t.Fatalf("installer missing %s", needle)
		}
	}
	if strings.Contains(text, "NOPASSWD") || strings.Contains(text, "sudoers") {
		t.Fatal("installer grants sudo")
	}
	helperText := string(helper)
	if strings.Contains(helperText, "RUNNER_ALLOW_RUNAS_ROOT") || strings.Contains(helperText, "--ephemeral") || strings.Contains(helperText, "eval ") {
		t.Fatal("service helper is not a locked-down persistent runner")
	}
	if !strings.Contains(helperText, "--disableupdate") || !strings.Contains(helperText, "fleet-runner") {
		t.Fatal("service helper does not configure the official runner")
	}
}
