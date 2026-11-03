package bootstrap

import (
	"context"
	"strings"
	"testing"
)

func TestRejectPublicLoopbackAndHostname(t *testing.T) {
	secret := "not-a-real-root-password"
	for _, host := range []string{"8.8.8.8", "127.0.0.1", "::1", "example.com", "0.0.0.0"} {
		_, err := Install(context.Background(), Request{Host: host, Port: 22, User: "root", RootPassword: secret})
		if err == nil {
			t.Fatal("unsafe SSH target accepted", host)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("root password leaked in target rejection")
		}
	}
}

func TestRootCommandChoosesRootSudoOrSu(t *testing.T) {
	secret := "super-secret-value"
	command, err := rootCommand("0", false, false, secret)
	if err != nil || command != "sh -s" || strings.Contains(command, secret) {
		t.Fatal("root session was not selected")
	}
	command, err = rootCommand("1000", true, true, secret)
	if err != nil || command != "sudo -n sh -s" || strings.Contains(command, secret) {
		t.Fatal("passwordless sudo was not selected")
	}
	command, err = rootCommand("1000", false, true, secret)
	if err != nil || command != "su" || strings.Contains(command, secret) {
		t.Fatal("su was not selected without embedding the password")
	}
	_, err = rootCommand("1000", false, false, secret)
	if err == nil || err.Error() != "su is not available" || strings.Contains(err.Error(), secret) {
		t.Fatal("missing su was not rejected")
	}
	_, err = rootCommand("1000", false, true, "")
	if err == nil || err.Error() != "root or passwordless sudo required; provide the root password for su" {
		t.Fatal("missing privilege was not rejected")
	}
	_, err = rootCommand("1000", false, true, "bad\nsecret")
	if err == nil || strings.Contains(err.Error(), "bad") || strings.Contains(err.Error(), "secret") {
		t.Fatal("rejected password was disclosed")
	}
}
