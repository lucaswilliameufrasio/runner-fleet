package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net"
	"strconv"
	"strings"
	"time"
)

type Request struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	PrivateKey  string `json:"private_key"`
	Fingerprint string `json:"fingerprint"`
	Installer   string `json:"installer"`
}

func Install(ctx context.Context, v Request) (string, error) {
	ip := net.ParseIP(v.Host)
	tailscale := false
	if ip != nil && ip.To4() != nil {
		b := ip.To4()
		tailscale = b[0] == 100 && b[1] >= 64 && b[1] <= 127
	}
	if ip == nil || (!ip.IsPrivate() && !tailscale) || ip.IsLoopback() || ip.IsUnspecified() {
		return "", errors.New("private or Tailscale literal IP required; loopback denied")
	}
	if v.Port < 1 || v.Port > 65535 {
		return "", errors.New("invalid port")
	}
	if v.User == "" || strings.ContainsAny(v.User, " \n\r;&") {
		return "", errors.New("invalid user")
	}
	key, e := ssh.ParsePrivateKey([]byte(v.PrivateKey))
	if e != nil {
		return "", errors.New("invalid SSH key")
	}
	cfg := &ssh.ClientConfig{User: v.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, Timeout: 15 * time.Second, HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != v.Fingerprint {
			return errors.New("SSH host fingerprint mismatch")
		}
		return nil
	}}
	raw, e := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(v.Host, strconv.Itoa(v.Port)))
	if e != nil {
		return "", e
	}
	raw.SetDeadline(time.Now().Add(10 * time.Minute))
	conn, ch, req, e := ssh.NewClientConn(raw, net.JoinHostPort(v.Host, strconv.Itoa(v.Port)), cfg)
	if e != nil {
		raw.Close()
		return "", e
	}
	client := ssh.NewClient(conn, ch, req)
	defer client.Close()
	sess, e := client.NewSession()
	if e != nil {
		return "", e
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(v.Installer)
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		}
	}()
	e = sess.Run("sudo -n sh -s")
	if e != nil {
		return "", fmt.Errorf("bootstrap failed; check sudo, outbound HTTPS and artifact configuration")
	}
	return "agent installed", nil
}
