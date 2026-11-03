package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Request struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"user"`
	PrivateKey   string `json:"private_key"`
	Fingerprint  string `json:"fingerprint"`
	Installer    string `json:"installer"`
	RootPassword string `json:"root_password,omitempty"`
}

func Install(ctx context.Context, v Request) (string, error) {
	if err := validateTarget(v); err != nil {
		return "", redactSecret(err, v.RootPassword)
	}
	if err := validatePassword(v.RootPassword); err != nil {
		return "", redactSecret(err, v.RootPassword)
	}
	client, err := dial(ctx, v)
	if err != nil {
		return "", redactSecret(err, v.RootPassword)
	}
	defer client.Close()
	go func() {
		<-ctx.Done()
		client.Close()
	}()
	uid, uidErr := remoteOutput(client, "id -u")
	_, sudoErr := remoteOutput(client, "sudo -n true")
	_, suErr := remoteOutput(client, "command -v su")
	if uidErr != nil {
		return "", redactSecret(errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration"), v.RootPassword)
	}
	mode, err := rootCommand(strings.TrimSpace(uid), sudoErr == nil, suErr == nil, v.RootPassword)
	if err != nil {
		return "", redactSecret(err, v.RootPassword)
	}
	switch mode {
	case "sh -s", "sudo -n sh -s":
		err = runInstaller(client, mode, v.Installer)
	case "su":
		path, stageErr := stageInstaller(client, v.Installer)
		if stageErr != nil {
			return "", redactSecret(stageErr, v.RootPassword)
		}
		defer removeStaged(client, path)
		err = runSu(client, path, v.RootPassword)
	default:
		err = errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	if err != nil {
		return "", redactSecret(err, v.RootPassword)
	}
	return "agent installed", nil
}

func rootCommand(uid string, sudoOK, suOK bool, password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	if uid == "0" {
		return "sh -s", nil
	}
	if sudoOK {
		return "sudo -n sh -s", nil
	}
	if password != "" && suOK {
		return "su", nil
	}
	if password != "" && !suOK {
		return "", errors.New("su is not available")
	}
	return "", errors.New("root or passwordless sudo required; provide the root password for su")
}

func validatePassword(password string) error {
	if password == "" {
		return nil
	}
	if len(password) > 1024 || strings.ContainsAny(password, "\n\r\x00") {
		return errors.New("invalid root password")
	}
	return nil
}

func validateTarget(v Request) error {
	ip := net.ParseIP(v.Host)
	tailscale := false
	if ip != nil && ip.To4() != nil {
		b := ip.To4()
		tailscale = b[0] == 100 && b[1] >= 64 && b[1] <= 127
	}
	if ip == nil || (!ip.IsPrivate() && !tailscale) || ip.IsLoopback() || ip.IsUnspecified() {
		return errors.New("private or Tailscale literal IP required; loopback denied")
	}
	if v.Port < 1 || v.Port > 65535 {
		return errors.New("invalid port")
	}
	if v.User == "" || strings.ContainsAny(v.User, " \n\r;&") {
		return errors.New("invalid user")
	}
	return nil
}

func dial(ctx context.Context, v Request) (*ssh.Client, error) {
	key, err := ssh.ParsePrivateKey([]byte(v.PrivateKey))
	if err != nil {
		return nil, errors.New("invalid SSH key")
	}
	cfg := &ssh.ClientConfig{
		User:    v.User,
		Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
		Timeout: 15 * time.Second,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			if ssh.FingerprintSHA256(key) != v.Fingerprint {
				return errors.New("SSH host fingerprint mismatch")
			}
			return nil
		},
	}
	raw, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(v.Host, strconv.Itoa(v.Port)))
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(10 * time.Minute))
	conn, ch, req, err := ssh.NewClientConn(raw, net.JoinHostPort(v.Host, strconv.Itoa(v.Port)), cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return ssh.NewClient(conn, ch, req), nil
}

func remoteOutput(client *ssh.Client, command string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	err = sess.Run(command)
	return strings.TrimSpace(out.String()), err
}

func runInstaller(client *ssh.Client, command, script string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Run(command); err != nil {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	return nil
}

func stageInstaller(client *ssh.Client, installer string) (string, error) {
	home, err := remoteOutput(client, `printf %s "$HOME"`)
	if err != nil || !safeAbsolute(home) {
		return "", errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	dir := home + "/.local/state/runner-fleet"
	path := dir + "/bootstrap.sh"
	if !safeAbsolute(path) {
		return "", errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	if _, err := remoteOutput(client, "umask 077; mkdir -p "+dir); err != nil {
		return "", errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	sess.Stdin = strings.NewReader(installer)
	var out bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &out
	if err := sess.Run("cat > " + path); err != nil {
		return "", errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	if _, err := remoteOutput(client, "chmod 700 "+path); err != nil {
		return "", errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	return path, nil
}

func removeStaged(client *ssh.Client, path string) {
	if !safeAbsolute(path) {
		return
	}
	sess, err := client.NewSession()
	if err != nil {
		return
	}
	defer sess.Close()
	_ = sess.Run("rm -f " + path)
}

func runSu(client *ssh.Client, path, password string) error {
	if !safeAbsolute(path) {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm", 40, 80, modes); err != nil {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	reader, writer := io.Pipe()
	sess.Stdout = writer
	sess.Stderr = writer
	stdin, err := sess.StdinPipe()
	if err != nil {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	if err := sess.Start("su - -c 'sh " + path + "'"); err != nil {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	waitErr := make(chan error, 1)
	go func() {
		err := sess.Wait()
		writer.Close()
		waitErr <- err
	}()
	stopPromptTimer := make(chan struct{})
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-stopPromptTimer:
		case <-timer.C:
			sess.Close()
		}
	}()
	head, prompted := readUntilPrompt(reader)
	close(stopPromptTimer)
	if !prompted {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	if _, err := io.WriteString(stdin, password+"\n"); err != nil {
		return errors.New("root password rejected")
	}
	_ = stdin.Close()
	rest := drainLimited(reader, 8<<20)
	head = append(head, rest...)
	err = <-waitErr
	if err != nil {
		if passwordRejected(head) {
			return errors.New("root password rejected")
		}
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	return nil
}

func readUntilPrompt(r io.Reader) ([]byte, bool) {
	buf := make([]byte, 256)
	var got []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
			if bytes.Contains(bytes.ToLower(got), []byte("assword:")) {
				return got, true
			}
			if len(got) > 8192 {
				got = got[:8192]
			}
		}
		if err != nil {
			return got, false
		}
	}
}

func drainLimited(r io.Reader, limit int) []byte {
	buf := make([]byte, 256)
	var head []byte
	total := 0
	for total < limit {
		n, err := r.Read(buf)
		if n > 0 {
			total += n
			if len(head) < 8192 {
				head = append(head, buf[:n]...)
				if len(head) > 8192 {
					head = head[:8192]
				}
			}
		}
		if err != nil {
			break
		}
	}
	return head
}

func passwordRejected(output []byte) bool {
	lower := bytes.ToLower(output)
	if bytes.Contains(lower, []byte("authentication failure")) {
		return true
	}
	if bytes.Contains(lower, []byte("sorry, try again")) {
		return true
	}
	return false
}

func safeAbsolute(path string) bool {
	if len(path) < 2 || len(path) > 256 || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return false
	}
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

func redactSecret(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	if strings.Contains(err.Error(), secret) {
		return errors.New("bootstrap failed; check root access, outbound HTTPS and artifact configuration")
	}
	return err
}
