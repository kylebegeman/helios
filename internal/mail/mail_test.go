package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSMTP speaks just enough SMTP to accept one message.
type fakeSMTP struct {
	auth string
	from string
	rcpt []string
	data string
}

func serve(t *testing.T) (*fakeSMTP, Server) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeSMTP{}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { conn.Write([]byte(s + "\r\n")) } //nolint:errcheck
		w("220 fake ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case strings.HasPrefix(line, "EHLO"):
				w("250-fake")
				w("250 AUTH PLAIN")
			case strings.HasPrefix(line, "AUTH PLAIN "):
				f.auth = strings.TrimPrefix(line, "AUTH PLAIN ")
				w("235 ok")
			case strings.HasPrefix(line, "MAIL FROM:"):
				f.from = line
				w("250 ok")
			case strings.HasPrefix(line, "RCPT TO:"):
				f.rcpt = append(f.rcpt, line)
				w("250 ok")
			case line == "DATA":
				w("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				f.data = b.String()
				w("250 queued")
			case line == "QUIT":
				w("221 bye")
				return
			default:
				w("250 ok")
			}
		}
	}()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	p, _ := strconv.Atoi(port)
	return f, Server{Host: "127.0.0.1", Port: p, User: "bedrock", Password: "pw"}
}

func TestSendsAPlainTextMessageWithAuthToALocalServer(t *testing.T) {
	f, srv := serve(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := Send(ctx, srv, Message{From: "bedrock@example.com", To: []string{"kyle@example.com", "ops@example.com"}, Subject: "hello is down", Body: "web isn't running\n.\nsecond line"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.StdEncoding.DecodeString(f.auth)
	if string(decoded) != "\x00bedrock\x00pw" {
		t.Fatalf("auth %q", decoded)
	}
	if f.from != "MAIL FROM:<bedrock@example.com>" || len(f.rcpt) != 2 || f.rcpt[1] != "RCPT TO:<ops@example.com>" {
		t.Fatalf("envelope %q %q", f.from, f.rcpt)
	}
	for _, want := range []string{"Subject: hello is down\r\n", "To: kyle@example.com, ops@example.com\r\n", "Content-Type: text/plain; charset=utf-8", "web isn't running\r\n..\r\nsecond line\r\n"} {
		if !strings.Contains(f.data, want) {
			t.Fatalf("message lacks %q:\n%s", want, f.data)
		}
	}
}

func TestRefusesAnUnencryptedRemoteServer(t *testing.T) {
	_, srv := serve(t)
	// The fake listens on loopback; pretend it is remote by name.
	srv.Host = "smtp.example.invalid"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := Send(ctx, srv, Message{From: "a@b", To: []string{"c@d"}, Subject: "x", Body: "y"})
	if err == nil {
		t.Fatal("sent in the clear to a remote host")
	}
}

func TestHeadersStayOnOneLineWhateverTheAddressesHold(t *testing.T) {
	m := Message{From: "a@b\r\nBcc: x@y", To: []string{"c@d\nBcc: z@w"}, Subject: "s\r\nX-Bad: y", Body: "hi"}
	headers, _, _ := strings.Cut(m.render(), "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") || strings.HasPrefix(line, "X-Bad:") {
			t.Fatalf("a header was injected: %q", headers)
		}
	}
	if !strings.Contains(headers, "From: a@b  Bcc: x@y") {
		t.Fatalf("the address was not kept on its line: %q", headers)
	}
}
