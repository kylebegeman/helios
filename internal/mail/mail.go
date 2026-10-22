// Package mail sends plain-text messages through an SMTP server: the
// fallback that reaches a person when nothing else does.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	stdmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Server is where messages go.
type Server struct {
	Host string
	Port int
	// User and Password authenticate when set.
	User     string
	Password string
}

// Message is one plain-text mail.
type Message struct {
	From     string // Plain mailbox for the SMTP envelope.
	FromName string // Optional display name for the message header only.
	To       []string
	Subject  string
	Body     string
}

// Send delivers a message. Port 465 speaks TLS from the start; other ports
// start plain and upgrade with STARTTLS, which is required unless the
// server is on this machine.
func Send(ctx context.Context, s Server, m Message) (err error) {
	if s.Host == "" || s.Port == 0 {
		return errors.New("no mail server configured")
	}
	if len(m.To) == 0 {
		return errors.New("no recipients")
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	tlsConfig := &tls.Config{ServerName: s.Host, MinVersion: tls.VersionTLS12}
	if s.Port == 465 {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("mail server %s: %w", addr, err)
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	deadline := time.Now().Add(60 * time.Second)
	if requested, ok := ctx.Deadline(); ok && requested.Before(deadline) {
		deadline = requested
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mail server %s: %w", addr, err)
	}
	defer c.Close()
	if err := c.Hello(clientName()); err != nil {
		return fmt.Errorf("mail server %s: %w", addr, err)
	}
	if s.Port != 465 {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("mail server %s: STARTTLS: %w", addr, err)
			}
		} else if !loopback(s.Host) {
			return fmt.Errorf("mail server %s doesn't offer STARTTLS; refusing to send in the clear", addr)
		}
	}
	if s.User != "" {
		if err := c.Auth(auth(s)); err != nil {
			return fmt.Errorf("mail server %s rejected the login: %w", addr, err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("mail server %s rejected the sender %s: %w", addr, m.From, err)
	}
	for _, to := range m.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("mail server %s rejected the recipient %s: %w", addr, to, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(m.render())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail server %s didn't accept the message: %w", addr, err)
	}
	// DATA's successful final reply accepts responsibility for delivery.
	// A failed session teardown must not send the same alert through a fallback.
	_ = c.Quit()
	return nil
}

// auth picks PLAIN, which net/smtp only allows over TLS or to localhost,
// and LOGIN for servers that offer nothing else.
func auth(s Server) smtp.Auth {
	return &plainOrLogin{plain: smtp.PlainAuth("", s.User, s.Password, s.Host), user: s.User, password: s.Password, host: s.Host}
}

type plainOrLogin struct {
	plain          smtp.Auth
	user, password string
	host           string
	login          bool
}

func (a *plainOrLogin) Start(server *smtp.ServerInfo) (string, []byte, error) {
	for _, m := range server.Auth {
		if m == "PLAIN" {
			return a.plain.Start(server)
		}
	}
	for _, m := range server.Auth {
		if m == "LOGIN" {
			if !server.TLS && !loopback(server.Name) {
				return "", nil, errors.New("unencrypted connection")
			}
			a.login = true
			return "LOGIN", nil, nil
		}
	}
	return a.plain.Start(server)
}

func (a *plainOrLogin) Next(fromServer []byte, more bool) ([]byte, error) {
	if !a.login {
		return a.plain.Next(fromServer, more)
	}
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("unexpected server challenge %q", fromServer)
}

// headerLine keeps a header's value to one line: a line break in an
// address or a subject would start a header of the sender's choosing.
func headerLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func clientName() string {
	if h, err := hostname(); err == nil && h != "" {
		return h
	}
	return "helios"
}

func (m Message) render() string {
	var b strings.Builder
	from := headerLine(m.From)
	if m.FromName != "" {
		from = (&stdmail.Address{Address: from, Name: headerLine(m.FromName)}).String()
	}
	fmt.Fprintf(&b, "From: %s\r\n", from)
	to := make([]string, 0, len(m.To))
	for _, addr := range m.To {
		to = append(to, headerLine(addr))
	}
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", headerLine(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%d.%s@%s>\r\n", time.Now().UnixNano(), "helios", clientName())
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	// net/smtp's data writer dot-stuffs lines itself.
	body := strings.ReplaceAll(m.Body, "\r\n", "\n")
	for _, line := range strings.Split(body, "\n") {
		b.WriteString(line + "\r\n")
	}
	return b.String()
}
