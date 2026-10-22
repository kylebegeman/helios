package watch

import (
	"context"
	"errors"
	"io"
	"net"
	stdmail "net/mail"
	"net/textproto"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kylebegeman/helios/internal/integration"
	"github.com/kylebegeman/helios/internal/mail"
	"github.com/kylebegeman/helios/internal/secrets"
)

func TestAlertSenderKeepsDisplayNameAndUsesMailboxEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, display, integration string
	}{
		{"primary", "Helios", integration.EmailName},
		{"fallback", "Hélios, alerts", integration.Email2Name},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			type receipt struct {
				envelope, message string
				err               error
			}
			delivered := make(chan receipt, 1)
			go func() {
				var result receipt
				defer func() { delivered <- result }()
				connection, err := listener.Accept()
				if err != nil {
					result.err = err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
				protocol := textproto.NewConn(connection)
				if result.err = protocol.PrintfLine("220 synthetic.example.test ready"); result.err != nil {
					return
				}
				for {
					line, err := protocol.ReadLine()
					if err != nil {
						result.err = err
						return
					}
					reply := "250 accepted"
					switch {
					case strings.HasPrefix(line, "MAIL FROM:"):
						result.envelope = line
					case line == "DATA":
						if result.err = protocol.PrintfLine("354 send message"); result.err != nil {
							return
						}
						body, err := io.ReadAll(protocol.DotReader())
						if err != nil {
							result.err = err
							return
						}
						result.message = string(body)
					case line == "QUIT":
						result.err = protocol.PrintfLine("221 bye")
						return
					}
					if result.err = protocol.PrintfLine("%s", reply); result.err != nil {
						return
					}
				}
			}()

			root := t.TempDir()
			store := &secrets.Store{Dir: filepath.Join(root, "secrets"), KeyPath: filepath.Join(root, "key")}
			if _, _, _, err := store.EnsureKey(); err != nil {
				t.Fatal(err)
			}
			if tc.integration == integration.Email2Name {
				if _, _, err := integration.Set(store, integration.EmailName, map[string]string{"smtp_host": "unavailable.example.test", "from": "primary@example.test", "to": "owner@example.test"}); err != nil {
					t.Fatal(err)
				}
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			from := (&stdmail.Address{Name: tc.display, Address: "helios@example.test"}).String()
			if _, _, err := integration.Set(store, tc.integration, map[string]string{"smtp_host": "127.0.0.1", "smtp_port": port, "from": from, "to": "owner@example.test"}); err != nil {
				t.Fatal(err)
			}
			relays, err := integration.LoadEmailRelays(store)
			if err != nil {
				t.Fatal(err)
			}
			notifier := EmailNotifier{Relays: relays, send: func(ctx context.Context, server mail.Server, message mail.Message) error {
				if server.Host == "unavailable.example.test" {
					return errors.New("synthetic primary failure")
				}
				return mail.Send(ctx, server, message)
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := notifier.Notify(ctx, Notice{Subject: "Synthetic alert", Body: "An isolated sender check."}); err != nil {
				t.Fatal(err)
			}
			result := <-delivered
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.envelope != "MAIL FROM:<helios@example.test>" {
				t.Fatalf("SMTP envelope includes a display name: %q", result.envelope)
			}
			message, err := stdmail.ReadMessage(strings.NewReader(result.message))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := stdmail.ParseAddress(message.Header.Get("From"))
			if err != nil || parsed.Name != tc.display || parsed.Address != "helios@example.test" {
				t.Fatalf("visible sender changed: %q, %v", message.Header.Get("From"), err)
			}
			if tc.integration == integration.Email2Name && !strings.Contains(message.Header.Get("From"), "=?utf-8?") {
				t.Fatal("non-ASCII display name was not encoded")
			}
		})
	}
}
