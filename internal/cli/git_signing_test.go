package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/kylebegeman/helios/internal/gitdeploy"
)

// publicKey is a fresh ed25519 public key line, made without ssh-keygen.
func publicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	for _, part := range [][]byte{[]byte("ssh-ed25519"), pub} {
		blob = binary.BigEndian.AppendUint32(blob, uint32(len(part)))
		blob = append(blob, part...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " someone@example.test"
}

func TestSignersArePlannedAndSignaturesWaitForASigner(t *testing.T) {
	if _, err := os.Stat(gitdeploy.SigningDir); !errors.Is(err, os.ErrNotExist) {
		t.Skipf("this machine has a signing policy of its own, or it can't be read: %v", err)
	}
	pub := publicKey(t)
	out, stderr, code := run(t, t.TempDir(), "git", "signers", "add", "kyle@example.com", pub, "--plan")
	if code != 0 || !strings.Contains(out, "let kyle@example.com sign deploy commits with ssh-ed25519 key SHA256:") || !strings.Contains(out, "plan digest ") {
		t.Fatalf("%d %s %s", code, out, stderr)
	}
	if _, stderr, code := run(t, t.TempDir(), "git", "signers", "add", "kyle example", pub, "--plan"); code == 0 || !strings.Contains(stderr, "one word") {
		t.Fatalf("a name with a space: %d %s", code, stderr)
	}
	if _, stderr, code := run(t, t.TempDir(), "git", "require-signed", "hello", "--plan"); code == 0 || !strings.Contains(stderr, "no signer is allowed yet") {
		t.Fatalf("signatures before a signer: %d %s", code, stderr)
	}
	out, _, code = run(t, t.TempDir(), "git", "signers", "list")
	if code != 0 || !strings.Contains(out, "no signer is allowed yet") || !strings.Contains(out, "no app deploys only signed commits") {
		t.Fatalf("%d %s", code, out)
	}
	out, _, _ = run(t, t.TempDir(), "--json", "git", "signers", "list")
	var list struct {
		Signers       []any    `json:"signers"`
		RequireSigned []string `json:"require_signed"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil || list.Signers == nil || list.RequireSigned == nil {
		t.Fatalf("%v %s", err, out)
	}
}

func TestATargetThatCantCheckSignaturesIsNotAskedTo(t *testing.T) {
	config, record := targetFixture(t)
	for _, args := range [][]string{
		{"git", "require-signed", "hello", "--plan"},
		{"git", "require-signed", "hello", "--yes"},
		{"git", "signers", "add", "kyle@example.com", publicKey(t), "--plan"},
		{"git", "signers", "add", "kyle@example.com", publicKey(t), "--yes"},
	} {
		if _, stderr, code := targetRun(t, config, args...); code == 0 || !strings.Contains(stderr, "does not gate deploys on signed commits") {
			t.Fatalf("%v: %d %s", args, code, stderr)
		}
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatal("the target was asked")
	}
}
