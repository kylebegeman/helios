package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures in testdata were made by ssh-keygen with throwaway keys whose
// private halves were never kept:
//
//	ssh-keygen -Y sign -f release -n helios-release SHA256SUMS
//
// and the same with another key, with -n file, and with an ECDSA key.
const fixtureSigner = "SHA256:L5pKCki3biS1Qo9z4OnvewnKmMNG9LOj0swiKu+oiG0"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pin makes keys the release keys for one test.
func pin(t *testing.T, keys ...string) {
	t.Helper()
	old := releaseKeys
	releaseKeys = keys
	t.Cleanup(func() { releaseKeys = old })
}

// newReleaseKey makes a key for a test to sign with, pins it, and returns it
// with its fingerprint.
func newReleaseKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := ed25519Blob(pub)
	pin(t, "ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob)+" a test release key")
	return key, Fingerprint(blob)
}

func ed25519Blob(pub ed25519.PublicKey) []byte {
	var b bytes.Buffer
	writeString(&b, []byte("ssh-ed25519"))
	writeString(&b, pub)
	return b.Bytes()
}

// sign does what ssh-keygen -Y sign does, so tests can sign what they
// publish. VerifySums is checked against ssh-keygen's own signatures, so a
// signature from here that it accepts is one ssh-keygen would make.
func sign(key ed25519.PrivateKey, namespace string, message []byte) []byte {
	sum := sha512.Sum512(message)
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, field := range [][]byte{[]byte(namespace), nil, []byte("sha512"), sum[:]} {
		writeString(&signed, field)
	}
	var signature bytes.Buffer
	writeString(&signature, []byte("ssh-ed25519"))
	writeString(&signature, ed25519.Sign(key, signed.Bytes()))
	var blob bytes.Buffer
	blob.WriteString("SSHSIG")
	binary.Write(&blob, binary.BigEndian, uint32(1))
	for _, field := range [][]byte{ed25519Blob(key.Public().(ed25519.PublicKey)), []byte(namespace), nil, []byte("sha512"), signature.Bytes()} {
		writeString(&blob, field)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: blob.Bytes()})
}

func TestASignatureMadeBySSHKeygenVerifies(t *testing.T) {
	pin(t, strings.TrimSpace(string(fixture(t, "release.pub"))))
	signer, err := VerifySums(fixture(t, "SHA256SUMS"), fixture(t, "SHA256SUMS.sig"))
	if err != nil || signer != fixtureSigner {
		t.Fatalf("signer %q, %v", signer, err)
	}
}

func TestAReleaseSignatureIsRefusedWithAReadableError(t *testing.T) {
	sums := fixture(t, "SHA256SUMS")
	sig := fixture(t, "SHA256SUMS.sig")
	block, _ := pem.Decode(sig)
	damaged := pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: block.Bytes[:len(block.Bytes)-9]})
	for _, c := range []struct {
		name, want string
		sums, sig  []byte
	}{
		{"tampered sums", "SHA256SUMS doesn't match the signature " + fixtureSigner + " made", append(append([]byte{}, sums...), "0000  helios_0.7.99_linux_amd64\n"...), sig},
		{"another key", "which isn't a Helios release key", sums, fixture(t, "SHA256SUMS.other-key.sig")},
		{"another namespace", `SHA256SUMS.sig was made for "file", not for helios-release`, sums, fixture(t, "SHA256SUMS.other-namespace.sig")},
		{"an ECDSA key", "made with a key of type ecdsa-sha2-nistp256; Helios releases are signed with Ed25519 keys only", sums, fixture(t, "SHA256SUMS.ecdsa.sig")},
		{"not a signature", "SHA256SUMS.sig isn't an SSH signature", sums, []byte("<html>not found</html>")},
		{"a damaged signature", "SHA256SUMS.sig is a damaged SSH signature", sums, damaged},
	} {
		t.Run(c.name, func(t *testing.T) {
			pin(t, strings.TrimSpace(string(fixture(t, "release.pub"))))
			signer, err := VerifySums(c.sums, c.sig)
			if err == nil || !strings.Contains(err.Error(), c.want) || signer != "" {
				t.Fatalf("want an error saying %q, got %q, %v", c.want, signer, err)
			}
		})
	}
}

func TestABuildThatPinsNoReleaseKeyTrustsNoSignature(t *testing.T) {
	pin(t)
	if _, err := VerifySums(fixture(t, "SHA256SUMS"), fixture(t, "SHA256SUMS.sig")); err == nil || !strings.Contains(err.Error(), "pins no release key") {
		t.Fatalf("want a no-key error, got %v", err)
	}
	pin(t, strings.TrimSpace(string(fixture(t, "ecdsa.pub"))))
	if _, err := VerifySums(fixture(t, "SHA256SUMS"), fixture(t, "SHA256SUMS.sig")); err == nil || !strings.Contains(err.Error(), "isn't an ssh-ed25519 key") {
		t.Fatalf("want an Ed25519-only error, got %v", err)
	}
}

// Every build of Helios has to pin a release key, or an upgrade without a
// pinned checksum refuses every release. release/allowed_signers is the
// same list for scripts/install-release.sh, which can't read Go.
func TestTheShippedReleaseKeysMatchAllowedSigners(t *testing.T) {
	keys, err := trusted()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "release", "allowed_signers"))
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if len(fields) < 4 || fields[0] != "helios-release" || fields[1] != `namespaces="helios-release"` {
			t.Fatalf("allowed_signers line %q must read: helios-release namespaces=\"helios-release\" <key>", line)
		}
		listed = append(listed, fields[2]+" "+fields[3])
	}
	var pinned []string
	for _, k := range keys {
		pinned = append(pinned, "ssh-ed25519 "+base64.StdEncoding.EncodeToString(k.blob))
	}
	if strings.Join(listed, "\n") != strings.Join(pinned, "\n") {
		t.Fatalf("release/allowed_signers lists\n%s\nbut the build pins\n%s", strings.Join(listed, "\n"), strings.Join(pinned, "\n"))
	}
}
