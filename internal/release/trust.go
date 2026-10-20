package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"strings"
)

// Namespace is what a release signature is made for, so a signature made
// for anything else with the same key, a git commit say, is never taken
// for one. Releases are signed with
//
//	ssh-keygen -Y sign -f <release key> -n helios-release SHA256SUMS
const Namespace = "helios-release"

// releaseKeys are the keys that may sign a release, in authorized_keys
// form, each with a comment naming it. release/allowed_signers holds the
// same keys for scripts/install-release.sh, and a test keeps the two
// equal.
//
// To rotate, add the new key to both and publish a release signed by the
// old one. Machines that install it trust both keys, so the release after
// it can be signed by the new key alone, and the old one leaves both lists
// the same way.
var releaseKeys = []string{}

// releaseKey is one key a release may be signed by.
type releaseKey struct {
	// blob is the key in SSH wire form, as a signature carries it.
	blob        []byte
	key         ed25519.PublicKey
	fingerprint string
	comment     string
}

// trusted parses the pinned keys. Only Ed25519 keys are accepted.
func trusted() ([]releaseKey, error) {
	keys := make([]releaseKey, 0, len(releaseKeys))
	for _, line := range releaseKeys {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "ssh-ed25519" {
			return nil, fmt.Errorf("pinned release key %q isn't an ssh-ed25519 key", line)
		}
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return nil, fmt.Errorf("pinned release key %q: %w", line, err)
		}
		key, err := parseEd25519(blob)
		if err != nil {
			return nil, fmt.Errorf("pinned release key %q: %w", line, err)
		}
		keys = append(keys, releaseKey{blob: blob, key: key, fingerprint: Fingerprint(blob), comment: strings.Join(fields[2:], " ")})
	}
	if len(keys) == 0 {
		return nil, errors.New("this build pins no release key")
	}
	return keys, nil
}

// Fingerprint names a public key in SSH wire form the way ssh-keygen -l
// does.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// VerifySums checks that sig, an armored SSH signature (the SSHSIG format
// ssh-keygen -Y sign writes), was made over sums for Namespace by a pinned
// release key. It returns that key's fingerprint.
func VerifySums(sums, sig []byte) (string, error) {
	block, _ := pem.Decode(sig)
	if block == nil || block.Type != "SSH SIGNATURE" {
		return "", errors.New("SHA256SUMS.sig isn't an SSH signature")
	}
	r := wire{b: block.Bytes}
	magic := r.fixed(6)
	version := r.uint32()
	pub := r.string()
	namespace := r.string()
	reserved := r.string()
	hashName := r.string()
	signature := r.string()
	if r.err != nil || len(r.b) != 0 || string(magic) != "SSHSIG" || version != 1 {
		return "", errors.New("SHA256SUMS.sig is a damaged SSH signature")
	}
	if string(namespace) != Namespace {
		return "", fmt.Errorf("SHA256SUMS.sig was made for %q, not for %s", namespace, Namespace)
	}
	if kind := keyType(pub); kind != "ssh-ed25519" {
		return "", fmt.Errorf("SHA256SUMS.sig was made with a key of type %s; Helios releases are signed with Ed25519 keys only", kind)
	}
	keys, err := trusted()
	if err != nil {
		return "", err
	}
	var signer *releaseKey
	for i := range keys {
		if bytes.Equal(keys[i].blob, pub) {
			signer = &keys[i]
		}
	}
	if signer == nil {
		return "", fmt.Errorf("SHA256SUMS.sig was made by %s, which isn't a Helios release key", Fingerprint(pub))
	}
	var h hash.Hash
	switch string(hashName) {
	case "sha512":
		h = sha512.New()
	case "sha256":
		h = sha256.New()
	default:
		return "", fmt.Errorf("SHA256SUMS.sig hashes with %q, not sha512 or sha256", hashName)
	}
	h.Write(sums)
	sigWire := wire{b: signature}
	if algorithm := sigWire.string(); string(algorithm) != "ssh-ed25519" {
		return "", fmt.Errorf("SHA256SUMS.sig is a %q signature, not ssh-ed25519", algorithm)
	}
	raw := sigWire.string()
	if sigWire.err != nil || len(sigWire.b) != 0 || len(raw) != ed25519.SignatureSize {
		return "", errors.New("SHA256SUMS.sig is a damaged SSH signature")
	}
	// What was signed: the magic, then the namespace, reserved field, hash
	// name and the message's hash, each as an SSH string.
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	for _, field := range [][]byte{namespace, reserved, hashName, h.Sum(nil)} {
		writeString(&signed, field)
	}
	if !ed25519.Verify(signer.key, signed.Bytes(), raw) {
		return "", fmt.Errorf("SHA256SUMS doesn't match the signature %s made", signer.fingerprint)
	}
	return signer.fingerprint, nil
}

func parseEd25519(blob []byte) (ed25519.PublicKey, error) {
	r := wire{b: blob}
	kind := r.string()
	key := r.string()
	if r.err != nil || len(r.b) != 0 || string(kind) != "ssh-ed25519" || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("not an ssh-ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

// keyType is the algorithm a public key in SSH wire form names.
func keyType(blob []byte) string {
	r := wire{b: blob}
	kind := r.string()
	if r.err != nil || len(kind) == 0 {
		return "damaged"
	}
	return string(kind)
}

// wire reads the SSH wire encoding: big-endian uint32s, and strings
// prefixed with their uint32 length. The first short read sets err.
type wire struct {
	b   []byte
	err error
}

func (w *wire) fixed(n int) []byte {
	if w.err != nil || len(w.b) < n {
		w.err = errors.New("short")
		return nil
	}
	out := w.b[:n]
	w.b = w.b[n:]
	return out
}

func (w *wire) uint32() uint32 {
	b := w.fixed(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (w *wire) string() []byte {
	n := w.uint32()
	if w.err != nil || uint64(n) > uint64(len(w.b)) {
		w.err = errors.New("short")
		return nil
	}
	return w.fixed(int(n))
}

func writeString(buf *bytes.Buffer, s []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	buf.Write(n[:])
	buf.Write(s)
}
