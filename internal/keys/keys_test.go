package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pomodorozhong/rsatoy/internal/armor"
)

func TestGenerateRefusesOtherSizes(t *testing.T) {
	for _, bits := range []int{0, 1024, 307, 3071, 5120, 16384} {
		if _, err := Generate(bits); !errors.Is(err, ErrBadSize) {
			t.Errorf("bits=%d: got %v, want ErrBadSize", bits, err)
		}
	}
}

func TestPublicRoundTrip(t *testing.T) {
	k, err := Generate(2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := NewPublic(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePublic("Here is my key:\n" + pub.Armor() + "bye\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != pub.Fingerprint || got.Bits != 2048 || got.Key.N.Cmp(k.N) != 0 {
		t.Fatal("public key changed in round trip")
	}
	if !strings.HasSuffix(pub.Fingerprint, "(RSA 2048)") {
		t.Fatalf("fingerprint %q does not show size", pub.Fingerprint)
	}
}

func TestParsePublicRefusesSmallKey(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := ParsePublic(armor.Encode(armor.PublicKey, der)); !errors.Is(err, ErrBadSize) {
		t.Fatalf("got %v, want ErrBadSize", err)
	}
}

func TestParsePublicRefusesNonRSA(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if _, err := ParsePublic(armor.Encode(armor.PublicKey, der)); !errors.Is(err, ErrNotRSA) {
		t.Fatalf("got %v, want ErrNotRSA", err)
	}
}

func TestPrivateKeyFile(t *testing.T) {
	k, err := Generate(2048)
	if err != nil {
		t.Fatal(err)
	}
	file, err := SealPrivate(k, []byte("correct horse"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPrivate(file, []byte("correct horse"))
	if err != nil || got.N.Cmp(k.N) != 0 {
		t.Fatalf("open failed: %v", err)
	}
	if _, err := OpenPrivate(file, []byte("wrong horse")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: got %v", err)
	}
	if _, err := OpenPrivate("not a key file", []byte("x")); !errors.Is(err, ErrBadKeyFile) {
		t.Fatalf("garbage: got %v", err)
	}
	// Change one byte inside the encrypted part.
	data, _ := armor.Decode(armor.PrivateKey, file)
	data[len(data)-5] ^= 1
	if _, err := OpenPrivate(armor.Encode(armor.PrivateKey, data), []byte("correct horse")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("changed byte: got %v", err)
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	paths, _ := DefaultPaths(filepath.Join(dir, "sub", "key"))
	if paths.Exists() {
		t.Fatal("key exists before save")
	}
	k, _ := Generate(2048)
	pub, _ := NewPublic(&k.PublicKey)
	file, _ := SealPrivate(k, []byte("pw"))
	if err := paths.Save(file, pub.Armor()); err != nil {
		t.Fatal(err)
	}
	if !paths.Exists() {
		t.Fatal("key missing after save")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(paths.Private)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode %v, want 0600", info.Mode().Perm())
		}
	}
	gotPub, err := paths.LoadPublic()
	if err != nil || gotPub.Fingerprint != pub.Fingerprint {
		t.Fatalf("load public: %v", err)
	}
	if _, err := paths.LoadPrivate([]byte("pw")); err != nil {
		t.Fatalf("load private: %v", err)
	}
}
