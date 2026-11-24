package message

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/pomodorozhong/rsatoy/internal/keys"
)

// key8192 loads a test-only 8192-bit key, made once and kept in testdata,
// because making one takes several seconds.
func key8192(t *testing.T) *rsa.PrivateKey {
	b, err := os.ReadFile("testdata/test-only-rsa8192.pem")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}

func keyOf(t *testing.T, bits int) *rsa.PrivateKey {
	if bits == 8192 {
		return key8192(t)
	}
	k, err := keys.Generate(bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripEverySize(t *testing.T) {
	secret := []byte("sk-test-1234567890")
	for _, bits := range keys.Sizes {
		k := keyOf(t, bits)
		msg, err := Encrypt(&k.PublicKey, secret)
		if err != nil {
			t.Fatalf("%d: %v", bits, err)
		}
		if want := 3 + bits/8 + nonceLen + len(secret) + 16; len(msg) != want {
			t.Fatalf("%d: message is %d bytes, want %d", bits, len(msg), want)
		}
		got, err := Decrypt(k, msg)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("%d: decrypt: %v", bits, err)
		}
	}
}

func TestEachMessageIsDifferent(t *testing.T) {
	k := keyOf(t, 2048)
	a, _ := Encrypt(&k.PublicKey, []byte("same"))
	b, _ := Encrypt(&k.PublicKey, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same secret are identical")
	}
}

func TestWrongKeyFails(t *testing.T) {
	a, b := keyOf(t, 2048), keyOf(t, 2048)
	msg, _ := Encrypt(&a.PublicKey, []byte("secret"))
	if _, err := Decrypt(b, msg); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	c := keyOf(t, 3072)
	if _, err := Decrypt(c, msg); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("other size: got %v, want ErrDecrypt", err)
	}
}

func TestChangedBytesFail(t *testing.T) {
	k := keyOf(t, 2048)
	msg, _ := Encrypt(&k.PublicKey, []byte("secret value"))
	fields := map[string]int{
		"length":     2,
		"wrappedKey": 10,
		"nonce":      3 + 256 + 1,
		"ciphertext": len(msg) - 20,
		"tag":        len(msg) - 1,
	}
	for name, i := range fields {
		bad := append([]byte{}, msg...)
		bad[i] ^= 0x01
		if _, err := Decrypt(k, bad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s changed: got %v, want ErrDecrypt", name, err)
		}
	}
}

func TestBadVersion(t *testing.T) {
	k := keyOf(t, 2048)
	msg, _ := Encrypt(&k.PublicKey, []byte("secret"))
	msg[0] = 0x02
	if _, err := Decrypt(k, msg); !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v, want ErrVersion", err)
	}
}

func TestTruncated(t *testing.T) {
	k := keyOf(t, 2048)
	msg, _ := Encrypt(&k.PublicKey, []byte("secret"))
	for _, n := range []int{0, 1, 3, 100, 3 + 256, 3 + 256 + 12, len(msg) - 1} {
		if _, err := Decrypt(k, msg[:n]); err == nil {
			t.Errorf("truncated to %d bytes: no error", n)
		}
	}
}

func TestSizeLimits(t *testing.T) {
	k := keyOf(t, 2048)
	if _, err := Encrypt(&k.PublicKey, nil); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty: got %v", err)
	}
	if _, err := Encrypt(&k.PublicKey, make([]byte, MaxSecret+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("too large: got %v", err)
	}
	if _, err := Encrypt(&k.PublicKey, make([]byte, MaxSecret)); err != nil {
		t.Errorf("at limit: got %v", err)
	}
}
