// Package keys makes RSA key pairs, checks their size, and reads and writes
// the public and private key files.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"

	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/fpr"
)

// Sizes lists the only RSA key sizes rsatoy accepts, in bits.
var Sizes = []int{2048, 3072, 4096, 8192}

// DefaultBits is the key size used when none is given.
const DefaultBits = 3072

const (
	fileVersion = 0x01
	saltLen     = 16
	nonceLen    = 12
	scryptN     = 1 << 15
	scryptR     = 8
	scryptP     = 1
)

var (
	// ErrBadSize means a key size is not one of Sizes.
	ErrBadSize = errors.New("keys: key size not allowed")
	// ErrNotRSA means a public key block holds something other than RSA.
	ErrNotRSA = errors.New("keys: not an RSA public key")
	// ErrWrongPassphrase means the private key file could not be opened,
	// because the passphrase is wrong or the file is damaged.
	ErrWrongPassphrase = errors.New("keys: wrong passphrase or damaged key file")
	// ErrBadKeyFile means the private key file is not in rsatoy's format.
	ErrBadKeyFile = errors.New("keys: not an rsatoy private key file")
)

// Allowed reports whether bits is one of Sizes.
func Allowed(bits int) bool {
	for _, s := range Sizes {
		if s == bits {
			return true
		}
	}
	return false
}

// Generate makes a new key pair of the given size.
func Generate(bits int) (*rsa.PrivateKey, error) {
	if !Allowed(bits) {
		return nil, ErrBadSize
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// Public is a parsed public key with its fingerprint.
type Public struct {
	Key         *rsa.PublicKey
	DER         []byte
	Bits        int
	Fingerprint string
}

// NewPublic wraps an RSA public key, checking its size.
func NewPublic(k *rsa.PublicKey) (*Public, error) {
	bits := k.N.BitLen()
	if !Allowed(bits) {
		return nil, ErrBadSize
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return &Public{Key: k, DER: der, Bits: bits, Fingerprint: fpr.Fingerprint(der, bits)}, nil
}

// Armor returns the public key as a text block.
func (p *Public) Armor() string { return armor.Encode(armor.PublicKey, p.DER) }

// ParsePublic finds a public key block in text and parses it.
func ParsePublic(text string) (*Public, error) {
	der, err := armor.Decode(armor.PublicKey, text)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, armor.ErrBadData
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, ErrNotRSA
	}
	return NewPublic(rk)
}

// SealPrivate encrypts a private key with a passphrase and returns the key
// file contents.
func SealPrivate(k *rsa.PrivateKey, passphrase []byte) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	defer wipe(der)
	salt := make([]byte, saltLen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	gcm, err := passGCM(passphrase, salt)
	if err != nil {
		return "", err
	}
	out := []byte{fileVersion}
	out = append(out, salt...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, der, nil)
	return armor.Encode(armor.PrivateKey, out), nil
}

// OpenPrivate decrypts a key file made by SealPrivate.
func OpenPrivate(text string, passphrase []byte) (*rsa.PrivateKey, error) {
	data, err := armor.Decode(armor.PrivateKey, text)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	if len(data) < 1+saltLen+nonceLen+16 || data[0] != fileVersion {
		return nil, ErrBadKeyFile
	}
	salt := data[1 : 1+saltLen]
	nonce := data[1+saltLen : 1+saltLen+nonceLen]
	gcm, err := passGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	der, err := gcm.Open(nil, nonce, data[1+saltLen+nonceLen:], nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	defer wipe(der)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, ErrBadKeyFile
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrBadKeyFile
	}
	return rk, nil
}

func passGCM(passphrase, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key(passphrase, salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Paths says where the key files live.
type Paths struct {
	Private string
	Public  string
}

// DefaultPaths returns the key file paths in the user's config folder, or
// next to override when it is not empty.
func DefaultPaths(override string) (Paths, error) {
	if override != "" {
		return Paths{Private: override, Public: override + ".pub"}, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	dir = filepath.Join(dir, "rsatoy")
	return Paths{Private: filepath.Join(dir, "key"), Public: filepath.Join(dir, "key.pub")}, nil
}

// Exists reports whether a private key file is already there.
func (p Paths) Exists() bool {
	_, err := os.Stat(p.Private)
	return err == nil
}

// Save writes both key files, creating the folder if needed. The folder gets
// mode 0700 and the private key 0600; Windows ignores these and keeps files
// in the user's profile private by default.
func (p Paths) Save(privateFile, publicFile string) error {
	if err := os.MkdirAll(filepath.Dir(p.Private), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p.Private, []byte(privateFile), 0o600); err != nil {
		return err
	}
	return os.WriteFile(p.Public, []byte(publicFile), 0o644)
}

// LoadPublic reads and parses the public key file.
func (p Paths) LoadPublic() (*Public, error) {
	b, err := os.ReadFile(p.Public)
	if err != nil {
		return nil, err
	}
	return ParsePublic(string(b))
}

// LoadPrivate reads the private key file and opens it with the passphrase.
func (p Paths) LoadPrivate(passphrase []byte) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(p.Private)
	if err != nil {
		return nil, err
	}
	return OpenPrivate(string(b), passphrase)
}

// SizesText returns the allowed sizes as "2048, 3072, 4096, 8192".
func SizesText() string {
	s := ""
	for i, b := range Sizes {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprint(b)
	}
	return s
}
