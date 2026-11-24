// Package message encrypts a secret to an RSA public key and decrypts it.
//
// It uses the standard hybrid scheme: a fresh AES-256-GCM key encrypts the
// secret, and RSA-OAEP with SHA-256 encrypts that key.
//
// Format: version (1 byte) || wrapped key length (2 bytes, big-endian) ||
// wrapped key || nonce (12 bytes) || AES-GCM ciphertext. Everything before
// the nonce is used as additional data, so changing it makes decryption fail.
package message

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	version  = 0x01
	nonceLen = 12
	// MaxSecret is the largest secret rsatoy encrypts, in bytes.
	MaxSecret = 64 * 1024
)

var label = []byte("rsatoy-1")

var (
	// ErrTooLarge means the secret is over MaxSecret.
	ErrTooLarge = errors.New("message: secret is too large")
	// ErrEmpty means the secret is empty.
	ErrEmpty = errors.New("message: secret is empty")
	// ErrDecrypt means the message could not be decrypted. It deliberately
	// does not say why: wrong key, damage, and tampering all look the same.
	ErrDecrypt = errors.New("message: could not decrypt")
	// ErrVersion means the message was made by a newer, unknown format.
	ErrVersion = errors.New("message: unknown format version")
)

// Encrypt returns the message bytes for secret, readable only with the
// private key matching pub.
func Encrypt(pub *rsa.PublicKey, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmpty
	}
	if len(secret) > MaxSecret {
		return nil, ErrTooLarge
	}
	key := make([]byte, 32)
	defer wipe(key)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, label)
	if err != nil {
		return nil, err
	}
	header := make([]byte, 3, 3+len(wrapped))
	header[0] = version
	binary.BigEndian.PutUint16(header[1:3], uint16(len(wrapped)))
	header = append(header, wrapped...)

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	out := append(append([]byte{}, header...), nonce...)
	return gcm.Seal(out, nonce, secret, header), nil
}

// Decrypt opens message bytes made by Encrypt.
func Decrypt(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	if len(msg) < 3 {
		return nil, ErrDecrypt
	}
	if msg[0] != version {
		return nil, ErrVersion
	}
	wl := int(binary.BigEndian.Uint16(msg[1:3]))
	if wl != priv.Size() || len(msg) < 3+wl+nonceLen+16 {
		return nil, ErrDecrypt
	}
	header := msg[:3+wl]
	nonce := msg[3+wl : 3+wl+nonceLen]
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, msg[3:3+wl], label)
	if err != nil || len(key) != 32 {
		return nil, ErrDecrypt
	}
	defer wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	secret, err := gcm.Open(nil, nonce, msg[3+wl+nonceLen:], header)
	if err != nil {
		return nil, ErrDecrypt
	}
	return secret, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
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
