// Package fpr makes the short codes people read aloud to each other: key
// fingerprints and message IDs.
package fpr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fingerprint returns the first 16 bytes of SHA-256 over a public key's DER
// bytes, as 32 hex characters in groups of four, followed by the key size,
// for example "3f2a 9c41 07be d5e8 1a6c 44f0 9b23 e7d1 (RSA 3072)".
func Fingerprint(der []byte, bits int) string {
	sum := sha256.Sum256(der)
	return fmt.Sprintf("%s (RSA %d)", group(sum[:16]), bits)
}

// MessageID returns the first 8 bytes of SHA-256 over the decoded message
// bytes, as 16 hex characters in groups of four.
func MessageID(msg []byte) string {
	sum := sha256.Sum256(msg)
	return group(sum[:8])
}

func group(b []byte) string {
	h := hex.EncodeToString(b)
	parts := make([]string, 0, len(h)/4)
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, " ")
}
