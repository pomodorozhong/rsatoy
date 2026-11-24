package fpr

import (
	"regexp"
	"testing"
)

func TestFingerprintFormat(t *testing.T) {
	got := Fingerprint([]byte("some der bytes"), 3072)
	if !regexp.MustCompile(`^([0-9a-f]{4} ){7}[0-9a-f]{4} \(RSA 3072\)$`).MatchString(got) {
		t.Fatalf("bad fingerprint %q", got)
	}
	if got != Fingerprint([]byte("some der bytes"), 3072) {
		t.Fatal("fingerprint not stable")
	}
	if got == Fingerprint([]byte("other der bytes"), 3072) {
		t.Fatal("different keys gave the same fingerprint")
	}
}

func TestMessageIDFormat(t *testing.T) {
	got := MessageID([]byte("message"))
	if !regexp.MustCompile(`^([0-9a-f]{4} ){3}[0-9a-f]{4}$`).MatchString(got) {
		t.Fatalf("bad message ID %q", got)
	}
	if got == MessageID([]byte("message2")) {
		t.Fatal("different messages gave the same ID")
	}
}
