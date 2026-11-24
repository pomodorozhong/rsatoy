package armor

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{1, 47, 48, 49, 100, 1000} {
		data := bytes.Repeat([]byte{0xab, 0x01, 0xff}, n)
		block := Encode(Message, data)
		for _, line := range strings.Split(strings.TrimSpace(block), "\n") {
			if len(line) > lineLen && !strings.HasPrefix(line, "-----") {
				t.Fatalf("line longer than %d: %q", lineLen, line)
			}
		}
		got, err := Decode(Message, block)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("n=%d: round trip failed: %v", n, err)
		}
	}
}

func TestFindsBlockInsideText(t *testing.T) {
	data := []byte("hello there, this is test data")
	block := Encode(Message, data)
	text := "Hi,\n\nhere it is:\n\n" + block + "\nThanks!\n-- \nsignature\n"
	got, err := Decode(Message, text)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestQuotedEmailReply(t *testing.T) {
	data := bytes.Repeat([]byte("quoted"), 30)
	block := Encode(Message, data)
	var b strings.Builder
	for _, line := range strings.Split(block, "\n") {
		b.WriteString("> " + line + "\r\n")
	}
	got, err := Decode(Message, b.String())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWrongLabelNotFound(t *testing.T) {
	block := Encode(PublicKey, []byte("key"))
	if _, err := Decode(Message, block); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestMissingEnd(t *testing.T) {
	block := Encode(Message, []byte("data data data"))
	cut := block[:strings.Index(block, "-----END")]
	if _, err := Decode(Message, cut); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}

func TestBadBase64(t *testing.T) {
	text := "-----BEGIN RSATOY MESSAGE-----\n!!!not base64!!!\n-----END RSATOY MESSAGE-----\n"
	if _, err := Decode(Message, text); !errors.Is(err, ErrBadData) {
		t.Fatalf("got %v, want ErrBadData", err)
	}
}

func TestHasEnd(t *testing.T) {
	block := Encode(Message, []byte("x"))
	if !HasEnd(Message, block) || HasEnd(Message, block[:10]) {
		t.Fatal("HasEnd wrong")
	}
}
