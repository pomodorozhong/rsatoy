// Package armor turns binary data into BEGIN/END text blocks and back.
//
// Blocks use standard base64 with padding, wrapped at 64 characters, so they
// survive email, chat apps, and copy-paste. Decoding ignores whitespace and
// any text outside the BEGIN and END lines.
package armor

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Labels used by rsatoy.
const (
	PublicKey  = "RSATOY PUBLIC KEY"
	PrivateKey = "RSATOY PRIVATE KEY"
	Message    = "RSATOY MESSAGE"
)

const lineLen = 64

// ErrNotFound means the text has no complete block with the wanted label.
var ErrNotFound = errors.New("armor: block not found")

// ErrBadData means the block was found but its body is not valid base64.
var ErrBadData = errors.New("armor: block is damaged")

func begin(label string) string { return "-----BEGIN " + label + "-----" }
func end(label string) string   { return "-----END " + label + "-----" }

// Encode wraps data in a block with the given label. The result ends with a
// newline.
func Encode(label string, data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	b.WriteString(begin(label))
	b.WriteByte('\n')
	for len(enc) > lineLen {
		b.WriteString(enc[:lineLen])
		b.WriteByte('\n')
		enc = enc[lineLen:]
	}
	if enc != "" {
		b.WriteString(enc)
		b.WriteByte('\n')
	}
	b.WriteString(end(label))
	b.WriteByte('\n')
	return b.String()
}

// Decode finds the first block with the given label in text and returns its
// data.
func Decode(label, text string) ([]byte, error) {
	start := strings.Index(text, begin(label))
	if start < 0 {
		return nil, ErrNotFound
	}
	body := text[start+len(begin(label)):]
	stop := strings.Index(body, end(label))
	if stop < 0 {
		return nil, ErrNotFound
	}
	body = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '>':
			// '>' lets a block quoted in an email reply still decode.
			return -1
		}
		return r
	}, body[:stop])
	data, err := base64.StdEncoding.DecodeString(body)
	if err != nil || len(data) == 0 {
		return nil, ErrBadData
	}
	return data, nil
}

// HasEnd reports whether text contains the END line for label. Readers use it
// to know when a pasted block is complete.
func HasEnd(label, text string) bool {
	return strings.Contains(text, end(label))
}
