package app

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/fpr"
	"github.com/pomodorozhong/rsatoy/internal/keys"
	"github.com/pomodorozhong/rsatoy/internal/message"
)

// NewPassphrase asks for a new passphrase twice.
func NewPassphrase(o *IO) ([]byte, error) {
	a, err := o.ReadHidden("p.pass.new")
	if err != nil {
		return nil, err
	}
	if len(a) == 0 {
		return nil, o.Fail(nil, "p.pass.empty")
	}
	b, err := o.ReadHidden("p.pass.again")
	if err != nil {
		wipe(a)
		return nil, err
	}
	defer wipe(b)
	if !bytes.Equal(a, b) {
		wipe(a)
		return nil, o.Fail(nil, "p.pass.mismatch")
	}
	return a, nil
}

// MakeKeys asks for a passphrase, makes a key pair, and saves it.
func MakeKeys(o *IO, paths keys.Paths, bits int) (*keys.Public, error) {
	if !keys.Allowed(bits) {
		return nil, o.Fail(keys.ErrBadSize, "e.badsize", keys.SizesText())
	}
	pass, err := NewPassphrase(o)
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	if bits >= 4096 {
		o.Say("p.making", bits)
	}
	k, err := keys.Generate(bits)
	if err != nil {
		return nil, err
	}
	pub, err := keys.NewPublic(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	sealed, err := keys.SealPrivate(k, pass)
	if err != nil {
		return nil, err
	}
	if err := paths.Save(sealed, pub.Armor()); err != nil {
		return nil, err
	}
	o.Say("p.saved", paths.Private)
	return pub, nil
}

// ShowPublic prints the public key block and its fingerprint.
func ShowPublic(o *IO, pub *keys.Public) {
	fmt.Fprintln(o.Data, o.P.T("p.pub.intro"))
	fmt.Fprintln(o.Data)
	fmt.Fprint(o.Data, pub.Armor())
	fmt.Fprintln(o.Data)
	fmt.Fprintln(o.Data, o.P.T("p.pub.fpr", pub.Fingerprint))
	fmt.Fprintln(o.Data, o.P.T("p.pub.read"))
}

// LoadPublic reads the person's own public key, with a friendly error when
// there is none.
func LoadPublic(o *IO, paths keys.Paths) (*keys.Public, error) {
	pub, err := paths.LoadPublic()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, o.Fail(err, "e.nokey")
	}
	return pub, err
}

// ParsePublic parses a public key block someone pasted or saved.
func ParsePublic(o *IO, text string) (*keys.Public, error) {
	pub, err := keys.ParsePublic(text)
	switch {
	case errors.Is(err, keys.ErrBadSize):
		return nil, o.Fail(err, "e.badsize", keys.SizesText())
	case err != nil:
		return nil, o.Fail(err, "e.nopub")
	}
	return pub, nil
}

// ConfirmFingerprint shows a key's fingerprint and asks whether it matches
// what the recipient read out. yes skips the question.
func ConfirmFingerprint(o *IO, pub *keys.Public, yes bool) error {
	o.Say("p.fpr.show", pub.Fingerprint)
	if yes {
		return nil
	}
	if !o.Interactive {
		return o.Fail(nil, "e.needtty")
	}
	ok, err := o.Ask("p.fpr.ask")
	if err != nil {
		return err
	}
	if !ok {
		return o.Fail(ErrMismatch, "e.mismatch")
	}
	return nil
}

// ReadSecret reads the secret at a hidden prompt.
func ReadSecret(o *IO) ([]byte, error) {
	s, err := o.ReadHidden("p.secret")
	if err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, o.Fail(message.ErrEmpty, "e.empty")
	}
	return s, nil
}

// Encrypt encrypts secret to pub and returns the message block and its ID.
func Encrypt(o *IO, pub *keys.Public, secret []byte) (block, id string, err error) {
	msg, err := message.Encrypt(pub.Key, secret)
	switch {
	case errors.Is(err, message.ErrTooLarge):
		return "", "", o.Fail(err, "e.toolarge")
	case errors.Is(err, message.ErrEmpty):
		return "", "", o.Fail(err, "e.empty")
	case err != nil:
		return "", "", err
	}
	return armor.Encode(armor.Message, msg), fpr.MessageID(msg), nil
}

// ParseMessage finds the message block in text.
func ParseMessage(o *IO, text string) ([]byte, error) {
	msg, err := armor.Decode(armor.Message, text)
	if err != nil {
		return nil, o.Fail(err, "e.nomsg")
	}
	return msg, nil
}

// ConfirmMessageID shows the message ID and asks whether the sender said it
// matches. yes skips the question.
func ConfirmMessageID(o *IO, msg []byte, yes bool) error {
	o.Say("p.id.show", fpr.MessageID(msg))
	if yes {
		return nil
	}
	if !o.Interactive {
		return o.Fail(nil, "e.needtty")
	}
	ok, err := o.Ask("p.id.ask")
	if err != nil {
		return err
	}
	if !ok {
		return o.Fail(ErrMismatch, "e.mismatch")
	}
	return nil
}

// DecryptMessage asks for the passphrase and decrypts msg.
func DecryptMessage(o *IO, paths keys.Paths, msg []byte) ([]byte, error) {
	if !paths.Exists() {
		return nil, o.Fail(fs.ErrNotExist, "e.nokey")
	}
	pass, err := o.ReadHidden("p.pass")
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	priv, err := paths.LoadPrivate(pass)
	switch {
	case errors.Is(err, keys.ErrWrongPassphrase), errors.Is(err, keys.ErrBadKeyFile):
		return nil, o.Fail(err, "e.wrongpass")
	case err != nil:
		return nil, err
	}
	secret, err := message.Decrypt(priv, msg)
	switch {
	case errors.Is(err, message.ErrVersion):
		return nil, o.Fail(err, "e.version")
	case err != nil:
		return nil, o.Fail(err, "e.decrypt")
	}
	return secret, nil
}

// Deliver hands the secret over: printed when print is true, otherwise put
// on the clipboard and cleared after clearAfter seconds (0 means never).
func Deliver(o *IO, secret []byte, print bool, clearAfter int) error {
	if print {
		_, err := fmt.Fprintln(o.Data, string(secret))
		return err
	}
	s := string(secret)
	if err := o.Clip.Write(s); err != nil {
		return o.Fail(err, "e.clipboard", err)
	}
	o.Say("p.clip.copied")
	if clearAfter <= 0 {
		return nil
	}
	o.Say("p.clip.wait", clearAfter)
	o.Sleep(time.Duration(clearAfter) * time.Second)
	if cur, err := o.Clip.Read(); err == nil && cur == s {
		if err := o.Clip.Write(""); err == nil {
			o.Say("p.clip.cleared")
		}
	}
	return nil
}
