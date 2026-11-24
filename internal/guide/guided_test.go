package guide

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pomodorozhong/rsatoy/internal/app"
	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/i18n"
	"github.com/pomodorozhong/rsatoy/internal/keys"
)

type fakeClip struct{ text string }

func (c *fakeClip) Write(s string) error  { c.text = s; return nil }
func (c *fakeClip) Read() (string, error) { return c.text, nil }

func newGuided(t *testing.T, lang i18n.Lang, input string, paths keys.Paths) (*Guided, *bytes.Buffer, *fakeClip) {
	t.Helper()
	out := &bytes.Buffer{}
	clip := &fakeClip{}
	o := &app.IO{
		In:          bufio.NewReader(strings.NewReader(input)),
		Out:         out,
		Data:        out,
		P:           i18n.New(lang),
		Interactive: true,
		Clip:        clip,
		Sleep:       func(time.Duration) {},
	}
	return &Guided{IO: o, Paths: paths, Dir: t.TempDir(), ClearAfter: 0}, out, clip
}

func lines(s ...string) string { return strings.Join(s, "\n") + "\n" }

// TestFullExchange runs the recipient's guide twice around the sender's:
// first to make keys, then to decrypt the sender's message.
func TestFullExchange(t *testing.T) {
	for _, lang := range i18n.All {
		t.Run(string(lang), func(t *testing.T) {
			paths, _ := keys.DefaultPaths(filepath.Join(t.TempDir(), "key"))

			// Recipient, first run: make keys, copy the public key, stop at
			// step 5 because no message has arrived yet (end of input).
			g, out, clip := newGuided(t, lang, lines(
				"r",        // role
				"pw", "pw", // passphrase twice
				"",         // step 1 pause
				"y",        // copy public key
				"", "", "", // pauses for steps 2, 3, 4
			), paths)
			_ = g.Run()
			pubBlock := clip.text
			if !strings.Contains(pubBlock, "BEGIN RSATOY PUBLIC KEY") {
				t.Fatalf("public key not copied; output:\n%s", out)
			}
			pub, _ := paths.LoadPublic()
			if !strings.Contains(out.String(), pub.Fingerprint) {
				t.Fatal("fingerprint not shown to recipient")
			}

			// Sender: paste the key, confirm the fingerprint, type the
			// secret, copy the message, confirm the message ID.
			g, out, clip = newGuided(t, lang, lines(
				"s",
				strings.TrimRight(pubBlock, "\n"),
				"",         // step 2 pause
				"y",        // fingerprint matches
				"sk-12345", // secret
				"y",        // copy message block
				"",         // step 4 pause
				"y",        // message ID matches
				"",         // close
			), paths)
			if err := g.Run(); err != nil {
				t.Fatalf("sender: %v\n%s", err, out)
			}
			msgBlock := clip.text
			if !strings.Contains(msgBlock, "BEGIN RSATOY MESSAGE") {
				t.Fatalf("message not copied; output:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(g.Dir, "friend.pub")); err != nil {
				t.Fatalf("friend.pub not saved: %v", err)
			}
			if strings.Contains(out.String(), "sk-12345") {
				t.Fatal("sender output shows the secret")
			}

			// Recipient, second run: key exists, so step 1 is skipped.
			g, out, clip = newGuided(t, lang, lines(
				"r",
				"",         // step 1 pause
				"n",        // do not copy public key
				"", "", "", // pauses for steps 2, 3, 4
				strings.TrimRight(msgBlock, "\n"),
				"y",  // message ID matches
				"pw", // passphrase
				"",   // close
			), paths)
			if err := g.Run(); err != nil {
				t.Fatalf("recipient: %v\n%s", err, out)
			}
			if clip.text != "sk-12345" {
				t.Fatalf("clipboard has %q, want the secret; output:\n%s", clip.text, out)
			}
			if !strings.Contains(out.String(), i18n.New(lang).T("g.r1.exists")) {
				t.Fatal("step 1 was not skipped")
			}
		})
	}
}

func TestSenderStopsOnFingerprintMismatch(t *testing.T) {
	paths, _ := keys.DefaultPaths(filepath.Join(t.TempDir(), "key"))
	k, _ := keys.Generate(2048)
	pub, _ := keys.NewPublic(&k.PublicKey)
	_ = paths
	g, out, _ := newGuided(t, i18n.EN, lines(
		"s",
		strings.TrimRight(pub.Armor(), "\n"),
		"",
		"n", // fingerprint does not match
		"",  // close
	), paths)
	err := g.Run()
	if !errors.Is(err, app.ErrMismatch) {
		t.Fatalf("got %v, want ErrMismatch", err)
	}
	if strings.Contains(out.String(), "Secret (hidden)") {
		t.Fatal("asked for the secret after a mismatch")
	}
}

func TestRecipientStopsOnMessageIDMismatch(t *testing.T) {
	paths, _ := keys.DefaultPaths(filepath.Join(t.TempDir(), "key"))
	k, _ := keys.Generate(2048)
	pub, _ := keys.NewPublic(&k.PublicKey)
	file, _ := keys.SealPrivate(k, []byte("pw"))
	_ = paths.Save(file, pub.Armor())
	block := armor.Encode(armor.Message, []byte("not really a message"))
	g, out, clip := newGuided(t, i18n.EN, lines(
		"r", "", "n", "", "", "",
		strings.TrimRight(block, "\n"),
		"n", // ID does not match
		"",
	), paths)
	if err := g.Run(); !errors.Is(err, app.ErrMismatch) {
		t.Fatalf("got %v, want ErrMismatch", err)
	}
	if strings.Contains(out.String(), "Passphrase:") || clip.text != "" {
		t.Fatal("went on to decrypt after a mismatch")
	}
}

func TestRoleIsAskedAgain(t *testing.T) {
	g, out, _ := newGuided(t, i18n.EN, lines("x", ""), keys.Paths{})
	_ = g.Run()
	if !strings.Contains(out.String(), "Please type r or s.") {
		t.Fatal("bad role answer not handled")
	}
}
