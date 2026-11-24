package guide

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pomodorozhong/rsatoy/internal/app"
	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/keys"
)

// Guided runs the step-by-step walk through the exchange.
type Guided struct {
	IO *app.IO
	// Color turns on ANSI colors and clearing the screen between steps.
	Color bool
	// Paths says where the recipient's key files are.
	Paths keys.Paths
	// Dir is where the sender saves the recipient's public key.
	Dir string
	// ClearAfter is how many seconds the secret stays on the clipboard.
	ClearAfter int
}

// Run asks for the role, walks through its steps, and waits for Enter at
// the end so a window opened by double-clicking does not vanish.
func (g *Guided) Run() error {
	o := g.IO
	g.clear()
	o.Say("g.welcome")
	fmt.Fprintln(o.Out)
	err := g.pickRole()
	var f *app.Failure
	switch {
	case errors.As(err, &f):
		fmt.Fprintln(o.Out)
		fmt.Fprintln(o.Out, f.Msg)
		o.Say("g.stopped")
	case errors.Is(err, io.EOF):
		fmt.Fprintln(o.Out)
		o.Say("g.stopped")
		return nil
	case err != nil:
		fmt.Fprintln(o.Out)
		fmt.Fprintln(o.Out, err)
		o.Say("g.stopped")
	}
	fmt.Fprintln(o.Out)
	fmt.Fprint(o.Out, o.P.T("g.close"))
	_, _ = o.ReadLine()
	return err
}

func (g *Guided) pickRole() error {
	o := g.IO
	for {
		fmt.Fprint(o.Out, o.P.T("g.role"))
		line, err := o.ReadLine()
		if err != nil {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "r":
			return g.recipient()
		case "s":
			return g.sender()
		}
		o.Say("g.role.bad")
	}
}

func (g *Guided) clear() {
	if g.Color {
		fmt.Fprint(g.IO.Out, "\x1b[H\x1b[2J")
	}
}

// show starts a step: the chart with this step marked, the step number, and
// what to do.
func (g *Guided) show(step int, id string, args ...any) {
	o := g.IO
	g.clear()
	fmt.Fprint(o.Out, Chart(o.P, g.Color, step))
	fmt.Fprintln(o.Out)
	head := o.P.T("g.step", step)
	if g.Color {
		head = ansiBold + riskColor(StepRisk[step]) + head + ansiReset
	}
	fmt.Fprintln(o.Out, head)
	o.Say(id, args...)
	fmt.Fprintln(o.Out)
}

func (g *Guided) pause() error {
	fmt.Fprintln(g.IO.Out)
	fmt.Fprint(g.IO.Out, g.IO.P.T("g.enter"))
	_, err := g.IO.ReadLine()
	return err
}

func (g *Guided) offerCopy(text string) error {
	o := g.IO
	ok, err := o.Ask("g.copy")
	if err != nil || !ok {
		return err
	}
	if err := o.Clip.Write(text); err != nil {
		return o.Fail(err, "e.clipboard", err)
	}
	o.Say("g.copied")
	return nil
}

func (g *Guided) recipient() error {
	o := g.IO

	g.show(1, "g.r1.what")
	if g.Paths.Exists() {
		o.Say("g.r1.exists")
	} else {
		if _, err := app.MakeKeys(o, g.Paths, keys.DefaultBits); err != nil {
			return err
		}
		o.Say("g.r1.done")
	}
	if err := g.pause(); err != nil {
		return err
	}

	pub, err := app.LoadPublic(o, g.Paths)
	if err != nil {
		return err
	}
	g.show(2, "g.r2.what")
	fmt.Fprint(o.Out, pub.Armor())
	fmt.Fprintln(o.Out)
	if err := g.offerCopy(pub.Armor()); err != nil {
		return err
	}
	if err := g.pause(); err != nil {
		return err
	}

	g.show(3, "g.r3.what")
	o.Say("g.r3.fpr", pub.Fingerprint)
	if err := g.pause(); err != nil {
		return err
	}

	g.show(4, "g.r4.what")
	if err := g.pause(); err != nil {
		return err
	}

	g.show(5, "g.r5.what")
	o.Say("p.paste.msg")
	text, err := o.ReadBlock(armor.Message, "")
	if err != nil {
		return err
	}
	msg, err := app.ParseMessage(o, text)
	if err != nil {
		return err
	}
	fmt.Fprintln(o.Out)
	if err := app.ConfirmMessageID(o, msg, false); err != nil {
		return err
	}

	g.show(6, "g.r6.what")
	secret, err := app.DecryptMessage(o, g.Paths, msg)
	if err != nil {
		return err
	}
	defer wipe(secret)
	if err := app.Deliver(o, secret, false, g.ClearAfter); err != nil {
		return err
	}
	o.Say("g.r6.done")
	return nil
}

func (g *Guided) sender() error {
	o := g.IO

	g.show(2, "g.s2.what")
	o.Say("g.s2.paste")
	first, err := o.ReadLine()
	if err != nil {
		return err
	}
	var text string
	if strings.Contains(first, "-----BEGIN") {
		if text, err = o.ReadBlock(armor.PublicKey, first); err != nil {
			return err
		}
	} else {
		b, err := os.ReadFile(strings.Trim(strings.TrimSpace(first), `"'`))
		if err != nil {
			return o.Fail(err, "e.nopub")
		}
		text = string(b)
	}
	pub, err := app.ParsePublic(o, text)
	if err != nil {
		return err
	}
	path := filepath.Join(g.Dir, "friend.pub")
	if err := os.WriteFile(path, []byte(pub.Armor()), 0o644); err != nil {
		return err
	}
	fmt.Fprintln(o.Out)
	o.Say("g.s2.saved", path)
	if err := g.pause(); err != nil {
		return err
	}

	g.show(3, "g.s3.what")
	if err := app.ConfirmFingerprint(o, pub, false); err != nil {
		return err
	}

	g.show(4, "g.s4.what")
	secret, err := app.ReadSecret(o)
	if err != nil {
		return err
	}
	block, id, err := app.Encrypt(o, pub, secret)
	wipe(secret)
	if err != nil {
		return err
	}
	fmt.Fprintln(o.Out)
	o.Say("g.s4.send")
	fmt.Fprintln(o.Out)
	fmt.Fprint(o.Out, block)
	fmt.Fprintln(o.Out)
	o.Say("g.s4.id", id)
	o.Say("g.s4.keep")
	fmt.Fprintln(o.Out)
	if err := g.offerCopy(block); err != nil {
		return err
	}
	if err := g.pause(); err != nil {
		return err
	}

	g.show(5, "g.s5.what", id)
	ok, err := o.Ask("g.s5.ask")
	if err != nil {
		return err
	}
	if !ok {
		return o.Fail(app.ErrMismatch, "g.s5.mismatch")
	}

	g.show(6, "g.s6.what")
	return nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
