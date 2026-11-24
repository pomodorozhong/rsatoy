// Command rsatoy sends a short secret to a friend so that only they can read
// it. See docs/design.md.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/term"

	"github.com/pomodorozhong/rsatoy/internal/app"
	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/guide"
	"github.com/pomodorozhong/rsatoy/internal/i18n"
	"github.com/pomodorozhong/rsatoy/internal/keys"
)

// version is set at release time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = `rsatoy: send a secret to a friend so only they can read it.

Usage:
  rsatoy [--lang en|zh-Hant]                 walk through the whole exchange
  rsatoy guide [--lang en|zh-Hant]           show the exchange chart and steps
  rsatoy init [--bits N] [--force] [--key P] make your key pair
  rsatoy pubkey [--key P]                    show your public key again
  rsatoy encrypt [--yes] <file|->            encrypt a secret for a public key
  rsatoy decrypt [--in F] [--print] [--clear-after S] [--yes] [--key P]
                                             decrypt a message sent to you
  rsatoy version                             show the version

Key sizes for --bits: 2048, 3072 (default), 4096, 8192.
More: https://github.com/pomodorozhong/rsatoy
`

type clip struct{}

func (clip) Write(s string) error  { return clipboard.WriteAll(s) }
func (clip) Read() (string, error) { return clipboard.ReadAll() }

func main() {
	colorOK := setupConsole()
	os.Exit(run(os.Args[1:], colorOK))
}

func stdinIsTerminal() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

func newIO(p i18n.Printer, out io.Writer) *app.IO {
	o := &app.IO{
		In:          bufio.NewReader(os.Stdin),
		Out:         out,
		Data:        os.Stdout,
		P:           p,
		Interactive: stdinIsTerminal(),
		Clip:        clip{},
		Sleep:       time.Sleep,
	}
	if o.Interactive {
		o.Hidden = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
	}
	return o
}

func useColor(colorOK bool) bool {
	return colorOK && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(os.Stdout.Fd()))
}

func run(args []string, colorOK bool) int {
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "":
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "-help") {
			fmt.Print(usage)
			return 0
		}
		err = runGuided(args, colorOK)
	case "guide":
		err = runGuide(args, colorOK)
	case "init":
		err = runInit(args)
	case "pubkey":
		err = runPubkey(args)
	case "encrypt":
		err = runEncrypt(args)
	case "decrypt":
		err = runDecrypt(args)
	case "version":
		fmt.Println("rsatoy", version)
		return 0
	case "help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "rsatoy: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 2
	}
	fmt.Fprintln(os.Stderr, "rsatoy:", err)
	return 1
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("rsatoy "+name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	return fs
}

func detectLang(flagVal string) (i18n.Printer, error) {
	l, err := i18n.Detect(flagVal, os.Getenv, i18n.SystemLanguages)
	return i18n.New(l), err
}

func runGuide(args []string, colorOK bool) error {
	fs := newFlags("guide")
	lang := fs.String("lang", "", "language: en or zh-Hant")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := detectLang(*lang)
	if err != nil {
		return err
	}
	fmt.Print(guide.Guide(p, useColor(colorOK)))
	return nil
}

func runGuided(args []string, colorOK bool) error {
	fs := newFlags("")
	lang := fs.String("lang", "", "language: en or zh-Hant")
	keyPath := fs.String("key", "", "use this private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := detectLang(*lang)
	if err != nil {
		return err
	}
	paths, err := keys.DefaultPaths(*keyPath)
	if err != nil {
		return err
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	g := &guide.Guided{
		IO:         newIO(p, os.Stdout),
		Color:      useColor(colorOK),
		Paths:      paths,
		Dir:        dir,
		ClearAfter: 60,
	}
	// Guided mode prints its own messages, so only report the exit code.
	if err := g.Run(); err != nil {
		os.Exit(1)
	}
	return nil
}

func english() i18n.Printer { return i18n.New(i18n.EN) }

func runInit(args []string) error {
	fs := newFlags("init")
	bits := fs.Int("bits", keys.DefaultBits, "key size in bits")
	force := fs.Bool("force", false, "replace an existing key")
	keyPath := fs.String("key", "", "use this private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := newIO(english(), os.Stderr)
	if !keys.Allowed(*bits) {
		return o.Fail(keys.ErrBadSize, "e.badsize", keys.SizesText())
	}
	paths, err := keys.DefaultPaths(*keyPath)
	if err != nil {
		return err
	}
	if paths.Exists() {
		if !*force {
			return o.Fail(nil, "e.keyexists", paths.Private)
		}
		ok, err := o.Ask("p.overwrite", paths.Private)
		if err != nil {
			return err
		}
		if !ok {
			return o.Fail(app.ErrMismatch, "g.stopped")
		}
	}
	pub, err := app.MakeKeys(o, paths, *bits)
	if err != nil {
		return err
	}
	fmt.Fprintln(o.Out)
	app.ShowPublic(o, pub)
	return nil
}

func runPubkey(args []string) error {
	fs := newFlags("pubkey")
	keyPath := fs.String("key", "", "use this private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := newIO(english(), os.Stderr)
	paths, err := keys.DefaultPaths(*keyPath)
	if err != nil {
		return err
	}
	pub, err := app.LoadPublic(o, paths)
	if err != nil {
		return err
	}
	app.ShowPublic(o, pub)
	return nil
}

func runEncrypt(args []string) error {
	fs := newFlags("encrypt")
	yes := fs.Bool("yes", false, "skip the fingerprint question")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := newIO(english(), os.Stderr)
	if fs.NArg() != 1 {
		fs.Usage()
		return flag.ErrHelp
	}
	var text string
	keyFromStdin := fs.Arg(0) == "-"
	if keyFromStdin {
		if o.Interactive {
			fmt.Fprintln(o.Out, "Paste the public key block, then press Enter:")
		}
		t, err := o.ReadBlock(armor.PublicKey, "")
		if err != nil {
			return err
		}
		text = t
	} else {
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		text = string(b)
	}
	pub, err := app.ParsePublic(o, text)
	if err != nil {
		return err
	}
	if err := app.ConfirmFingerprint(o, pub, *yes); err != nil {
		return err
	}

	var secret []byte
	switch {
	case o.Interactive:
		secret, err = app.ReadSecret(o)
	case keyFromStdin:
		return o.Fail(nil, "e.needtty")
	default:
		secret, err = io.ReadAll(io.LimitReader(o.In, 64*1024+2))
		secret = trimNewline(secret)
	}
	if err != nil {
		return err
	}
	block, id, err := app.Encrypt(o, pub, secret)
	for i := range secret {
		secret[i] = 0
	}
	if err != nil {
		return err
	}
	fmt.Fprint(o.Data, block)
	o.Say("p.id.remind", id)
	return nil
}

func trimNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

func runDecrypt(args []string) error {
	fs := newFlags("decrypt")
	in := fs.String("in", "", "read the message from this file")
	print := fs.Bool("print", false, "print the secret instead of copying it")
	clearAfter := fs.Int("clear-after", 60, "seconds before the clipboard is cleared (0: never)")
	yes := fs.Bool("yes", false, "skip the message ID question")
	keyPath := fs.String("key", "", "use this private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o := newIO(english(), os.Stderr)
	paths, err := keys.DefaultPaths(*keyPath)
	if err != nil {
		return err
	}
	var text string
	if *in != "" {
		b, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		text = string(b)
	} else {
		if o.Interactive {
			o.Say("p.paste.msg")
		}
		if text, err = o.ReadBlock(armor.Message, ""); err != nil {
			return err
		}
	}
	msg, err := app.ParseMessage(o, text)
	if err != nil {
		return err
	}
	if err := app.ConfirmMessageID(o, msg, *yes); err != nil {
		return err
	}
	secret, err := app.DecryptMessage(o, paths, msg)
	if err != nil {
		return err
	}
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	return app.Deliver(o, secret, *print, *clearAfter)
}
