// Package app holds the steps that both the commands and guided mode run:
// making keys, checking fingerprints and message IDs, encrypting, and
// decrypting. Keeping them in one place means the checks are identical
// everywhere.
package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pomodorozhong/rsatoy/internal/armor"
	"github.com/pomodorozhong/rsatoy/internal/i18n"
)

// Clipboard reads and writes the system clipboard.
type Clipboard interface {
	Write(string) error
	Read() (string, error)
}

// IO is everything a step needs to talk to the person.
type IO struct {
	In   *bufio.Reader
	Out  io.Writer // prompts and explanations
	Data io.Writer // blocks and other output meant to be saved or piped
	P    i18n.Printer

	// Interactive is true when In is a terminal, so questions can be asked.
	Interactive bool
	// Hidden reads one line without echoing it. When nil, lines are read
	// from In instead.
	Hidden func() ([]byte, error)
	Clip   Clipboard
	Sleep  func(time.Duration)
}

// ErrMismatch means a fingerprint or message ID check was answered no.
var ErrMismatch = errors.New("check did not match")

// Failure is an error with a message ready to show the person.
type Failure struct {
	Msg  string
	Kind error
}

func (f *Failure) Error() string { return f.Msg }
func (f *Failure) Unwrap() error { return f.Kind }

// Fail returns a Failure with the translated message id.
func (o *IO) Fail(kind error, id string, args ...any) error {
	return &Failure{Msg: o.P.T(id, args...), Kind: kind}
}

// Say prints the translated message id on its own line.
func (o *IO) Say(id string, args ...any) {
	fmt.Fprintln(o.Out, o.P.T(id, args...))
}

// ReadLine reads one line from In without its line ending.
func (o *IO) ReadLine() (string, error) {
	line, err := o.In.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Ask prints a yes or no question and reports whether the answer was yes.
// Anything but y or yes counts as no.
func (o *IO) Ask(id string, args ...any) (bool, error) {
	fmt.Fprint(o.Out, o.P.T(id, args...))
	line, err := o.ReadLine()
	if err != nil {
		fmt.Fprintln(o.Out)
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// ReadHidden prints a prompt and reads one line without echo.
func (o *IO) ReadHidden(id string) ([]byte, error) {
	fmt.Fprint(o.Out, o.P.T(id))
	if o.Hidden == nil {
		line, err := o.ReadLine()
		if !o.Interactive {
			// Piped input is not echoed, so end the prompt's line here.
			fmt.Fprintln(o.Out)
		}
		return []byte(line), err
	}
	b, err := o.Hidden()
	fmt.Fprintln(o.Out)
	return b, err
}

// ReadBlock reads lines from In until the END line for label, and returns
// everything read. first, when not empty, is a line already read.
func (o *IO) ReadBlock(label, first string) (string, error) {
	var b strings.Builder
	if first != "" {
		b.WriteString(first)
		b.WriteByte('\n')
	}
	for !armor.HasEnd(label, b.String()) {
		line, err := o.In.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	return b.String(), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
