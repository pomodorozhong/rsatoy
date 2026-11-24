// Package guide draws the exchange chart in the terminal and runs guided
// mode. The chart is the terminal version of docs/exchange.svg; change both
// together.
package guide

import (
	"fmt"
	"strings"

	"golang.org/x/text/width"

	"github.com/pomodorozhong/rsatoy/internal/i18n"
)

// Risk is how careful a step needs to be, and decides its color.
type Risk int

// Risk levels, matching the diagram's gray, green, and red.
const (
	NoChannel Risk = iota
	LowRisk
	NeedsCare
)

// StepRisk gives the risk of steps 1 to 6.
var StepRisk = [7]Risk{0, NoChannel, LowRisk, NeedsCare, LowRisk, NeedsCare, NoChannel}

const (
	colLabel     = 7
	colRecipient = 25
	colBetween   = 22
	// MaxWidth is the widest a chart line may be, in terminal columns.
	MaxWidth = 80
)

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiRed   = "\x1b[31m"
	ansiGreen = "\x1b[32m"
	ansiGray  = "\x1b[90m"
)

func riskColor(r Risk) string {
	switch r {
	case LowRisk:
		return ansiGreen
	case NeedsCare:
		return ansiRed
	}
	return ansiGray
}

// DisplayWidth is how many terminal columns s takes. Wide and full-width
// characters, such as Chinese, take two.
func DisplayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch width.LookupRune(r).Kind() {
		case width.EastAsianWide, width.EastAsianFullwidth:
			n += 2
		default:
			n++
		}
	}
	return n
}

func pad(s string, w int) string {
	if d := w - DisplayWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

type row struct {
	recipient, sender []string
	between           string
}

func rows(p i18n.Printer) [7]row {
	t := p.T
	return [7]row{
		{},
		{recipient: []string{t("chart.1.r1"), t("chart.1.r2")}},
		{recipient: []string{t("chart.2.r1")}, between: t("chart.2.b"), sender: []string{t("chart.2.s1")}},
		{recipient: []string{t("chart.3.r1")}, between: t("chart.3.b"), sender: []string{t("chart.3.s1"), t("chart.3.s2")}},
		{recipient: []string{t("chart.4.r1")}, between: t("chart.4.b"), sender: []string{t("chart.4.s1"), t("chart.4.s2")}},
		{recipient: []string{t("chart.5.r1"), t("chart.5.r2")}, between: t("chart.5.b"), sender: []string{t("chart.5.s1")}},
		{recipient: []string{t("chart.6.r1"), t("chart.6.r2")}},
	}
}

// Chart draws the exchange chart. With color, step numbers and arrows are
// colored by risk. current, from 1 to 6, marks that step with ">" and dims
// the others; 0 marks none.
func Chart(p i18n.Printer, color bool, current int) string {
	paint := func(code, s string) string {
		if !color || s == "" {
			return s
		}
		return code + s + ansiReset
	}
	var b strings.Builder
	line := func(s string) { b.WriteString(strings.TrimRight(s, " ") + "\n") }

	line(strings.Repeat(" ", colLabel) + pad(p.T("chart.head.recipient"), colRecipient) +
		pad(p.T("chart.head.between"), colBetween) + p.T("chart.head.sender"))
	line(strings.Repeat(" ", colLabel) + strings.Repeat("-", 22) + "   " +
		strings.Repeat("-", 20) + "  " + strings.Repeat("-", 20))

	for step, r := range rows(p) {
		if step == 0 {
			continue
		}
		n := max(len(r.recipient), len(r.sender), 1)
		for i := 0; i < n; i++ {
			label := strings.Repeat(" ", colLabel)
			if i == 0 {
				mark := "  "
				if step == current {
					mark = "> "
				}
				label = mark + paint(riskColor(StepRisk[step]), fmt.Sprintf("[%d]", step)) + "  "
			}
			rec, snd, bet := "", "", ""
			if i < len(r.recipient) {
				rec = r.recipient[i]
			}
			if i < len(r.sender) {
				snd = r.sender[i]
			}
			if i == 0 && r.between != "" {
				// Pad before painting so color codes do not count as width.
				bet = paint(riskColor(StepRisk[step]), r.between) +
					strings.Repeat(" ", max(colBetween-DisplayWidth(r.between), 0))
			} else {
				bet = strings.Repeat(" ", colBetween)
			}
			text := strings.TrimRight(label+pad(rec, colRecipient)+bet+snd, " ")
			switch {
			case color && current > 0 && step == current:
				text = ansiBold + text + ansiReset
			case color && current > 0:
				text = ansiDim + text + ansiReset
			}
			line(text)
		}
	}
	line("")
	line("  " + paint(ansiGreen, "---->") + "  " + p.T("chart.legend.any"))
	line("  " + paint(ansiRed, "====>") + "  " + p.T("chart.legend.trusted"))
	return b.String()
}

// Guide is the text `rsatoy guide` prints: a title, the chart, the steps in
// plain words, and a tip.
func Guide(p i18n.Printer, color bool) string {
	var b strings.Builder
	title := p.T("guide.title")
	if color {
		title = ansiBold + title + ansiReset
	}
	b.WriteString(title + "\n\n")
	b.WriteString(Chart(p, color, 0))
	b.WriteString("\n")
	for i := 1; i <= 6; i++ {
		b.WriteString(p.T(fmt.Sprintf("guide.step.%d", i)) + "\n")
	}
	b.WriteString("\n" + p.T("guide.tip") + "\n")
	return b.String()
}
