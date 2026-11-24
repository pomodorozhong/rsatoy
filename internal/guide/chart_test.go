package guide

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pomodorozhong/rsatoy/internal/i18n"
)

var update = flag.Bool("update", false, "rewrite golden files")

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/guide -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%s changed. If this is deliberate, update docs/exchange.svg and run go test ./internal/guide -update.\ngot:\n%s", name, got)
	}
}

func TestChartGolden(t *testing.T) {
	for _, l := range i18n.All {
		p := i18n.New(l)
		golden(t, "chart_"+string(l)+".txt", Chart(p, false, 0))
		golden(t, "chart_"+string(l)+"_color_step3.txt", Chart(p, true, 3))
		golden(t, "guide_"+string(l)+".txt", Guide(p, false))
	}
}

func TestChartFitsEightyColumns(t *testing.T) {
	for _, l := range i18n.All {
		for step := 0; step <= 6; step++ {
			for _, color := range []bool{false, true} {
				chart := Chart(i18n.New(l), color, step)
				for _, line := range strings.Split(chart, "\n") {
					if w := DisplayWidth(ansi.ReplaceAllString(line, "")); w > MaxWidth {
						t.Errorf("%s step %d: line is %d columns: %q", l, step, w, line)
					}
				}
			}
		}
	}
}

// TestColumnsLineUp checks every arrow starts in the same column, measured
// by display width, so Chinese text does not push the chart out of shape.
func TestColumnsLineUp(t *testing.T) {
	for _, l := range i18n.All {
		for _, line := range strings.Split(Chart(i18n.New(l), false, 0), "\n") {
			i := strings.IndexAny(line, "<=-")
			if i < 0 || !strings.HasPrefix(line, "  [") {
				continue
			}
			if col := DisplayWidth(line[:i]); col != colLabel+colRecipient {
				t.Errorf("%s: arrow starts at column %d, want %d: %q", l, col, colLabel+colRecipient, line)
			}
		}
	}
}

func TestCurrentStepMarked(t *testing.T) {
	chart := Chart(i18n.New(i18n.EN), false, 4)
	if !strings.Contains(chart, "> [4]") || strings.Contains(chart, "> [3]") {
		t.Fatalf("step 4 not marked:\n%s", chart)
	}
}

func TestDisplayWidth(t *testing.T) {
	cases := map[string]int{"abc": 3, "訊息": 4, "訊息 ID": 7, "（你）": 6, "，": 2}
	for s, want := range cases {
		if got := DisplayWidth(s); got != want {
			t.Errorf("DisplayWidth(%q) = %d, want %d", s, got, want)
		}
	}
}

// TestDocsShowSameChart checks the charts in docs/design.md match what
// rsatoy prints, so the docs cannot drift from the program.
func TestDocsShowSameChart(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "design.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range i18n.All {
		if !strings.Contains(string(doc), "```text\n"+Chart(i18n.New(l), false, 0)+"```") {
			t.Errorf("docs/design.md does not show the current %s chart", l)
		}
	}
}
