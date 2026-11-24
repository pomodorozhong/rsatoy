// Package i18n picks the guide's language and looks up its strings.
//
// Only guided mode and `rsatoy guide` follow the system language. The plain
// commands always use English.
package i18n

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/text/language"
)

// Lang is a supported language.
type Lang string

// Supported languages.
const (
	EN Lang = "en"
	ZH Lang = "zh-Hant"
)

// All lists the supported languages.
var All = []Lang{EN, ZH}

//go:embed en.json zh-Hant.json
var files embed.FS

var catalogs = map[Lang]map[string]string{}

func init() {
	for _, l := range All {
		b, err := files.ReadFile(string(l) + ".json")
		if err != nil {
			panic(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			panic(fmt.Sprintf("i18n: %s.json: %v", l, err))
		}
		catalogs[l] = m
	}
}

// Catalog returns the strings for l. Tests use it to compare catalogs.
func Catalog(l Lang) map[string]string { return catalogs[l] }

// Printer looks up strings in one language.
type Printer struct{ Lang Lang }

// New returns a Printer for l.
func New(l Lang) Printer { return Printer{Lang: l} }

// T returns the string with this id, formatted with args when given.
func (p Printer) T(id string, args ...any) string {
	s, ok := catalogs[p.Lang][id]
	if !ok {
		s, ok = catalogs[EN][id]
	}
	if !ok {
		return "[" + id + "]"
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// ErrUnknownLang means a --lang or RSATOY_LANG value is not supported.
var ErrUnknownLang = errors.New("unknown language: use en or zh-Hant")

// Parse reads an explicit choice such as "en" or "zh-Hant".
func Parse(s string) (Lang, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "en":
		return EN, nil
	case "zh-hant":
		return ZH, nil
	}
	return "", ErrUnknownLang
}

// FromLocale maps a locale such as "zh_TW.UTF-8", "zh-Hant-TW" or "en-US" to
// a supported language. ok is false when s says nothing usable (empty, C,
// POSIX, or unparseable). Only Chinese written in Traditional script maps to
// ZH; everything else, Simplified Chinese included, maps to EN.
func FromLocale(s string) (l Lang, ok bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, ".@"); i >= 0 {
		s = s[:i]
	}
	if s == "" || s == "C" || s == "POSIX" {
		return "", false
	}
	tag, err := language.Parse(strings.ReplaceAll(s, "_", "-"))
	if err != nil {
		return "", false
	}
	base, _ := tag.Base()
	if base.String() != "zh" {
		return EN, true
	}
	script, _ := tag.Script()
	if script.String() == "Hant" {
		return ZH, true
	}
	return EN, true
}

// Detect picks the guide language. The first source that gives an answer
// wins: the flag, RSATOY_LANG, LC_ALL, LC_MESSAGES, LANG, the system's
// preferred UI languages, then English.
func Detect(flag string, getenv func(string) string, system func() []string) (Lang, error) {
	if flag != "" {
		return Parse(flag)
	}
	if v := getenv("RSATOY_LANG"); v != "" {
		return Parse(v)
	}
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if l, ok := FromLocale(getenv(name)); ok {
			return l, nil
		}
	}
	if system != nil {
		for _, s := range system() {
			if l, ok := FromLocale(s); ok {
				return l, nil
			}
		}
	}
	return EN, nil
}
