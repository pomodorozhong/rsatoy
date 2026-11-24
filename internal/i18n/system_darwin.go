package i18n

import (
	"os/exec"
	"regexp"
)

var quoted = regexp.MustCompile(`"([^"]+)"|([A-Za-z]{2,3}(?:-[A-Za-z0-9]+)*)`)

// SystemLanguages returns the user's preferred languages from macOS, most
// preferred first. A program started by double-clicking may get no LANG, so
// this is read from the system settings instead.
func SystemLanguages() []string {
	out, err := exec.Command("/usr/bin/defaults", "read", "-g", "AppleLanguages").Output()
	if err != nil {
		return nil
	}
	return parseAppleLanguages(string(out))
}

// parseAppleLanguages reads output such as:
//
//	(
//	    "zh-Hant-TW",
//	    "en-TW"
//	)
func parseAppleLanguages(s string) []string {
	var langs []string
	for _, m := range quoted.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			langs = append(langs, m[1])
		} else if m[2] != "" {
			langs = append(langs, m[2])
		}
	}
	return langs
}
