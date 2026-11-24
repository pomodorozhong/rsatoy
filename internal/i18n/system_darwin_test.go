package i18n

import (
	"reflect"
	"testing"
)

func TestParseAppleLanguages(t *testing.T) {
	out := "(\n    \"zh-Hant-TW\",\n    \"en-TW\",\n    en\n)\n"
	want := []string{"zh-Hant-TW", "en-TW", "en"}
	if got := parseAppleLanguages(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
