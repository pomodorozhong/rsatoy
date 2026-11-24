package i18n

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func keysOf(m map[string]string) []string {
	var k []string
	for id := range m {
		k = append(k, id)
	}
	sort.Strings(k)
	return k
}

func TestCatalogsHaveSameIDs(t *testing.T) {
	en, zh := keysOf(Catalog(EN)), keysOf(Catalog(ZH))
	if !reflect.DeepEqual(en, zh) {
		t.Fatalf("catalogs differ:\nen: %v\nzh-Hant: %v", en, zh)
	}
}

var verb = regexp.MustCompile(`%[-+# 0]*[0-9]*(?:\.[0-9]+)?[a-zA-Z%]`)

func TestCatalogsHaveSameVerbs(t *testing.T) {
	for id, s := range Catalog(EN) {
		a := verb.FindAllString(s, -1)
		b := verb.FindAllString(Catalog(ZH)[id], -1)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: en has %v, zh-Hant has %v", id, a, b)
		}
	}
}

// TestUsedIDsExist checks every message ID the code looks up is in the
// catalog, so a typo cannot show "[id]" to a user.
func TestUsedIDsExist(t *testing.T) {
	id := regexp.MustCompile(`"((?:chart|guide|g|p|e)\.[a-z0-9.]+)"`)
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range id.FindAllStringSubmatch(string(b), -1) {
			if _, ok := Catalog(EN)[m[1]]; !ok {
				t.Errorf("%s uses unknown message %q", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFromLocale(t *testing.T) {
	cases := []struct {
		in   string
		want Lang
		ok   bool
	}{
		{"zh_TW.UTF-8", ZH, true},
		{"zh-TW", ZH, true},
		{"zh-HK", ZH, true},
		{"zh-MO", ZH, true},
		{"zh-Hant", ZH, true},
		{"zh-Hant-TW", ZH, true},
		{"zh-Hans", EN, true},
		{"zh-CN", EN, true},
		{"zh_CN.UTF-8", EN, true},
		{"zh-SG", EN, true},
		{"zh", EN, true},
		{"en_US.UTF-8", EN, true},
		{"en-GB", EN, true},
		{"fr_FR", EN, true},
		{"ja-JP", EN, true},
		{"", "", false},
		{"C", "", false},
		{"C.UTF-8", "", false},
		{"POSIX", "", false},
		{"%%%", "", false},
	}
	for _, c := range cases {
		got, ok := FromLocale(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("FromLocale(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDetectOrder(t *testing.T) {
	sysZH := func() []string { return []string{"zh-Hant-TW", "en"} }
	sysEN := func() []string { return []string{"en-US"} }
	cases := []struct {
		name   string
		flag   string
		env    map[string]string
		system func() []string
		want   Lang
	}{
		{"flag wins", "en", map[string]string{"RSATOY_LANG": "zh-Hant", "LANG": "zh_TW.UTF-8"}, sysZH, EN},
		{"RSATOY_LANG next", "", map[string]string{"RSATOY_LANG": "zh-hant", "LANG": "en_US.UTF-8"}, sysEN, ZH},
		{"LC_ALL before LANG", "", map[string]string{"LC_ALL": "zh_TW.UTF-8", "LANG": "en_US.UTF-8"}, sysEN, ZH},
		{"LC_MESSAGES before LANG", "", map[string]string{"LC_MESSAGES": "en_US.UTF-8", "LANG": "zh_TW.UTF-8"}, sysZH, EN},
		{"LANG", "", map[string]string{"LANG": "zh_HK.UTF-8"}, sysEN, ZH},
		{"C is skipped", "", map[string]string{"LANG": "C"}, sysZH, ZH},
		{"system", "", nil, sysZH, ZH},
		{"system English", "", nil, sysEN, EN},
		{"nothing", "", nil, nil, EN},
	}
	for _, c := range cases {
		got, err := Detect(c.flag, env(c.env), c.system)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestDetectUnknown(t *testing.T) {
	if _, err := Detect("fr", env(nil), nil); !errors.Is(err, ErrUnknownLang) {
		t.Errorf("flag: got %v", err)
	}
	if _, err := Detect("", env(map[string]string{"RSATOY_LANG": "zh-CN"}), nil); !errors.Is(err, ErrUnknownLang) {
		t.Errorf("env: got %v", err)
	}
}

func TestPrinter(t *testing.T) {
	if got := New(EN).T("g.step", 3); got != "Step 3 of 6" {
		t.Errorf("got %q", got)
	}
	if got := New(ZH).T("g.step", 3); got != "第 3 步，共 6 步" {
		t.Errorf("got %q", got)
	}
	if got := New(EN).T("no.such.id"); got != "[no.such.id]" {
		t.Errorf("got %q", got)
	}
}
