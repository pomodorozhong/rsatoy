package i18n

import "golang.org/x/sys/windows"

// SystemLanguages returns the user's preferred UI languages from Windows,
// most preferred first.
func SystemLanguages() []string {
	langs, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil {
		return nil
	}
	return langs
}
