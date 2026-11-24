//go:build !darwin && !windows

package i18n

// SystemLanguages returns nil on systems other than macOS and Windows, where
// the locale environment variables are the only source.
func SystemLanguages() []string { return nil }
