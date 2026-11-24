//go:build !windows

package main

// setupConsole has nothing to do outside Windows: terminals there already
// handle UTF-8 and ANSI colors.
func setupConsole() bool { return true }
