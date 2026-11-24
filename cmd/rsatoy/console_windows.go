package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// setupConsole switches the console to UTF-8 output, so Chinese text shows
// in the old console window, and turns on ANSI color support. It reports
// whether colors can be used.
func setupConsole() bool {
	_ = windows.SetConsoleOutputCP(65001) // UTF-8
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
