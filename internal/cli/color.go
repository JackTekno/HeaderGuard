// Package cli provides HeaderGuard's terminal output.
package cli

import "os"

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
)

// Color paints text when enabled.
type Color struct{ Enabled bool }

func (c Color) paint(code, s string) string {
	if !c.Enabled {
		return s
	}
	return code + s + ansiReset
}

func (c Color) Red(s string) string    { return c.paint(ansiRed, s) }
func (c Color) Green(s string) string  { return c.paint(ansiGreen, s) }
func (c Color) Yellow(s string) string { return c.paint(ansiYellow, s) }
func (c Color) Cyan(s string) string   { return c.paint(ansiCyan, s) }
func (c Color) Bold(s string) string   { return c.paint(ansiBold, s) }
func (c Color) Dim(s string) string    { return c.paint(ansiDim, s) }

// IsTerminal reports whether stdout is a TTY (Linux/macOS/Windows).
func IsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
