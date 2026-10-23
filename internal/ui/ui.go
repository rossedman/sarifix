// Package ui holds every terminal style sarifix uses, built from the brand
// palette, plus helpers that keep machine output and untrusted text safe.
//
// Commands import styles from here and never define colors inline. Styled
// output goes through Writer, which downsamples or strips color for the
// terminal's profile and honors NO_COLOR.
package ui

import (
	"image/color"
	"io"
	"os"
	"strings"
	"unicode"

	"charm.land/fang/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
)

// Brand colors, as light-background / dark-background pairs. Mint means
// "fixed", amber means "finding".
var (
	mintLight  = lipgloss.Color("#0A7D58")
	mintDark   = lipgloss.Color("#3DF5B5")
	amberLight = lipgloss.Color("#9A5800")
	amberDark  = lipgloss.Color("#FFB547")
	redLight   = lipgloss.Color("#B4232B")
	redDark    = lipgloss.Color("#FF7A7A")
	dimLight   = lipgloss.Color("#56676C")
	dimDark    = lipgloss.Color("#8FA3A8")
	textLight  = lipgloss.Color("#13231F")
	textDark   = lipgloss.Color("#E4F2EE")
	inkDark    = lipgloss.Color("#0B1714")
)

// Styles is the set of styles used in human output.
type Styles struct {
	Title   lipgloss.Style
	Brand   lipgloss.Style
	Finding lipgloss.Style
	Fixed   lipgloss.Style
	Bad     lipgloss.Style
	Dim     lipgloss.Style
	Text    lipgloss.Style
	Key     lipgloss.Style
	Path    lipgloss.Style
	Header  lipgloss.Style
}

// NewStyles builds the styles for a light or dark background.
func NewStyles(isDark bool) Styles {
	c := lipgloss.LightDark(isDark)
	mint := c(mintLight, mintDark)
	return Styles{
		Title:   lipgloss.NewStyle().Bold(true).Foreground(mint),
		Brand:   lipgloss.NewStyle().Foreground(mint),
		Finding: lipgloss.NewStyle().Foreground(c(amberLight, amberDark)),
		Fixed:   lipgloss.NewStyle().Foreground(mint),
		Bad:     lipgloss.NewStyle().Bold(true).Foreground(c(redLight, redDark)),
		Dim:     lipgloss.NewStyle().Foreground(c(dimLight, dimDark)),
		Text:    lipgloss.NewStyle().Foreground(c(textLight, textDark)),
		Key:     lipgloss.NewStyle().Bold(true).Foreground(c(textLight, textDark)),
		Path:    lipgloss.NewStyle().Underline(true).Foreground(c(textLight, textDark)),
		Header:  lipgloss.NewStyle().Bold(true).Foreground(c(dimLight, dimDark)),
	}
}

// ColorScheme is the fang help theme in brand colors.
func ColorScheme(c lipgloss.LightDarkFunc) fang.ColorScheme {
	cs := fang.DefaultColorScheme(c)
	mint := c(mintLight, mintDark)
	amber := c(amberLight, amberDark)
	cs.Title = mint
	cs.Program = mint
	cs.Command = amber
	cs.Flag = mint
	cs.QuotedString = amber
	cs.ErrorHeader = [2]color.Color{inkDark, c(redLight, redDark)}
	return cs
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// IsDark guesses whether the terminal background is dark. It only queries
// the terminal when both stdin and stdout are terminals; otherwise it
// assumes dark, which is what most terminals use.
func IsDark() bool {
	if !IsTerminal(os.Stdin) || !IsTerminal(os.Stdout) {
		return true
	}
	return lipgloss.HasDarkBackground(os.Stdin, os.Stdout)
}

// Writer wraps w so styled text is rendered for the terminal's color
// profile: full color on a capable TTY, none when piped or NO_COLOR is set.
func Writer(w io.Writer) io.Writer {
	return colorprofile.NewWriter(w, os.Environ())
}

// Sanitize makes untrusted text (SARIF messages, file paths from a scanner)
// safe to print: it strips ANSI escape sequences and control characters,
// replaces newlines with spaces and truncates to max runes (0 = no limit).
func Sanitize(s string, max int) string {
	s = ansi.Strip(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			r = ' '
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		if max > 0 && n == max {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// ErrorHandler prints command errors for fang. Unlike fang's default it never
// re-cases or re-wraps the message, because sarifix errors carry file paths
// and config keys that must stay exact. Off a terminal it prints a plain
// "Error: ..." line.
func ErrorHandler(w io.Writer, styles fang.Styles, err error) {
	f, isFile := w.(*os.File)
	if !isFile || !IsTerminal(f) {
		_, _ = io.WriteString(w, "Error: "+err.Error()+"\n")
		return
	}
	_, _ = io.WriteString(w, styles.ErrorHeader.String()+"\n")
	text := styles.ErrorText.UnsetTransform().UnsetWidth()
	for _, line := range strings.Split(err.Error(), "\n") {
		_, _ = io.WriteString(w, text.Render(line)+"\n")
	}
	_, _ = io.WriteString(w, "\n")
}
