package cli

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Finding fields come from scanner output and other tools, so they are
// untrusted. Before printing them to a terminal, escape control characters
// (which can move the cursor, rewrite earlier output or change the window
// title) and bidirectional-text controls (which can make text display in a
// different order than it is stored).

// cleanLine makes untrusted text safe to print on a single line.
func cleanLine(s string) string {
	return clean(s, false)
}

// cleanText makes untrusted text safe to print, keeping line breaks and tabs.
func cleanText(s string) string {
	return clean(s, true)
}

func clean(s string, multiline bool) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			if multiline {
				b.WriteRune(r)
			} else {
				b.WriteByte(' ')
			}
		case isUnsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isUnsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}
