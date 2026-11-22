package server

import "strings"

// logSafe neutralises control characters (CR, LF, tabs, escapes) in a value that
// came from a request before it is logged, so a caller cannot forge log lines.
func logSafe(s string) string {
	// The explicit CR/LF replacements come first: they are what static analysis (CodeQL go/log-injection)
	// recognises as a sanitiser. The Map then neutralises every other control character.
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", "_"), "\r", "_")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}
