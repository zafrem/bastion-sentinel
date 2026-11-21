package server

import "strings"

// logSafe neutralises control characters (CR, LF, tabs, escapes) in a value that
// came from a request before it is logged, so a caller cannot forge log lines.
func logSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}
