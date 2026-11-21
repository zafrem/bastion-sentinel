package prompt

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Limits keep decoding cheap and bounded so it cannot be used to burn CPU.
const (
	maxScanBytes     = 64 << 10 // only the first 64 KiB of a query is scanned for encodings
	maxEncodedTokens = 8        // encoded fragments decoded per pass
	maxDecodedBytes  = 8 << 10  // a decoded fragment longer than this is ignored
	maxDecodeDepth   = 2        // base64 inside base64, and no deeper
)

var (
	base64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexToken    = regexp.MustCompile(`(?i)\b(?:0x)?(?:[0-9a-f]{2}){12,}\b`)
	pctToken    = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}[A-Za-z0-9._~ +-]{0,6}){4,}`)
)

// Candidate is one view of the query that the rules are matched against.
type Candidate struct {
	Text string
	// Encoding names how the view was produced ("" for the query as sent).
	Encoding string
}

// stripInvisible removes characters that render as nothing but break up words
// ("ig\u200bnore"): zero-width spaces and joiners, soft hyphens, BOM, bidi marks.
func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\u200b', r == '\u200c', r == '\u200d', r == '\u2060', r == '\ufeff', r == '\u00ad', r == '\u180e':
			return -1
		case r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069', r == '\u200e', r == '\u200f':
			return -1
		}
		return r
	}, s)
}

// printable reports whether decoded bytes look like human text, so random
// binary that happens to be valid base64 is not scanned.
func printable(b []byte) bool {
	if len(b) < 4 || !utf8.Valid(b) {
		return false
	}
	good, total := 0, 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			good++
		}
	}
	return total > 0 && float64(good)/float64(total) > 0.95
}

func decodeBase64(tok string) ([]byte, bool) {
	tok = strings.TrimRight(tok, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(tok); err == nil && len(b) <= maxDecodedBytes && printable(b) {
			return b, true
		}
	}
	return nil, false
}

// Candidates returns the query as sent plus every normalised and decoded view of it.
// Rules run on all of them, so an attack hidden by encoding or invisible characters is
// matched exactly like the plain-text version.
func Candidates(query string) []Candidate {
	if len(query) > maxScanBytes {
		query = query[:maxScanBytes]
	}
	base := norm.NFC.String(query)
	out := []Candidate{{Text: base}}
	seen := map[string]bool{base: true}
	add := func(text, enc string) {
		if text != "" && !seen[text] {
			seen[text] = true
			out = append(out, Candidate{Text: text, Encoding: enc})
		}
	}
	// Presentation tricks: invisible characters and full-width / compatibility forms.
	view := stripInvisible(base)
	add(view, "invisible-chars")
	add(norm.NFKC.String(view), "unicode-compat")

	// Encodings, up to maxDecodeDepth layers.
	frontier := []Candidate{{Text: view}}
	for depth := 0; depth < maxDecodeDepth && len(frontier) > 0; depth++ {
		var next []Candidate
		for _, c := range frontier {
			for _, d := range decodeOnce(c.Text) {
				if !seen[d.Text] {
					seen[d.Text] = true
					out = append(out, d)
					next = append(next, d)
				}
			}
		}
		frontier = next
	}
	return out
}

func decodeOnce(s string) []Candidate {
	var out []Candidate
	for _, tok := range firstN(base64Token.FindAllString(s, -1), maxEncodedTokens) {
		if b, ok := decodeBase64(tok); ok {
			out = append(out, Candidate{Text: stripInvisible(string(b)), Encoding: "base64"})
		}
	}
	for _, tok := range firstN(hexToken.FindAllString(s, -1), maxEncodedTokens) {
		tok = strings.TrimPrefix(strings.TrimPrefix(tok, "0x"), "0X")
		if b, err := hex.DecodeString(tok); err == nil && len(b) <= maxDecodedBytes && printable(b) {
			out = append(out, Candidate{Text: stripInvisible(string(b)), Encoding: "hex"})
		}
	}
	if pctToken.MatchString(s) {
		if u, err := url.QueryUnescape(s); err == nil && u != s {
			out = append(out, Candidate{Text: stripInvisible(u), Encoding: "url-encoding"})
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
