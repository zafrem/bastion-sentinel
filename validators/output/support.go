package output

import (
	"strings"
	"unicode"
)

// Content support: what share of an answer's ordinary words can be found in its sources.
//
// This is a lexical test and says nothing about meaning. It reliably separates an answer that
// is about something else from one that restates its sources, and it cannot tell an answer that
// uses the same words with the opposite meaning. It only reads words written in Latin letters:
// Korean and other scripts attach endings to words, so a plain match would be unreliable, and
// an answer with too few Latin content words is not judged at all (the numbers check still is).
const (
	maxAnswerWords = 400 // longer answers are judged on their first words
	maxMissingList = 8   // unsupported words reported
)

var stopwords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`
		the and for are was were but not you your yours our ours his her its their them they this that
		these those with from have has had will would can could should may might must shall been being
		does did done doing about into onto over under than then there here what when where which who
		whom whose why how all any some such only also just very more most much many each every other
		another one out off its it's i'm you're we're they're don't doesn't isn't aren't can't won't
		let get got make made yes sure okay please thanks thank help happy glad able like want need
		see use used using way ways etc per via too own same both few our ourselves
	`) {
		m[w] = true
	}
	return m
}()

// words returns the lowercase Latin-script words of text, in order.
func words(text string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range strings.ToLower(text) {
		if unicode.Is(unicode.Latin, r) || r == '\'' {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// stem4 is a crude stem: the first four letters, so open/opening and close/closed match.
func stem4(w string) string {
	if r := []rune(w); len(r) > 4 {
		return string(r[:4])
	}
	return w
}

// contentSupport returns the share of the answer's content words found in the sources, and the
// ones that were not. ok is false when the answer has fewer than minWords content words.
func contentSupport(answer string, sources []string, minWords int) (support float64, missing []string, ok bool) {
	var content []string
	seen := map[string]bool{}
	for _, w := range words(answer) {
		w = strings.Trim(w, "'")
		if len([]rune(w)) < 3 || stopwords[w] || seen[w] {
			continue
		}
		seen[w] = true
		content = append(content, w)
		if len(content) == maxAnswerWords {
			break
		}
	}
	if len(content) < minWords {
		return 0, nil, false
	}
	exact := map[string]bool{}
	stems := map[string]bool{}
	for _, s := range sources {
		for _, w := range words(s) {
			w = strings.Trim(w, "'")
			exact[w] = true
			stems[stem4(w)] = true
		}
	}
	found := 0
	for _, w := range content {
		// Three-letter words must match exactly; longer ones by their first four letters.
		if exact[w] || (len([]rune(w)) >= 4 && stems[stem4(w)]) {
			found++
		} else if len(missing) < maxMissingList {
			missing = append(missing, w)
		}
	}
	return float64(found) / float64(len(content)), missing, true
}
