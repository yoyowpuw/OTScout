package main

import (
	"strings"
	"testing"
)

// The forbidden characters are written as escapes throughout. Typing them would
// make this file fail the rule it is testing.

func problemsFor(t *testing.T, name, body string) []problem {
	t.Helper()
	return checkFile(name, []byte(body))
}

func onlyProblem(t *testing.T, name, body string) problem {
	t.Helper()
	found := problemsFor(t, name, body)
	if len(found) != 1 {
		t.Fatalf("want exactly one problem, got %d: %v", len(found), found)
	}
	return found[0]
}

func TestPlainASCIIPasses(t *testing.T) {
	body := "package main\n\n// A comment with 'quotes' and a hyphen-joined word.\nfunc main() {}\n"
	if found := problemsFor(t, "main.go", body); len(found) != 0 {
		t.Fatalf("clean file reported problems: %v", found)
	}
}

func TestEachForbiddenCharacterIsNamed(t *testing.T) {
	cases := []struct {
		char rune
		want string
	}{
		{'\u2014', "em dash"},
		{'\u2013', "en dash"},
		{'\u2018', "left single quote"},
		{'\u2019', "right single quote"},
		{'\u201c', "left double quote"},
		{'\u201d', "right double quote"},
		{'\u2026', "ellipsis"},
		{'\u00a0', "non-breaking space"},
		{'\u2192', "an arrow"},
		{'\u2190', "an arrow"},
		{'\U0001f680', "an emoji"},
		{'\u2705', "a symbol or emoji"},
		{'\ufeff', "byte order mark"},
		{'\u200b', "zero width space"},
	}
	for _, c := range cases {
		body := "a " + string(c.char) + " b\n"
		got := onlyProblem(t, "doc.md", body)
		if !strings.Contains(got.msg, c.want) {
			t.Errorf("U+%04X: message %q does not name %q", c.char, got.msg, c.want)
		}
		if !strings.Contains(got.msg, "use ") {
			t.Errorf("U+%04X: message %q does not say what to write instead", c.char, got.msg)
		}
	}
}

// An unlisted non-ASCII character still fails. The table exists to give better
// advice, not to enumerate what is banned: the rule is ASCII.
func TestAnUnlistedNonASCIICharacterStillFails(t *testing.T) {
	got := onlyProblem(t, "doc.md", "caf\u00e9\n")
	if !strings.Contains(got.msg, "U+00E9") {
		t.Fatalf("message %q does not identify the character", got.msg)
	}
}

func TestThePositionPointsAtTheCharacter(t *testing.T) {
	body := "first line\nsecond \u2014 line\n"
	got := onlyProblem(t, "doc.md", body)
	if got.line != 2 {
		t.Errorf("line = %d, want 2", got.line)
	}
	// "second " is seven bytes, so the dash starts at column eight.
	if got.col != 8 {
		t.Errorf("col = %d, want 8", got.col)
	}
}

func TestTheAllowDirectiveExemptsOneLine(t *testing.T) {
	body := "quoted \u2014 from an advisory // " + allowDirective + "\nours \u2014 not quoted\n"
	got := onlyProblem(t, "doc.md", body)
	if got.line != 2 {
		t.Fatalf("the directive exempted the wrong line, problem on line %d", got.line)
	}
}

func TestGeneratedFillerIsCaught(t *testing.T) {
	for _, body := range []string{
		"It is worth noting that the CPU answers on port 102.\n",
		"IT IS WORTH NOTING that the CPU answers.\n",
		"Let us delve into the protocol.\n",
		"This is a cutting-edge scanner.\n",
	} {
		if found := problemsFor(t, "README.md", body); len(found) == 0 {
			t.Errorf("filler not caught: %q", body)
		}
	}
}

// A phrase that happens to sit inside a longer token is not filler. Without this
// the checker would fire on identifiers and URLs.
func TestAPhraseInsideALongerWordIsNotFiller(t *testing.T) {
	for _, body := range []string{
		"supercharger := newSupercharger()\n",
		"https://example.org/embark_ondeck\n",
	} {
		if found := problemsFor(t, "main.go", body); len(found) != 0 {
			t.Errorf("false positive on %q: %v", body, found)
		}
	}
}

// The file that lists the phrases necessarily contains them. It is exempt from
// the phrase rule and from nothing else.
func TestTheRulesFileIsExemptFromPhrasesOnly(t *testing.T) {
	body := "\"delve into\",\n"
	if found := problemsFor(t, "scripts/check-text/rules.go", body); len(found) != 0 {
		t.Errorf("rules file flagged for its own list: %v", found)
	}

	got := onlyProblem(t, "scripts/check-text/rules.go", "// an em dash \u2014 here\n")
	if !strings.Contains(got.msg, "em dash") {
		t.Fatalf("rules file escaped the character rule: %q", got.msg)
	}
}

func TestABinaryFileIsSkipped(t *testing.T) {
	body := "\x00\x01\x02\u2014\n"
	if found := problemsFor(t, "capture.bin", body); len(found) != 0 {
		t.Errorf("binary content was scanned: %v", found)
	}
	if found := problemsFor(t, "capture.pcap", "\u2014\n"); len(found) != 0 {
		t.Errorf("binary extension was scanned: %v", found)
	}
}

func TestTheFileMustEndWithExactlyOneNewline(t *testing.T) {
	if found := problemsFor(t, "doc.md", "no newline"); len(found) != 1 ||
		!strings.Contains(found[0].msg, "no newline at end") {
		t.Errorf("missing final newline not caught: %v", found)
	}
	if found := problemsFor(t, "doc.md", "text\n\n"); len(found) != 1 ||
		!strings.Contains(found[0].msg, "blank line at end") {
		t.Errorf("trailing blank line not caught: %v", found)
	}
	if found := problemsFor(t, "doc.md", ""); len(found) != 0 {
		t.Errorf("empty file reported: %v", found)
	}
}

// Two trailing spaces are a hard line break in markdown, which is why
// .editorconfig exempts it. The checker follows that rather than contradict it.
func TestTrailingWhitespaceFailsExceptInMarkdown(t *testing.T) {
	if found := problemsFor(t, "main.go", "code() \n"); len(found) != 1 ||
		!strings.Contains(found[0].msg, "trailing whitespace") {
		t.Errorf("trailing whitespace not caught in Go: %v", found)
	}
	if found := problemsFor(t, "doc.md", "a line break  \nnext\n"); len(found) != 0 {
		t.Errorf("markdown line break was flagged: %v", found)
	}
}

func TestAControlCharacterFails(t *testing.T) {
	got := onlyProblem(t, "doc.md", "a\x07b\n")
	if !strings.Contains(got.msg, "control character") {
		t.Fatalf("message %q does not name the control character", got.msg)
	}
	if found := problemsFor(t, "main.go", "\tindented\n"); len(found) != 0 {
		t.Errorf("a tab is not a control character problem: %v", found)
	}
}

func TestInvalidUTF8Fails(t *testing.T) {
	got := onlyProblem(t, "doc.md", "a\xffb\n")
	if !strings.Contains(got.msg, "not valid UTF-8") {
		t.Fatalf("message %q does not report the bad byte", got.msg)
	}
}
