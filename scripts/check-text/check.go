package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// allowDirective on a line exempts that line from every rule. It exists for the
// case this checker cannot judge: text quoted from somewhere else, where
// changing a character would misquote the source.
const allowDirective = "check-text: allow"

// problem is one rule violation, positioned so an editor can jump to it.
type problem struct {
	path string
	line int
	col  int
	msg  string
}

func (p problem) String() string {
	return fmt.Sprintf("%s:%d:%d: %s", p.path, p.line, p.col, p.msg)
}

// phraseExempt lists paths where the phrase rule cannot apply, because the file
// is the rule. Only the phrase rule is lifted; the character rules still hold.
func phraseExempt(path string) bool {
	dir := filepath.ToSlash(filepath.Dir(path))
	return dir == "scripts/check-text"
}

// binaryExt are the extensions .gitattributes already marks binary. Content
// sniffing catches the rest, but an extension check avoids reading a large
// capture only to discard it.
var binaryExt = map[string]bool{
	".pcap":   true,
	".pcapng": true,
	".png":    true,
	".jpg":    true,
	".jpeg":   true,
	".gif":    true,
	".ico":    true,
	".woff":   true,
	".woff2":  true,
	".ttf":    true,
	".otf":    true,
	".zip":    true,
	".gz":     true,
	".pdf":    true,
}

func isBinaryPath(path string) bool {
	return binaryExt[strings.ToLower(filepath.Ext(path))]
}

// isBinaryContent treats a NUL byte as the mark of a file that is not prose. It
// is the same test git uses to decide whether to print a diff.
func isBinaryContent(data []byte) bool {
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

func checkFile(path string, data []byte) []problem {
	if isBinaryPath(path) || isBinaryContent(data) {
		return nil
	}

	var found []problem
	checkPhrases := !phraseExempt(path)
	trailingSpaceMatters := strings.ToLower(filepath.Ext(path)) != ".md"

	lineStart := 0
	lineNo := 0
	for lineStart <= len(data) {
		lineNo++
		end := bytes.IndexByte(data[lineStart:], '\n')
		var line []byte
		if end < 0 {
			line = data[lineStart:]
			lineStart = len(data) + 1
		} else {
			line = data[lineStart : lineStart+end]
			lineStart += end + 1
		}
		// A repository checked out on Windows can still carry a stray carriage
		// return. Line endings are .gitattributes' problem, not this checker's.
		line = bytes.TrimSuffix(line, []byte("\r"))

		if bytes.Contains(line, []byte(allowDirective)) {
			continue
		}

		found = append(found, checkRunes(path, lineNo, line)...)
		if checkPhrases {
			found = append(found, checkPhraseLine(path, lineNo, line)...)
		}
		if trailingSpaceMatters {
			if trimmed := bytes.TrimRight(line, " \t"); len(trimmed) != len(line) {
				found = append(found, problem{path, lineNo, len(trimmed) + 1,
					"trailing whitespace"})
			}
		}

		if end < 0 {
			break
		}
	}

	found = append(found, checkFileEnding(path, data, lineNo)...)
	return found
}

// checkFileEnding requires exactly one newline at the end. A file with none
// makes the last line unreadable to tools that read line by line, and one that
// ends in blank lines produces a diff on the final line every time somebody
// appends to it.
func checkFileEnding(path string, data []byte, lastLine int) []problem {
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		return []problem{{path, lastLine, len(data), "no newline at end of file"}}
	}
	if bytes.HasSuffix(data, []byte("\n\n")) {
		return []problem{{path, lastLine, 1, "blank line at end of file"}}
	}
	return nil
}

func checkRunes(path string, lineNo int, line []byte) []problem {
	var found []problem
	for offset := 0; offset < len(line); {
		r, size := utf8.DecodeRune(line[offset:])
		col := offset + 1
		offset += size

		if r == utf8.RuneError && size == 1 {
			found = append(found, problem{path, lineNo, col,
				"byte that is not valid UTF-8"})
			continue
		}
		if r < utf8.RuneSelf {
			if r == '\t' || r >= 0x20 {
				continue
			}
			found = append(found, problem{path, lineNo, col,
				fmt.Sprintf("control character U+%04X", r)})
			continue
		}
		found = append(found, problem{path, lineNo, col, describeRune(r)})
	}
	return found
}

func describeRune(r rune) string {
	if repl, ok := namedRunes[r]; ok {
		return fmt.Sprintf("%s (U+%04X), use %s", repl.name, r, repl.use)
	}
	for _, block := range namedBlocks {
		if r >= block.lo && r <= block.hi {
			return fmt.Sprintf("%s (U+%04X), use %s", block.repl.name, r, block.repl.use)
		}
	}
	return fmt.Sprintf("non-ASCII character U+%04X, this project writes ASCII", r)
}

func checkPhraseLine(path string, lineNo int, line []byte) []problem {
	lower := asciiLower(line)
	var found []problem
	for _, phrase := range phrases {
		from := 0
		for {
			at := bytes.Index(lower[from:], []byte(phrase))
			if at < 0 {
				break
			}
			at += from
			from = at + 1
			if !wordBounded(lower, at, len(phrase)) {
				continue
			}
			found = append(found, problem{path, lineNo, at + 1,
				fmt.Sprintf("%q reads as generated filler, say the thing plainly", phrase)})
		}
	}
	return found
}

// asciiLower folds A-Z and leaves every other byte alone, so the result is the
// same length as the input and a match offset is also an offset into the
// original line. strings.ToLower can change the byte length of some runes, which
// would put the reported column on the wrong character.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// wordBounded rejects a match that is part of a longer word, so "embark on" is
// caught but a hypothetical identifier that contains it is not.
func wordBounded(line []byte, at, length int) bool {
	if at > 0 && isWordByte(line[at-1]) {
		return false
	}
	if end := at + length; end < len(line) && isWordByte(line[end]) {
		return false
	}
	return true
}

func isWordByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_':
		return true
	}
	return false
}
