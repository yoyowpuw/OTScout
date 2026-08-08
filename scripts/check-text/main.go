// Command check-text enforces the writing rules in AGENTS.md that a machine can
// judge: this project writes ASCII, and it does not write the filler that
// generated prose reaches for.
//
// It takes the file list from git, so it sees what a clone would get and never
// wanders into build output or a dependency directory.
//
// Usage:
//
//	check-text            every tracked file
//	check-text -staged    what is about to be committed, read from the index
//	check-text FILE...    named files, read from the working tree
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
)

func main() {
	staged := flag.Bool("staged", false,
		"check staged content rather than the working tree, for a pre-commit hook")
	flag.Parse()

	clean, err := run(*staged, flag.Args(), os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "check-text: %v\n", err)
		os.Exit(2)
	}
	if !clean {
		os.Exit(1)
	}
}

func run(staged bool, args []string, out io.Writer) (bool, error) {
	paths, read, err := sources(staged, args)
	if err != nil {
		return false, err
	}

	var found []problem
	for _, path := range paths {
		data, err := read(path)
		if err != nil {
			return false, err
		}
		found = append(found, checkFile(path, data)...)
	}
	sortProblems(found)

	if len(found) == 0 {
		fmt.Fprintf(out, "check-text: %s, clean\n", count(len(paths), "file"))
		return true, nil
	}
	for _, p := range found {
		fmt.Fprintln(out, p)
	}
	fmt.Fprintf(out, "\n%s in %s. AGENTS.md says why these rules exist.\n",
		count(len(found), "problem"), count(countPaths(found), "file"))
	fmt.Fprintf(out, "Text quoted from elsewhere can carry %q on the line to exempt it.\n",
		allowDirective)
	return false, nil
}

func sortProblems(found []problem) {
	sort.Slice(found, func(i, j int) bool {
		if found[i].path != found[j].path {
			return found[i].path < found[j].path
		}
		if found[i].line != found[j].line {
			return found[i].line < found[j].line
		}
		return found[i].col < found[j].col
	})
}

func count(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func countPaths(found []problem) int {
	seen := make(map[string]bool, len(found))
	for _, p := range found {
		seen[p.path] = true
	}
	return len(seen)
}

// reader returns the bytes to check for a path. Which bytes those are depends on
// the mode: a pre-commit hook has to judge the staged content, because a file can
// be half staged and the working tree copy is then not what the commit contains.
type reader func(path string) ([]byte, error)

func sources(staged bool, args []string) ([]string, reader, error) {
	if len(args) > 0 {
		return args, os.ReadFile, nil
	}
	if staged {
		paths, err := gitPaths("diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
		return paths, readStaged, err
	}
	paths, err := gitPaths("ls-files", "-z")
	return paths, os.ReadFile, err
}

func readStaged(path string) ([]byte, error) {
	out, err := exec.Command("git", "show", ":"+path).Output()
	if err != nil {
		return nil, fmt.Errorf("read staged %s: %w", path, gitError(err))
	}
	return out, nil
}

// gitPaths asks git for a NUL separated list, because a path can contain
// anything the filesystem allows and splitting on newlines breaks on the one
// that contains a newline.
func gitPaths(args ...string) ([]string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), gitError(err))
	}

	var paths []string
	for _, field := range bytes.Split(out, []byte{0}) {
		if len(field) == 0 {
			continue
		}
		paths = append(paths, string(field))
	}
	return paths, nil
}

// gitError surfaces what git printed. Without this the caller sees only
// "exit status 128", which says nothing about a missing repository or a bad ref.
func gitError(err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if msg := strings.TrimSpace(string(exitErr.Stderr)); msg != "" {
			return errors.New(msg)
		}
	}
	return err
}
