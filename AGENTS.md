# Working on OTScout

Notes for anyone, human or agent, making changes here.

## Attribution

**Never record a tool as a commit co-author.** Do not add a `Co-authored-by`
trailer naming an editor, an agent or a bot account, and do not leave one in
place if something else added it. GitHub reads that trailer and lists the account
on the repository contributor page, and the contributors of this project are
people.

Some agent harnesses append the trailer by passing `--trailer` to `git commit`,
which no git setting overrides. `.githooks/commit-msg` strips it, so run this
once per clone:

```bash
make hooks
```

That points `core.hooksPath` at `.githooks`. Without it the hook does not run and
the trailer reaches the commit, at which point the only remedy is rewriting
history and force pushing.

A `Co-authored-by` line naming an actual person is fine. That is what the trailer
is for.

## Writing

The rules below apply to everything: code, comments, commit messages,
documentation and any text the tool prints or renders.

- ASCII only. No em dash, no en dash, no smart quotes, no ellipsis character, no
  arrows, no non breaking spaces, no emoji. A hyphen and a straight quote are
  always available. Text that came from an advisory is data and passes through
  unchanged, which is a different thing from text this project writes.
- Say the thing plainly. No filler openers, no summaries of what was just said,
  no praise of the work, no phrases that exist to sound thorough.
- Comments explain a constraint or a decision that the code cannot show. They do
  not narrate the next line, cite where a change came from, or argue that the
  change is correct.

`make check-text` enforces the mechanical part of this.

## Safety

This tool talks to industrial equipment, where a badly formed packet can disturb
a running process. Before changing anything under `internal/safety`,
`internal/protocol` or `internal/probe`, read `docs/SAFETY.md`.

Two rules that are not negotiable:

- A request that reaches a device can only come from a builder in
  `internal/protocol`, and no builder there encodes a write. A test reads that
  package's source and fails when it grows a byte producing function that is not
  on a reviewed list.
- Every probe template step needs a recorded response in the golden corpus, so a
  template can be reviewed by somebody who owns none of the equipment. See
  `docs/FIXTURES.md`.

## Before pushing

```bash
make check
```

That runs the same commands CI does: tidiness, formatting, vet, the text rules
and the tests.
