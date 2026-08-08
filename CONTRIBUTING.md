# Contributing to OTScout

This tool tells people which of their controllers are vulnerable, and it can be
pointed at equipment that runs a physical process. Both of those shape how
changes are reviewed here. A wrong answer delivered confidently is worse than no
answer, and a badly formed packet is worse than a missing feature.

None of what follows requires you to own industrial equipment.

## What helps most

**Fixtures.** A recorded device response paired with the identity it must
produce. This is the cheapest useful contribution and the only way a decoder
change can be reviewed by somebody who does not own the device it affects. See
[docs/FIXTURES.md](docs/FIXTURES.md).

**Templates.** One identification exchange with one kind of device, written in
YAML, no Go required. See [docs/TEMPLATES.md](docs/TEMPLATES.md).

**Vendor normalization.** Advisories and devices name the same product
differently, and closing that gap is most of what makes matching work. Aliases
live in `internal/normalize/data`, and a catalog number parser or a firmware
comparator for a vendor this project handles badly is worth more than it looks.

**A finding that is wrong.** If a device is matched to an advisory that does not
apply to it, that is a bug report this project wants, with the asset identity and
the advisory id. Every finding carries the evidence for why it matched, so the
report can start from what the tool claimed rather than a guess.

## Setting up

Go 1.24 or later, and nothing else. Then, once per clone:

```bash
make hooks
```

That points `core.hooksPath` at `.githooks` and installs two hooks. One runs
gofmt and the text rules on what you staged, so a formatting slip costs a second
rather than a round trip through CI. The other strips any `Co-authored-by`
trailer naming a bot, which is explained below.

Before pushing:

```bash
make check
```

That is what CI runs: module tidiness, formatting, vet, the text rules and the
tests.

## How changes are reviewed

Small and self contained. One template is one pull request. Say in the
description what a reader cannot get from the diff: where the bytes came from,
which device you tested against, what you are unsure of.

A change that alters what the tool claims about a device needs a fixture that
would have failed before it. Not for coverage, but because a claim about
equipment is the product here, and an unverified change to one is the thing this
project is organised to prevent.

Uncertainty in a pull request description is useful and welcome. Uncertainty
absent from a pull request description is the problem.

## The parts with extra rules

Read [docs/SAFETY.md](docs/SAFETY.md) before changing anything under
`internal/safety`, `internal/protocol` or `internal/probe`.

Two rules there are not open for discussion:

- A request that reaches a device can only come from a builder in
  `internal/protocol`, and no builder there encodes a write. A test reads that
  package's source and fails when it grows a byte producing function that is not
  on a reviewed list.
- Every probe template step needs a recorded response in the golden corpus.

Both exist so that a reviewer who owns none of the equipment can still tell
whether a change is safe.

## Writing

The rules apply to code, comments, commit messages, documentation and anything
the tool prints: ASCII only, and say the thing plainly.
[AGENTS.md](AGENTS.md) has the reasoning and `make check-text` enforces the
mechanical part, reporting a line, a column and what to write instead. Text
quoted from an advisory is data and can carry `check-text: allow` on the line.

## Attribution

Do not add a `Co-authored-by` trailer naming an editor, an agent or a bot
account. GitHub reads that trailer and lists the account on the contributor page,
and the contributors of this project are people. Some tools add the trailer
without being asked, which is why `make hooks` installs something that removes
it.

A `Co-authored-by` line naming an actual person is welcome. That is what the
trailer is for.

## Security issues

Do not open a public issue for a vulnerability in this tool.
[SECURITY.md](SECURITY.md) says where to send it.

A vulnerability in somebody else's equipment goes to that vendor or to CISA, not
here. This project reads published advisories, it does not publish them.

## License

Contributions are made under the Apache License 2.0, the same as the rest of the
project. See [LICENSE](LICENSE). Bytes recorded from a published capture arrive
under the license of that capture, which the fixture has to name; see
[NOTICE](NOTICE).
