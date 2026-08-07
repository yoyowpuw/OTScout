# The golden corpus

`internal/golden/corpus` holds recorded ICS protocol responses paired with the
identity each one must produce. It is the reason you can change a decoder, or add
one, and find out in CI whether you broke a device you have never seen.

## Why it exists

A fingerprint is a claim about what a sequence of bytes on the wire means, and
there are only two ways to check such a claim. One is to put the tool in front of
the equipment, which is expensive, slow and available to almost nobody: the people
most able to review this project are the least able to keep a Siemens rack and a
Rockwell chassis on a desk. The other is to keep the bytes.

Without the corpus this project would have to accept changes it has no way to
evaluate. For a tool that tells people which of their controllers is vulnerable,
that is not a gap in test coverage. It is a way of being wrong quietly.

## What a fixture looks like

One JSON file per exchange, named after its `id`:

```json
{
  "id": "iti-rockwell-1756-enbt-list-identity",
  "summary": "what this fixture is here to prove, in one line",
  "device": {
    "source": "Allen-Bradley 1756-ENBT/A",
    "description": "how the device presents itself",
    "provenance": "captured",
    "license": "CC-BY-4.0",
    "references": ["a URL a reviewer can check this against"]
  },
  "port": 44818,
  "transport": "tcp",
  "response": "6300330000...",
  "expect": {
    "protocol": "enip",
    "verdict": "decoded",
    "fields": { "product_name": "1756-ENBT/A" },
    "identity": { "vendor_raw": "Rockwell Automation/Allen-Bradley" }
  }
}
```

`port` and `transport` are not decoration. The passive path chooses decoders by
port and falls back to trying all of them when nothing is registered, so a fixture
on an unusual port exercises a different route through the code than the same
bytes on the registered one.

You do not write the `expect` block by hand. Record the bytes, describe where they
came from, then run:

```bash
go test ./internal/golden -update
```

Read the diff before you commit it. That diff is the review, and a diff touching a
fixture your change was not about is the signal to stop.

## Provenance, which decides how much a fixture proves

`captured` means the bytes came off a wire or out of a capture file, from the
device the fixture names. This is the strong kind.

`constructed` means the bytes were assembled to match what the cited software
emits for the cited configuration, rather than observed. A constructed fixture is
weaker evidence and is never described as a capture. It is still worth having: the
emulators this project cites are open source, so their output follows from a source
file a reviewer can open, and `TestConstructedFixturesMatchTheEmulatorTheyCite`
re-derives it on every run rather than trusting a comment. If you replace a
constructed fixture with a real capture and leave the expectations untouched, that
is a contribution this project actively wants.

A `captured` fixture must name the `license` its bytes arrive under, because a
published capture is somebody's work and redistributing a frame from it is an
obligation rather than a copy. See [NOTICE](../NOTICE).

## Verdicts

- `decoded`: the decoder returned no error.
- `device-error`: the device answered with a protocol level refusal. That is a
  successful observation, not a failure. Something is listening and it speaks the
  protocol.
- `truncated`: the frame is a valid start that ends early, so the caller should
  hold it and wait for the rest of the stream.
- `not-this-protocol`: every decoder correctly declined the payload.

## Fixtures that must be refused

Roughly a quarter of the corpus is traffic no decoder may claim, and those files
are not filler. Passive discovery tries every decoder on a port nothing is
registered for, so the decoders are constantly asked about payloads that are none
of their business, and a wrong acceptance is worse than a miss. It invents a
protocol, which becomes a role, a Purdue level, and an advisory search against
equipment the device is not. Real captures found four of these:

- HART-IP puts zeroes where the Modbus protocol id belongs, and a gateway was
  filed as a Modbus device answering function 13.
- A Niagara Fox greeting begins with the ASCII `fox`, which read as an EtherNet/IP
  encapsulation command.
- An Omron FINS reply begins with `FINS`, likewise.
- A historian on port 5450 begins with two zero bytes, which read as the
  EtherNet/IP NOP command.

If you widen a decoder, these are the fixtures that will tell you that you widened
it too far.

## Adding one

1. Get the bytes. A capture from equipment you have access to is best. Failing
   that, run one of the emulators the corpus already cites and record it, or derive
   the frame from the emulator's source and add a derivation function to
   `emulator_test.go` so the derivation is checked rather than asserted.
2. Write the fixture with an empty `expect` block, then fill it with `-update`.
3. Audit the diff. Every field in it is now a promise about real equipment.
4. Run `go test ./internal/golden`. The corpus is also replayed as a synthetic
   capture through the whole passive path, so a fixture that decodes correctly and
   then lands on the wrong asset will fail there rather than passing quietly.

A fixture whose expectations you cannot explain is worse than no fixture, because
the next person will trust it.
