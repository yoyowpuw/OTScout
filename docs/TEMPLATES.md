# Writing a probe template

A template describes one identification exchange with one kind of device: which
port to reach it on, which requests to send, and in what order. Templates are the
part of this project that most benefits from people who know specific equipment,
and they are deliberately the part you can contribute without writing Go.

They live in `internal/probe/templates`, one YAML file per protocol, and they are
compiled into the binary.

## A template names a request, it does not contain one

The single most important thing about the format: a step says `request:
s7comm.read-szl`, never a string of bytes.

```yaml
steps:
  - purpose: read SZL 0x0011, the module identification list carrying the order number
    request: s7comm.read-szl
    params:
      szl_id: "0x0011"
      szl_index: "0"
```

The name refers to a builder in `internal/protocol`, and that package contains no
encoder for a write, a reset or a stop. A template therefore cannot express one,
however it is written, and a template file from a stranger cannot put an
arbitrary packet on an industrial network. That is a structural guarantee rather
than a promise, and it is the reason templates can be reviewed at all. See
[SAFETY.md](SAFETY.md).

The cost is that a genuinely new kind of request needs a Go change, reviewed
separately. That is covered at the end.

## The shape

```yaml
version: 1

templates:
  - id: enip-list-identity
    summary: >-
      One line saying what an operator gets from this, because it is what they
      will read in the pre-flight screen.
    protocol: enip
    port: 44818
    transport: tcp
    risk: safe
    references:
      - https://a.specification.a.reviewer.can.check
    steps:
      - purpose: shown in the dry run and written to the audit log
        request: enip.list-identity
        params:
          sender_context: "0000000000000000"
```

### Template fields

| Field | Required | Rule |
|---|---|---|
| `id` | yes | Lowercase words joined by hyphens. It appears in the audit log, the deny list and bug reports, so it has to be stable and typeable. Must be unique across every file. |
| `summary` | yes | What this gets from a device, in one line. |
| `protocol` | yes | One of `modbus`, `enip`, `s7comm`, `bacnet`. This selects the decoder that reads the replies. |
| `port` | yes | 1 to 65535. |
| `transport` | yes | `tcp` or `udp`. |
| `risk` | yes | `safe`, `caution` or `lab-only`. See below. |
| `risk_note` | only above `safe` | Why the rating is what it is. |
| `references` | yes in practice | Where the request is specified. A test fails a template that cites nothing. |
| `steps` | yes | At least one. |

### Step fields

| Field | Required | Rule |
|---|---|---|
| `purpose` | yes | Plain words. This ends up in a change request submitted to somebody who does not know the protocol. |
| `request` | yes | A registered builder name. |
| `params` | no | Strings. Numbers may be decimal or `0x` hex. Anything omitted takes the default below. |

Steps in one template share a connection and run in order. Declare every packet,
including the ones that are only setup. S7comm needs a COTP connection and a
negotiated PDU size before a CPU will answer anything, so its templates have four
steps rather than one. Hiding those in the transport would put three unpaced
packets on the wire and leave two out of the audit log, and the dry run would
under-report the packet count to the person approving the scan.

A step that fails ends its exchange. The remaining steps are not attempted.

## Builders you can call

| `request:` | Parameters, with defaults |
|---|---|
| `modbus.read-device-identification` | `transaction_id` (0), `unit_id` (1), `read_code` (1, meaning basic; 2 regular, 3 extended) |
| `enip.list-identity` | `sender_context`, 8 bytes of hex (zeroes) |
| `s7comm.connection-request` | `source_tsap` (0x0100), `dest_tsap` (0x0102) |
| `s7comm.setup-communication` | `pdu_reference` (0) |
| `s7comm.read-szl` | `pdu_reference` (0), `szl_id` (0x001C), `szl_index` (0) |
| `bacnet.who-is` | none |
| `bacnet.read-property` | `invoke_id` (0), `property` (70, model name) |

Unknown parameter names are ignored rather than rejected, so check your spelling
against this table. A value out of range is refused at load time and names the
field.

## Risk, and what a rating costs

`safe` is a read that the protocol defines for identification and that the
device is expected to answer as part of normal operation.

`caution` is anything you would not run during a production shift without asking.
`lab-only` is anything you would only run against equipment on a bench.

Only `safe` templates run by default. The others are skipped, recorded in the
audit log as skipped rather than silently dropped, and need `--allow-risk
caution` or `--allow-risk lab-only`. A dry run still prints them, with the bytes,
marked as not sent.

Anything above `safe` needs `risk_note`, and a test requires at least ten words
of it. A rating with no reason attached cannot be argued with, and cannot be
revised when somebody who owns the equipment knows better. Write the reason, not
a restatement of the rating.

## Every step needs a recorded answer

A template whose steps have no fixture in the golden corpus is refused by
`TestEveryTemplateStepHasBeenAnsweredBySomething`:

```
template X step 1 sends Y and no fixture records a device answering it. Add one
to internal/golden/corpus, or this step gets tested for the first time against
real equipment.
```

That last clause is the whole rule. Untested here means tested on somebody's
plant. [FIXTURES.md](FIXTURES.md) covers how to record one, including what to do
when you do not own the device.

## Adding a builder, when no existing request will do

This is a Go change and a deliberately loud one.

1. Write the byte producing function in `internal/protocol`.
2. Register it in the `builders` map in `registry.go` under a dotted name.
3. Add the Go function to `reviewedBuilders` in `readonly_test.go`, with the
   function or service code it encodes and why that is a read.
4. Add the YAML name to `reviewedRequests` in the same file.

Steps 3 and 4 are not bookkeeping. A test reads the package source and fails on
any exported function returning `[]byte` that is not on the reviewed list, so the
list cannot drift from the code, and adding to it is a diff that states in words
that a new kind of packet may now reach industrial equipment. If the answer to
"why is this a read" is not a short sentence citing the specification, the change
does not belong here.

## Checking your work

```bash
go test ./internal/probe ./internal/protocol ./internal/golden -count=1
```

Then see it the way an operator will, without opening a socket:

```bash
otscout probe 192.0.2.10 --dry-run
```

The dry run performs target expansion and template selection and prints a hex
dump of every request. If that output would not survive being pasted into a
change request, the template is not finished.
