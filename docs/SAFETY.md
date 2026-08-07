# Safety model

This document is the contract OTScout makes with the people who run the networks
it touches. If a change to the codebase would weaken anything stated here, that
change does not belong in this project.

## The problem being managed

An IT vulnerability scanner assumes that a probe which crashes a host is an
inconvenience. In an industrial network that assumption does not hold. A PLC
sitting on a network segment may be holding a valve position, a burner interlock
or a turbine governor. Some field devices have single threaded network stacks
that stall when they receive a request they do not recognise, and stalling the
network stack can stall the scan cycle.

There are documented cases of ordinary IT scanning knocking control devices
offline. That is why the ICS community treats active scanning as something you do
deliberately, in a maintenance window, with the plant staff informed, or not at
all.

OTScout is built so that the careless path is the safe path.

## Layer 1: passive is the default

`otscout ingest` reads packet captures, Zeek logs and Nmap output. It opens no
sockets to any device. The same fingerprint templates that drive active probing
are applied to captured bytes, so the passive path produces the same identity
fields as the active path wherever the traffic happened to contain them.

Passive discovery costs nothing in risk. It is the recommended way to start and
often the only path a site needs.

## Layer 2: read-only by construction

Active probes are not written in Go. They are declared in YAML templates, and the
template schema has no way to express a state change.

Concretely, the loader rejects a template when:

- The declared protocol has a known set of read-only operations and the template
  uses anything outside it. Modbus function codes are restricted to 43 with MEI
  type 14, which is Read Device Identification. Write single coil, write multiple
  registers, and the diagnostic subfunctions that force a listen-only mode or
  restart communications are not representable.
- A probe declares more than one request and response exchange than the protocol
  handler allows.
- The payload exceeds the length ceiling for its protocol.

This is enforcement in the loader, not advice in a document. A contributor cannot
submit a template that writes to a device, because the schema will not carry it
and the test suite will reject it.

## Layer 3: pacing

Defaults, all of which can be made stricter but not arbitrarily looser:

| Control | Default | Purpose |
| --- | --- | --- |
| Concurrent hosts | 1 | A device never competes with a neighbour for bandwidth |
| Connections per host | 1 | No connection table exhaustion on small stacks |
| Inter-packet delay | 250ms | Leaves the scan cycle room to breathe |
| Global packet ceiling | 4 per second | Bounds total load on a segment |
| Connect timeout | 3s | Fails fast rather than holding a socket |
| Read timeout | 3s | Same |
| Error rate abort | 20 percent | Stops the run when devices start not answering |

The error rate abort matters more than it looks. If a scan begins to provoke
failures, continuing is the worst possible action, so the engine stops on its own
rather than waiting for a human to notice.

## Layer 4: review before sending

`--dry-run` performs template selection and target expansion, then prints a hex
dump of every request that would be sent to every target, and exits without
opening a socket. The output is intended to be pasted into a change request.

## Layer 5: risk ratings

Every template declares one of three ratings.

- `safe`: a standard identification request that the protocol defines for this
  purpose, widely implemented, with no known adverse reports. Runs by default.
- `caution`: a legitimate read that some implementations handle poorly. Requires
  `--allow-risk caution`.
- `lab-only`: useful for research but not appropriate for production equipment.
  Requires `--allow-risk lab-only` and prints a warning naming each template.

The rating lives in the template so that the judgement travels with the probe and
can be revised by whoever learns something new about a device family.

## Layer 6: the fragile device deny list

Some device families are known to react badly to specific probes. Those pairings
live in a deny list that is consulted after a device has been identified, and a
matching probe is skipped with the reason recorded. The list is data, so it can
be extended by anyone who finds a new case, without a code change.

## Layer 7: the audit log

Every active run writes a JSON Lines audit file. One record per packet, with the
timestamp, target, template, risk rating, request bytes, response bytes and
outcome. Also recorded: the operator supplied reason for the scan, the exact
flags used, and the effective safety settings.

This exists because the honest answer to "what did your tool do to my network"
has to be a file, not a recollection.

## Running scans from the web interface

The bundled web interface can start a scan, but only when the server was started
with `--allow-active-scan`. Without that flag the scan endpoints are not
registered at all, so the default server has no code path that can emit a packet.

When the flag is present, the additional controls are:

- Bind to `127.0.0.1` on a random port, with a single use token that is exchanged
  for an `httpOnly` `SameSite=Strict` session cookie and then removed from the
  URL.
- Strict `Origin` and `Host` validation on every state changing request, which is
  what blocks DNS rebinding. A local web server that can reach a PLC is an
  attractive target, and the consequence of getting this wrong is not a data leak
  but traffic sent to control equipment.
- A pre-flight screen that lists the exact targets, templates, per probe bytes,
  estimated packet count and duration, and requires the operator to retype the
  target range to confirm.
- A heartbeat. If the browser stops reporting in, the run pauses. Nothing keeps
  running unattended.

## Reporting a safety problem

If you find a probe that misbehaves against real equipment, please open an issue
with the device model, firmware version and the template id. Reports that lead to
a deny list entry or a downgraded risk rating are the most valuable contributions
this project can receive.
