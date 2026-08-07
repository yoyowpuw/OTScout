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

There is no code path in this project that can encode a write.

Requests are not assembled from bytes supplied by a template. They are produced
by a closed set of builders in `internal/protocol`, and a template chooses among
them by name and supplies parameters. Nothing else can reach the wire. The
current set is seven builders: Modbus Read Device Identification, EtherNet/IP
List Identity, the S7comm connection request, setup and SZL read, and BACnet
Who-Is and ReadProperty.

Two things keep that set honest:

- `TestThePackageEncodesNoWrites` reads the protocol package's own source and
  fails when it exports a byte producing function that is not on a reviewed list,
  with a note saying which operation it encodes and why that is safe to send.
  Adding an eighth builder is therefore not a quiet commit. It is a diff that
  says, in words, that a new kind of packet may now reach industrial equipment.
- Where a template supplies a number that could change the operation, the builder
  bounds it. The Modbus function code and MEI type are fixed by the builder and
  the read code is clamped to the three the specification defines. Every one of
  the 256 values a template could carry is tested.

Write single coil, write multiple registers, the diagnostic subfunctions that
force listen-only mode or restart communications, BACnet WriteProperty and
ReinitializeDevice: none of these has an encoder here. A contributor cannot
submit a template that writes to a device, because there is nothing for such a
template to call.

## Layer 3: pacing

The engine sends one packet at a time, to one host at a time, over one
connection. There is no concurrency setting. Parallelism is the single change
most likely to turn a survey into an outage, so it is not a knob that can be
turned by accident, or at all.

The rest can be made stricter but not meaningfully looser:

| Control | Flag | Default | May be |
| --- | --- | --- | --- |
| Inter-packet delay | `--delay` | 250ms | Raised freely, lowered only to 50ms |
| Global packet ceiling | `--rate` | 4 per second | Lowered only |
| Connect timeout | `--connect-timeout` | 3s | Shortened, or raised to at most 30s |
| Read timeout | `--read-timeout` | 3s | Same |
| Error rate abort | `--abort-error-rate` | 20 percent | Lowered only |

The delay floor is generous because the packet ceiling is the real limit: at four
packets per second the engine already waits 250ms, so lowering the delay alone
buys nothing and cannot be used to hurry a run.

Timeouts are bounded in both directions. A longer wait is not the safe direction
here, because holding a socket open against a device with a small connection
table is itself a load.

The error rate abort matters more than it looks. If a scan begins to provoke
failures, continuing is the worst possible action, so the engine stops on its own
rather than waiting for a human to notice. It waits for at least five attempts
first, since one failure out of one attempt is a rate of 100 percent and means
nothing.

## Layer 4: review before sending

`--dry-run` performs template selection and target expansion, then prints a hex
dump of every request that would be sent to every target, and exits without
opening a socket. Templates held back by the risk gate are listed too, with their
bytes and the reason they are held back, because a reviewer is deciding what this
tool may do and not only what it is about to do.

The output also carries the effective limits and an estimated duration computed
from the same arithmetic the engine paces with, so the figure somebody plans a
maintenance window around cannot drift away from the run.

It is intended to be pasted into a change request.

To see the limits and the deny list without planning a scan at all, run
`otscout safety`.

## Layer 5: risk ratings

Every template declares one of three ratings.

- `safe`: a standard identification request that the protocol defines for this
  purpose, widely implemented, with no known adverse reports. Runs by default.
- `caution`: a legitimate read that some implementations handle poorly. Requires
  `--allow-risk caution`.
- `lab-only`: useful for research but not appropriate for production equipment.
  Requires `--allow-risk lab-only`.

A run allows only `safe` unless told otherwise. Anything above the ceiling is
skipped and reported by name, along with the flag that would include it, so an
operator who wanted it learns how to ask rather than concluding the template is
broken.

The point of the gate is not that a `caution` probe must never run. It is that
running one should be a sentence somebody typed.

The rating lives in the template so that the judgement travels with the probe and
can be revised by whoever learns something new about a device family.

## Layer 6: the fragile device deny list

Some device families react badly to particular probes, and some equipment should
not be probed at all. Both live in `internal/safety/data/fragile.yaml`. A matching
probe is skipped and the rule that skipped it is named in the output, so the
decision can be argued with rather than merely obeyed.

The list is consulted against what the run has learned about a device, which
means it can normally only stop the second and later probes of a host. That is
inherent: to know a device is fragile you have to know what it is, and to know
what it is you have to have asked it something. The first question asked of any
host is therefore always the safest one available.

There is a way around that, and it is the reason to run the passive path first.
Pass an existing inventory to `probe` and the deny list applies from the first
packet, because the identities are already known. For a safety instrumented
system that is the difference between one packet and none.

The list is short on purpose. An entry is a claim about how real equipment
behaves, and a guessed entry silently removes a device from every scan, which
from the outside looks identical to the device not being there. So a rule cites
what it rests on: either a published report, or a stated refusal to actively
probe a class of equipment. `TestEveryRuleCitesSomethingOrExplainsWhyNot` holds
the file to that.

Two kinds of entry are currently in it.

The first is a report. The SIMATIC S7-300 CPU family is documented to enter
defect mode under repeated packets to port 102, recovery needs a cold restart,
and Siemens states no fix is planned. So once a device identifies as an S7-300,
this tool stops speaking S7comm to it. It has already got what it came for.

The second is a policy. Safety instrumented systems are not probed, at all. A
safety controller exists to take a process to a safe state when something else
has already gone wrong, and it is the last automated thing between a plant and an
incident. The benefit of fingerprinting one is a slightly more complete
inventory; the cost of being wrong is a safety function. Nothing this tool
produces is worth that trade. Triconex, ProSafe-RS, Safety Manager and HIMax are
in the list, and passive capture identifies them at no risk.

## Layer 7: the audit log

An active run will not start without `--reason` and `--audit`. Neither is
defaulted: an audit path this tool chose is one the operator does not know
exists, and a reason this tool invented is not a reason.

The file is JSON Lines. A header naming the reason, the invocation and the
effective settings; one record per exchange with the timestamp, target,
template, risk rating, request bytes, response bytes, duration and outcome; and a
summary line at the end, so a truncated file is visibly truncated.

Skipped exchanges are recorded too, with the rule or flag that skipped them. A
run that sent almost nothing should be able to say why, rather than looking like
a run that found nothing.

Records are flushed as they happen rather than at the end, because the run that
matters most is the one that ends badly. An existing audit file is never
overwritten; the run is refused instead.

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
