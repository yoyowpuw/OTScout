# OTScout

Safe ICS asset discovery and vulnerability correlation, in one binary.

Point OTScout at a packet capture or, when you choose to, at a network. It builds
an inventory of industrial control system assets, normalizes their vendor and
firmware identities, and correlates them against public security advisories to
produce a prioritized patch list with the evidence for every match.

The command is `otscout`.

## Why this exists

Public ICS advisories are not machine matchable. CISA publishes its ICS
advisories in CSAF 2.0, but the documents contain no CPE and no
`product_identification_helper`. A typical product tree looks like this:

```json
"product_tree": { "branches": [{ "category": "vendor", "name": "Hitachi Energy",
  "branches": [{ "category": "product_family", "name": "FOXMAN-UN",
    "branches": [
      { "category": "product_version", "name": "R15A" },
      { "category": "product_version", "name": "R16B_PC4" },
      { "category": "product_version_range", "name": "<R15A" }
    ]}]}]}
```

Product identity is free text, and versions use vendor specific schemes that no
semantic version comparator can order. Meanwhile a device on the wire reports
equally unstructured strings such as `Siemens`, `6ES7 214-1AG40-0XB0` and
`V4.5.1`.

The work that closes that gap is a normalization layer: vendor aliases, catalog
number parsers, and a firmware comparator per vendor. OTScout builds that layer
once and uses it on both sides, which is why discovery and correlation live in
the same tool rather than in two.

## Safety comes first

Active scanning in an OT network can disturb a running process. OTScout treats
that as a design constraint rather than a disclaimer.

- The passive path is the default and sends no packets at all.
- Active probes are read-only, and not by policy. Requests come from a closed set
  of builders, none of which encodes a write, a reset or a stop, and a test fails
  when that set changes without review. There is nothing for a hostile template
  to call.
- Probing is sequential: one host, one connection and one packet at a time. That
  is not a setting, and there is no flag to raise it.
- Pacing defaults to a 250ms gap and four packets per second. Every limit can be
  tightened and none can be meaningfully loosened.
- `--dry-run` prints a hex dump of every byte that would be sent, before anything
  is sent, in a form meant for a change request.
- Each template carries a risk rating, and anything above `safe` requires an
  explicit `--allow-risk` flag.
- Known fragile equipment is skipped by name, and safety instrumented systems are
  never probed at all.
- The run stops on its own if devices start failing to answer.
- An active run will not start without `--reason` and `--audit`, and every
  packet, skip and refusal lands in that file as it happens.
- Every template step has to have been answered by a device recorded in the
  golden corpus, so no probe reaches its first real test on somebody's plant
  floor.

Run `otscout safety` to print the limits and the deny list without planning a
scan, and see [docs/SAFETY.md](docs/SAFETY.md) for the full model.

## Install

```bash
go install github.com/yoyowpuw/OTScout/cmd/otscout@latest
```

Or build from source:

```bash
make build
```

## Quick start, without touching the network

```bash
# 1. Build an inventory from a capture you already have.
otscout ingest --pcap capture.pcapng --out site.assets.json

# 2. Download the advisory corpus.
otscout sync --dir corpus/

# 3. Correlate.
otscout match --inventory site.assets.json --corpus corpus/ --output site.findings.json

# 4. Read the result.
otscout report --findings site.findings.json --format html --output site-report.html
```

Step 4 writes a single self contained HTML file. It needs no server and makes no
network requests, so it opens from a USB stick on an isolated workstation.

To review the same data interactively:

```bash
otscout serve --assets site.assets.json --findings site.findings.json
```

The server binds to `127.0.0.1` on a random port and prints a URL containing a
single use token. It cannot start a scan unless you also pass
`--allow-active-scan`.

## The advisory corpus

`otscout sync` is the only command that talks to the internet, and it is not meant
to run on a plant network. Run it on a connected machine, copy the corpus
directory across, and use `--offline` on the isolated side.

```bash
# See every source, what it covers and under what terms.
otscout sync --list

# The default set, which is the sources that are public domain.
otscout sync --dir corpus/

# Add a vendor feed. These carry their own terms, so they are opt in.
otscout sync --dir corpus/ --source siemens-csaf --source cert-vde-csaf

# Add a vendor that is not built in, by domain. Its feed is located the way the
# CSAF specification says to, through security.txt and then the well-known path.
otscout sync --dir corpus/ --csaf-provider nozominetworks.com

# Refresh only what changed in the last month.
otscout sync --dir corpus/ --since 30

# On the air-gapped side, from the copied corpus.
otscout sync --dir corpus/ --offline
```

Sources are fetched conditionally, so a daily refresh of an existing corpus costs
a handful of requests and usually downloads nothing. A source that cannot be
reached does not abort the run: the rest of the corpus is still written, the
failure is recorded in `corpus/manifest.json`, and the exit status is non zero so
a scheduled job notices.

The corpus is a directory of sorted JSON lines rather than one blob, so it can be
committed to version control and a refresh reviewed as a diff. Two counters are
printed after every sync:

- **products with an unrecognised vendor**, meaning the vendor string in the
  advisory is not in the alias table
- **products with an unparsed version range**, meaning the range could not be
  understood and the matcher will report indeterminate rather than guess

Both are the highest value place to contribute. Each one you close turns a
shrugged answer into a real one.

Each source records its own licence and whether a corpus built from it may be
republished, because that question is much easier to answer while the data is
being downloaded than afterwards. A provider passed to `--csaf-provider` is always
recorded as not republishable, since OTScout cannot read that vendor's terms.

Discovery only ever reads from the domain it was given. A `security.txt` naming a
CSAF endpoint on an unrelated host is ignored, because that file is third party
input and following it anywhere would let whoever controls it aim OTScout at
anything.

## Matching, and why every finding explains itself

`otscout match` correlates the inventory against the corpus. It sends no packets
and needs no network.

```bash
otscout match --inventory site.assets.json --corpus corpus/

# Only the findings worth acting on without further checking.
otscout match --min-tier confirmed

# Only advisories from the last quarter.
otscout match --since 90
```

Findings are graded into three tiers, and the grade answers a specific question
rather than expressing a mood:

- **confirmed** means the device is identified precisely enough for the advisory
  to apply to it, and its version falls inside an affected range. An advisory
  stating that every SIMATIC S7-1200 is affected is confirmed against a device
  known to be an S7-1200, because the advisory itself made the family wide claim.
- **likely** means the device is identified, but its version could not be
  compared, usually because the device did not report one. Neither affected nor
  safe can be claimed, so neither is.
- **possible** means the advisory names something more specific than could be
  established. If the advisory covers CPU 1215C and all that is known is that the
  device is an S7-1200, that is a lead to check, not a conclusion.

A device whose version the corpus positively rules out produces no finding, and
those are counted, so that an empty result can be told apart from a run that did
nothing. Two vendors sharing a name is never a match on its own, and two order
codes that disagree end the comparison: they are different orderable items
whatever their marketing names have in common.

Every finding carries the whole chain: which vendor alias resolved, which product
designation matched and by what route, which version range was evaluated by which
comparator, and what that returned. Steps that failed are kept as well as steps
that passed, because knowing that a version check ran and could not answer is what
stops an engineer redoing it by hand.

## Reporting, for three different readers

`otscout report` renders a findings document into something somebody else can
read. It sends no packets and needs no network.

```bash
# The spreadsheet where triage actually happens.
otscout report --findings site.findings.json --format csv

# One self contained file to send or archive.
otscout report --findings site.findings.json --format html --output site-report.html

# A CSAF 2.0 VEX document, for tooling and for auditors.
otscout report --findings site.findings.json --format vex \
  --publisher "Example Water Authority" --publisher-namespace https://example.org
```

The **CSV** carries one row per finding, including the version check and the
matched advisory node, so the reasoning survives the trip into a spreadsheet. It
is written with a byte order mark, because Excel reads a bare UTF-8 file as the
local code page and mangles any vendor name with an accent in it.

The **HTML** report is one file with no external references at all: no web font,
no stylesheet, no script from anywhere else. It opens from a USB stick on a
workstation that has never had a route to the internet, and it prints. Every row
expands to show the evidence behind it, using no JavaScript, so the file is still
complete when it is opened in ten years by whatever is to hand.

The **VEX** document follows the CSAF 2.0 VEX profile, and only confirmed
findings are stated as `known_affected`. Anything weaker is
`under_investigation`, because a VEX is read by machines and repeated by people,
and a guess that travels as a fact is worse than no document. Every affected
product carries an action statement, which the profile requires and which is the
specification saying that telling somebody they are exposed without telling them
what to do is not useful.

Device addresses are left out of the VEX unless you pass `--include-addresses`.
The document is made to be handed to an auditor, a regulator or a partner, and
the addresses of exploitable equipment are the part of an inventory least suited
to leaving the site. Each product entry still says how many devices run it. The
sharing label defaults to `TLP:AMBER` and is set with `--tlp`.

A VEX has to name who is making the statement, so `--publisher` and
`--publisher-namespace` are required rather than defaulted. This tool is not the
issuer, and guessing one would put words in an organisation's mouth.

## Active discovery, when you decide to

Read the limits and the fragile device list first. Nothing is sent and no file is
written.

```bash
otscout safety
```

See what can be asked, and the exact bytes of each request. Also sends nothing.

```bash
otscout templates --bytes
```

There are four protocols. Modbus/TCP Read Device Identification, EtherNet/IP List
Identity, S7comm Read SZL and BACnet ReadProperty. Each is the call its protocol
defines for asking a device what it is, and each template cites the specification
it comes from.

Two of them need more than one packet. S7comm takes four, because a CPU will not
serve a diagnostic read until a connection is established and a PDU size
negotiated. BACnet takes five, because it keeps identity in one property per
read. The template says so, the dry run dumps every one of them, and the audit
file records each separately.

Then produce the review document. This performs target expansion and template
selection and prints a hex dump of every request, without opening a socket. It is
meant to be pasted into a change request.

```bash
otscout probe 10.10.0.0/24 --dry-run
```

Targets can be single addresses, CIDR prefixes, or inclusive `first-last` ranges,
given as arguments or with `--targets-from hosts.txt`. Host names are refused, so
that the audit file records the address that was contacted rather than the name
that was typed. A prefix wider than 4096 addresses is refused outright rather
than trimmed to fit, because scanning the first few thousand and reporting the
rest as empty is a false statement about a plant.

Then run it. Both flags are required, because a scan with no stated purpose and
no record is not something this tool will perform.

```bash
otscout probe 10.10.0.0/24 \
  --reason "quarterly inventory, work order 8812" \
  --audit runs/2026-03-02.jsonl \
  --out site.assets.json
```

Pass the inventory from the passive path and two things improve. The fragile
device rules apply from the first packet rather than the second, because the
equipment is already identified. And with `--only-known-ports`, templates run
only against ports that were actually seen open, so the scan stops knocking on
doors nobody has reported.

```bash
otscout probe --targets-from hosts.txt \
  --known site.assets.json --only-known-ports \
  --reason "quarterly inventory, work order 8812" \
  --audit runs/2026-03-02.jsonl
```

Narrow it further with `--template`, and reach a protocol on a non-standard port
with `--port`.

```bash
otscout probe 10.10.0.7 --template modbus-device-id --port 5020 ...
```

## Privacy

OTScout has no telemetry, no analytics, no crash reporting and no update check.
The only outbound connections it ever makes are the advisory downloads performed
by `otscout sync`, against the sources `otscout sync --list` prints. Everything
else runs entirely on your machine.

## Contributing

Fingerprint templates and vendor normalization rules are the parts that benefit
most from people who know specific equipment. One template is one pull request,
and the test harness replays recorded protocol responses so you can contribute
without owning the hardware. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/TEMPLATES.md](docs/TEMPLATES.md).

The recordings live in `internal/golden/corpus`, one file per exchange, pairing a
response frame with the identity it must produce. Adding one is the cheapest useful
contribution to this project and the only way a decoder change can be reviewed by
someone who does not own the device it affects. See
[docs/FIXTURES.md](docs/FIXTURES.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
