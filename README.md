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
- Active probes are read-only. The template schema cannot express a write, a
  reset or a stop, so no template can be authored that changes device state.
- Probing is sequential, one host and one connection at a time, with a delay
  between packets and a global packet rate ceiling.
- `--dry-run` prints a hex dump of every byte that would be sent, before
  anything is sent.
- Each template carries a risk rating, and anything above `safe` requires an
  explicit `--allow-risk` flag.
- Every packet sent is written to an audit log suitable for change management
  paperwork.

See [docs/SAFETY.md](docs/SAFETY.md) for the full model.

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
otscout report --findings site.findings.json --format html --out site-report.html
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

## Active discovery, when you decide to

```bash
# Show exactly what would be sent, and send nothing.
otscout probe --targets 10.10.0.0/24 --dry-run

# Run it.
otscout probe --targets 10.10.0.0/24 --out site.assets.json --audit audit/
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
