# Security policy

## Reporting a vulnerability

Report security issues through GitHub private vulnerability reporting on this
repository, under the Security tab. Please do not open a public issue for
anything exploitable.

Include the version, the platform, and the smallest input that reproduces the
problem. If the finding involves the local web server, state whether
`--allow-active-scan` was in use, because that flag changes which code paths
exist.

We aim to acknowledge within 5 working days.

## What we consider a vulnerability

This project parses untrusted input and runs a local web server that can, when
explicitly enabled, send packets to control equipment. The following are in
scope.

- Any path where a crafted packet capture, Zeek log, Nmap file, advisory
  document or fingerprint template causes memory unsafety, a panic that survives
  the per-file recovery boundary, unbounded memory growth, or code execution.
- Any way to make the active prober send bytes that a loaded template did not
  declare, exceed the configured rate limits, or run a template whose risk rating
  was not permitted by the flags in effect.
- Any way to reach a scan endpoint without `--allow-active-scan`, or to reach any
  state changing endpoint without a valid session, including through DNS
  rebinding or a cross site request.
- Cross site scripting in the web interface or in a generated HTML report.
  Advisory text is third party content and is treated as untrusted.
- Token or session leakage, including into browser history, referrer headers or
  the audit log.

## What we do not consider a vulnerability

- Reachability of a device by the prober when the operator supplied the target
  range and confirmed the pre-flight. That is the tool working.
- Denial of service against a device caused by a template rated `caution` or
  `lab-only` that the operator explicitly enabled. Please still report it, as a
  safety issue rather than a security issue, so the rating or the deny list can be
  corrected. See [docs/SAFETY.md](docs/SAFETY.md).
- Findings that require an attacker to already have write access to the
  configuration directory or the template directory.

## Design commitments

These properties are tested and are intended to stay true.

- No telemetry, no analytics, no crash reporting, no update check. The only
  outbound connections are the advisory downloads in `otscout sync`.
- The default `otscout serve` has no registered route that can send a packet to a
  device.
- Fingerprint templates cannot express a write, a reset or a stop operation. This
  is enforced by the template loader, not by convention.
- Generated HTML reports contain no external references and execute no remote
  code.
