# Redacted preflight diagnostics

`onyx-server doctor <config> [metrics-url] [--json]` loads a candidate through
the shared quiet configuration loader and runs fixed, read-only checks. It
does not start the daemon or install a service. An explicit metrics URL causes
one bounded GET; omit the URL for offline configuration/certificate checks.

```sh
onyx-server doctor /path/to/candidate.toml --json
onyx-server doctor /path/to/candidate.toml http://127.0.0.1:9130/metrics --json
```

JSON goes to stdout. Text retains the existing doctor output on stderr. JSON
schema version 1 contains `mode`, `readiness`, `failed`, a `checks` array,
`report_build_version`, and optional `observations`. The build version identifies
the reporting binary; it does not identify a remote metrics endpoint.
The additive `service_environment` section shares setup's bounded OpenRC,
systemd and container-marker observations. Values distinguish `present`,
`absent`, and `unknown`; they describe marker evidence rather than a running
supervisor. Daemon, mesh and media readiness retain their separate checks.
The additive `service_plan` reports shipped OpenRC, systemd, foreground and
container template facts, including argv and preflight policy. Paths and
identities are examples, not observations of this host. Container and
foreground preflight is an explicit operator step; the Dockerfile does not
run it automatically. Manager status, file access, daemon readiness, network
reachability and host resource ceilings remain unknown. Doctor emits only
fixed template values here, never the candidate path or credentials.
Each check has a stable `id`, `status` (`pass`, `fail`, or `skipped`), `source`
setting/metric identifier, and a server-defined explanation in `detail`.
The same check records produce both representations. Exit status is 1 if a
check fails or configuration loading fails, 2 for invalid arguments, otherwise
0. A skipped check is unknown, not a successful observation.

Reports omit private configuration values, resolved secrets, candidate/certificate
paths, metrics URLs and certificate responder URLs. Anonymous cadence and the
account-cloak enabled/disabled setting are explicit nonsecret observations. Error names remain useful
without embedding the private input. Keep the candidate configuration and any
separately collected raw metrics private; redaction of this report does not
redact arbitrary files added to a support archive.

Checks cover incompatible I/O flags, the kTLS mode, configured mesh security
and cloak requirements, OCSP responder presence when enabled, TCP/established-link
handshake symptoms, and the partition gauge when supplied. Missing, negative,
fractional, nonfinite, overflowing, duplicated or malformed count gauges are
unknown. Numeric observations use the same single-pass parser as the health
checks: unsigned decimal counts only, with a one MiB input limit. They include
TCP and established-link counts, peer-health counts, partition and quorum
indicators, component count, and the fixed connection diagnostic event names.
Established links include both secured and plaintext S2S links; the legacy
`secured_links` field remains `null` because the aggregate gauge cannot
distinguish them. The `established_links` field reports that aggregate.
Metric freshness and negotiated capabilities are unknown from these gauges. Missing observations are `null`; offline reports have
`observations: null`. Unrecognized metric names and arbitrary labels are never
copied into the report. A reported
partition fails the relevant check. These observations describe the supplying
node and do not prove network-wide health or service readiness. Static cloak checks do not prove that keys
or settings agree between nodes.

Readiness remains **unknown** even when all available checks pass. Process
status, a valid config, a TCP connection and an established secured mesh link
prove different things. Doctor does not establish live client participation,
DNS/TLS reachability, media quality, native/browser compatibility or rolling
upgrade safety. Use the operational acceptance procedures for those claims.

This is the redacted diagnostic core for Q08/M01, not a complete live support
bundle: bounded connection traces, version/capability inventory and explicit
retention/export consent still need integrated acceptance.

The native CLI acceptance fixture is available on Linux:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/doctor_smoke.py --binary /path/to/onyx-server
```

It uses a private temporary candidate and a disposable loopback HTTP endpoint;
the daemon is never started. It checks offline unknown observations, one GET,
fixed numeric fields, private-input omission, duplicate counts, partition
failure and absence of generated state. Captures are bounded, private and
removed on exit. Its report identifies the tested artifact; fixture metrics
do not establish live mesh or media readiness.


## Anonymous cloak cadence

The `cloak_anon_cadence` check reports the effective `cloak.anon_epoch_secs`
interval in seconds in both text and JSON. The default is fourteen days
(1,209,600 seconds). A daily setting (86,400 seconds) receives an explicit prompt
to decide whether to retain it or adopt the default; custom intervals and zero
(disabled rotation) remain valid operator choices. The check does not change the
configuration or prove that another node has the same settings.

The report distinguishes account-cloak configuration from anonymous rotation.
Authenticated clients are excluded from anonymous rotation even when account
cloaks are disabled. This diagnostic does not imply that login immediately
replaces a host already displayed to other clients.


## Operator mesh snapshot

A cross-reactor MESH view requires a reactor-0 publication with owned peer
names, explicit freshness and separately observed plaintext and secured
transport state. Missing or stale information is unknown, not zero or proof
of health. Negotiated capability fields require actual peer observations;
the aggregate established-link metric cannot provide them. Integration and
nonzero-reactor acceptance are still required for such a production view.
