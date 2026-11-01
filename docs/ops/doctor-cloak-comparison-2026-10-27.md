# Compare cloak configuration inputs

Operators can compare two locally readable configuration files before a planned
network change:

```sh
onyx-server doctor /etc/onyx-server/onyx-server.toml --peer-config /private/peer-copy.toml
onyx-server doctor /etc/onyx-server/onyx-server.toml --peer-config /private/peer-copy.toml --json
```

The command loads both files through the normal validated configuration and
secret resolver. Filesystem permissions govern access to private configuration
and referenced files. Relative referenced-file paths follow the command's
working directory, as in ordinary startup loading. Both files resolve environment
references against this command's environment; remote environment values and
remote relative-file contents are not fetched. Supply local inputs that accurately
represent each intended deployment. Use the intended deployment build for this
comparison.

The result describes resolved inputs and effective values for that build.
Running-process configuration, key material, active epochs and historical-build
compatibility require separate evidence. Readiness remains `unknown`, with
runtime observations `null`; no listeners or peer metric requests are opened.
Supplying a metrics URL together with `--peer-config` is an argument error.

| Check | Meaning |
| --- | --- |
| `cloak_current` | Both current secret inputs are present and equal. Missing current inputs fail. |
| `cloak_previous` | Previous inputs have the same role and value. Both absent is `skipped`/not configured; this does not prove historical continuity. |
| `cloak_suffix` | Normalized public suffixes agree. |
| `cloak_mode` | Effective cloak modes agree. |
| `cloak_account` | Account-cloak policies agree. |
| `cloak_cadence` | Anonymous rotation cadences agree, including effective defaults. |

Output contains fixed categories and statuses. It includes no secret values,
derived key fingerprints, sample cloaks or supplied peer paths. Unreadable or
invalid input produces an unavailable comparison and failure status. The scoped
allocator wipes its owned allocations before freeing them on success and
failure paths; caller-owned environment memory remains outside that scope.

The feature is integrated into current source and tested on native Safe artifact
`43d703c0466ad1945f43b8765e338f41c4339997eb791f72ecd5a91a646b9a81`.
Module gates passed 96/96 in Debug and Safe; executable gates passed 4/4 in both,
including allocation-failure wiping checks. Actual human/JSON CLI comparisons
cover equality, mismatches, malformed/unreadable peer input and missing secrets.
Evidence: `.zig-cache/wave-9/combined-candidate-v2/doctor-cli.json` and the
source-promotion receipt. Full release acceptance and deployment remain pending.
