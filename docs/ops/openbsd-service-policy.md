# OpenBSD service policy

The managed service helper reads canonical binary NSCF from
`/etc/onyx-server/service.nscf`. The separate `onyx-server-policy` tool compiles
explicit JSON configuration into that format. It does not create an account,
configure a login class, start the daemon, or prove readiness. The helper checks
the protected policy file and the actual selected process context separately.

Build and stage the compiler with:

```sh
zig build native-service-policy -Dtarget=x86_64-openbsd
```

`openbsd-service-assets` and `package` also install it in `libexec`, alongside
the helper. Both executables use ReleaseSafe. On the target, after selecting
the actual account, login class and root-owned protected paths, create the policy:

```sh
doas /usr/local/libexec/onyx-server-policy \
    /etc/onyx-server/service.json /etc/onyx-server/service.nscf
```

The output must be an absolute canonical path. Its parent must already exist.
The compiler publishes complete bytes with mode0600, and refuses an existing
file or symlink. It does not overwrite a live policy. Run it as root to produce
the ownership required by the helper. Protect the JSON source and every policy
ancestor from group/world writes as well.

All fields below are mandatory. These numbers illustrate the format; select
the account's actual UID, primary GID and complete sorted supplementary groups,
and limit rules that match the selected login class and configured daemon's
resource requirements. The compiler does not supply missing values.

```json
{
  "helper": "/usr/local/libexec/onyx-server-helper",
  "executable": "/usr/local/bin/onyx-server",
  "config": "/etc/onyx-server/onyx-server.toml",
  "cwd": "/var/onyx-server",
  "user": "_onyx",
  "class": "onyx",
  "uid": 1001,
  "gid": 1001,
  "groups": [1001, 1002],
  "rtable": 0,
  "limits": {
    "cputime": {"min_soft": 60, "max_soft": 60, "max_hard": 120},
    "filesize": {"min_soft": 8388608, "max_soft": 8388608, "max_hard": 16777216},
    "datasize": {"min_soft": 134217728, "max_soft": 134217728, "max_hard": 268435456},
    "stacksize": {"min_soft": 8388608, "max_soft": 8388608, "max_hard": 8388608},
    "coredumpsize": {"min_soft": 0, "max_soft": 0, "max_hard": 0},
    "memoryuse": {"min_soft": 67108864, "max_soft": 67108864, "max_hard": 134217728},
    "memorylocked": {"min_soft": 65536, "max_soft": 65536, "max_hard": 65536},
    "maxproc": {"min_soft": 16, "max_soft": 16, "max_hard": 32},
    "openfiles": {"min_soft": 64, "max_soft": 128, "max_hard": 128}
  }
}
```

Limit names map to OpenBSD RLIMIT0..8 in the displayed order. Each rule requires
`min_soft <= max_soft <= max_hard`. CPU values are seconds; file, data, stack,
core, resident memory and locked memory values are bytes; process and open-file
values are counts. The helper permits only the existing daemon normalization
of the open-file soft limit to its actual hard limit; the selected openfiles
rule must allow both observations. It requires all other actual observations
to remain identical across the child-to-daemon exec.

JSON input is bounded to16KiB. Duplicate fields, unknown fields, missing fields,
invalid canonical paths, root UID/GID, unsorted/duplicate groups, more than16
groups and invalid routing-table/limit ranges refuse compilation. The NSCF
loader remains responsible for root ownership, protected ancestors and actual
execution-policy enforcement.

Current verification is bounded host compiler tests and cross-built OpenBSD
assets. Actual target policy publication and the complete installed rcctl
lifecycle/reboot journey remain required acceptance gates.
