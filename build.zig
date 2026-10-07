// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Onyx Server targets 64-bit only (native x86_64/aarch64; the wasm32 browser
    // codec below is the lone, deliberate exception). Reject a 32-bit daemon
    // target at configure time with a clear message instead of a confusing later
    // failure.
    if (target.result.ptrBitWidth() != 64) {
        std.debug.panic(
            "Onyx Server is 64-bit only; target '{s}' is {d}-bit. Use a 64-bit target (e.g. x86_64-linux, aarch64-linux).",
            .{ @tagName(target.result.cpu.arch), target.result.ptrBitWidth() },
        );
    }

    // Strip debug info from optimized builds (smaller, faster-to-load binaries).
    // Debug builds keep symbols for backtraces; test binaries (below) always keep
    // them so failing-test traces stay readable.
    const strip_release = optimize != .Debug;

    // Focused testing: `zig build test -Dtest-filter=<substr>` runs only matching
    // tests — a big win on the full suite's compile+run time during iteration.
    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains the given substring") orelse &.{};

    // macOS/BSD reach the OS via libc (getentropy, clock_gettime, getpid) in
    // src/substrate/platform.zig. Linux uses raw syscalls (no libc) and Windows
    // uses ntdll/advapi32, so libc is linked only on the libc-mandatory targets.
    const os_tag = target.result.os.tag;
    const needs_libc = os_tag != .linux and os_tag != .windows;
    // The pinned Windows Zig compiler can abort without a diagnostic while
    // lowering the complete daemon through LLVM. Keep an explicit native
    // backend path so the executable and test gates remain buildable there.
    const windows_self_hosted = b.option(bool, "windows-self-hosted", "Use Zig's self-hosted Windows code generator for the daemon and test gates") orelse false;
    if (windows_self_hosted and (os_tag != .windows or
        b.graph.host.result.os.tag != .windows or
        target.result.cpu.arch != b.graph.host.result.cpu.arch))
        std.debug.panic("-Dwindows-self-hosted requires a native Windows target", .{});
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    const mod = b.addModule("onyx_server", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
        // Honor -Doptimize for the module (and thus `zig build test`): release
        // builds exercise codegen paths Debug never sees (the ReleaseFast
        // RSA inline-asm earlyclobber regression in crypto/rsa_verify.zig was
        // invisible to Debug-only test runs).
        .optimize = optimize,
        .link_libc = needs_libc,
    });

    // Embed the current git revision (short hash, suffixed "-dirty" when the
    // working tree has uncommitted changes) so the running binary can report
    // exactly which commit it was built from (banner + VERSION). Available to
    // module source as `@import("build_info").git_commit`.
    //
    // `gitCommit` reads HEAD via a subprocess at configure time. Zig 0.17's
    // CONFIGURATION cache cannot see that read, so when only the commit moved
    // (build.zig and every source file unchanged) `zig build` reused the cached
    // configuration — including the previously-generated options module — and
    // silently stamped the OLD commit: the banner, 002/004, and RPL_VERSION (351)
    // lagged HEAD, and a clean `zig build release` could ship mislabeled
    // provenance. Declaring a CONTENT dependency on the git ref files below folds
    // them into the configuration-cache key, so the configure phase re-runs — and
    // the stamp regenerates — the instant HEAD moves, while staying a fast cache
    // hit when it does not.
    //   * .git/HEAD      — moves on a branch switch / detached-HEAD update.
    //   * .git/logs/HEAD — the reflog, appended on every commit/checkout/reset/
    //                      fetch regardless of loose-vs-packed refs: the reliable
    //                      trigger for a commit on the current branch.
    //
    // Each dependency is wired ONLY when the file actually exists as a plain file
    // under a real `.git` DIRECTORY: `dependOnFileContents` hashes the file at
    // configure and hard-fails (FileNotFound / CacheCheckFailed) if it is absent
    // or if `.git` is a FILE (a linked worktree). So a `.git`-less source tarball
    // (git-archive) and a worktree build skip the dependency and keep working via
    // `gitCommit`'s subprocess fallback ("unknown" with no git, or the resolved
    // commit in a worktree); they simply do not auto-refresh the stamp on a bare
    // commit — an acceptable trade for not regressing those builds.
    if (gitRefExists(b, ".git/HEAD")) b.dependOnFileContents(b.path(".git/HEAD"));
    if (gitRefExists(b, ".git/logs/HEAD")) b.dependOnFileContents(b.path(".git/logs/HEAD"));
    const build_info = b.addOptions();
    const git = gitCommit(b);
    build_info.addOption([]const u8, "git_commit", git);
    // Composed release version "<semver>+<git-short-hash>" (semver build
    // metadata), e.g. "0.1.0+8fba2c5" or "0.1.0+8fba2c5-dirty". The semver
    // comes from build.zig.zon (single source of truth); the hash pins the
    // exact commit. This is what the banner, 002/004, and RPL_VERSION report.
    build_info.addOption([]const u8, "version", b.fmt("{s}+{s}", .{ manifestVersion(), git }));
    build_info.addOption(bool, "windows_rollover_smoke", false);
    const build_info_mod = build_info.createModule();
    mod.addImport("build_info", build_info_mod);

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "onyx-server",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .strip = strip_release,
            // List of modules available for import in source files part of the
            // root module.
            .imports = &.{
                // Here "onyx" is the name you will use in your source code to
                // import this module (e.g. `@import("onyx_server")`). The name is
                // repeated because you are allowed to rename your imports, which
                // can be extremely useful in case of collisions (which can happen
                // importing modules from different packages).
                .{ .name = "onyx_server", .module = mod },
            },
        }),
    });
    if (windows_self_hosted) exe.use_llvm = false;

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // A separate, explicitly requested Windows executable exercises automatic
    // descriptor rollover at process scale. Its marker hook is absent from the
    // normal daemon, checks, tests, and release artifact.
    const windows_rollover_smoke_step = b.step("windows-rollover-smoke-server", "Build the Windows automatic-rollover process smoke executable");
    if (os_tag == .windows) {
        const smoke_info = b.addOptions();
        smoke_info.addOption([]const u8, "git_commit", git);
        smoke_info.addOption([]const u8, "version", b.fmt("{s}+{s}", .{ manifestVersion(), git }));
        smoke_info.addOption(bool, "windows_rollover_smoke", true);
        const smoke_mod = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
        });
        smoke_mod.addImport("build_info", smoke_info.createModule());
        const smoke_exe = b.addExecutable(.{
            .name = "onyx-server-rollover-smoke",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = target,
                .optimize = optimize,
                .link_libc = needs_libc,
                .strip = strip_release,
                .imports = &.{.{ .name = "onyx_server", .module = smoke_mod }},
            }),
        });
        if (windows_self_hosted) smoke_exe.use_llvm = false;
        windows_rollover_smoke_step.dependOn(&b.addInstallArtifact(smoke_exe, .{}).step);
    }

    // Build-only: these probes must execute on an isolated OpenBSD machine.
    const openbsd_probes = b.step("openbsd-probes", "Build native OpenBSD Helix and worker acceptance probes");
    const probe_names = [_][]const u8{
        "openbsd_helix_primitives_probe",
        "openbsd_helix_sandbox_probe",
        "openbsd_worker_protocol_probe",
    };
    for (probe_names) |name| {
        const probe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("tools/{s}.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .link_libc = needs_libc,
                .imports = &.{.{ .name = "onyx_server", .module = mod }},
            }),
        });
        openbsd_probes.dependOn(&b.addInstallArtifact(probe, .{}).step);
    }

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    run_cmd.addPassthruArgs();

    const verbose_test_runner = std.Build.Step.Compile.TestRunner{
        .path = b.path("tools/verbose_test_runner.zig"),
        .mode = .simple,
    };

    // Creates an executable that will run `test` blocks from the provided module.
    // Here `mod` needs to define a target, which is why earlier we made sure to
    // set the relevant field.
    const mod_tests = b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
    });

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_mod_step = b.step("test-mod", "Run only the library/module test artifact; accepts -Dtest-filter=<text>");
    const mod_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_mod_tests_verbose = b.addRunArtifact(mod_tests_verbose);
    const test_mod_verbose_step = b.step("test-mod-verbose", "Run module tests with per-test progress output; accepts -Dtest-filter=<text>");
    // The pinned Zig Windows compiler exits without a diagnostic when emitting
    // the unfiltered ~10k-test root artifact. Filter by top-level source path
    // while retaining src/root.zig as the module root: direct package roots
    // cannot resolve their cross-package relative imports. The source root
    // imports only these five path families; anonymous root tests are included
    // by Zig in every filtered runner.
    const windows_full_shards = os_tag == .windows and test_filters.len == 0;
    const shard_names = [_][]const u8{ "crypto", "daemon", "proto", "substrate", "wasm" };
    const TestShard = struct {
        name: []const u8,
        compile: *std.Build.Step.Compile,
        run: *std.Build.Step.Run,
        verbose_compile: *std.Build.Step.Compile,
        verbose_run: *std.Build.Step.Run,
    };
    var test_shards: [shard_names.len]TestShard = undefined;
    if (windows_full_shards) {
        for (shard_names, 0..) |name, index| {
            const filters: []const []const u8 = &.{b.fmt("{s}.", .{name})};
            const compile = b.addTest(.{ .root_module = mod, .filters = filters });
            const verbose_compile = b.addTest(.{
                .root_module = mod,
                .filters = filters,
                .test_runner = verbose_test_runner,
            });
            test_shards[index] = .{
                .name = name,
                .compile = compile,
                .run = b.addRunArtifact(compile),
                .verbose_compile = verbose_compile,
                .verbose_run = b.addRunArtifact(verbose_compile),
            };
            // The default Zig test protocol times out on a few intentionally
            // expensive pure-Zig RSA cases in Windows Debug. The simple runner
            // has no per-test response watchdog and reports exact pass counts.
            test_mod_step.dependOn(&test_shards[index].verbose_run.step);
            test_mod_verbose_step.dependOn(&test_shards[index].verbose_run.step);
        }
    } else {
        test_mod_step.dependOn(&run_mod_tests.step);
        test_mod_verbose_step.dependOn(&run_mod_tests_verbose.step);
    }

    // Creates an executable that will run `test` blocks from the executable's
    // root module. Note that test executables only test one module at a time,
    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .filters = test_filters,
    });

    // A run step that will run the second test executable.
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_exe_step = b.step("test-exe", "Run only the daemon executable-root test artifact; accepts -Dtest-filter=<text>");
    test_exe_step.dependOn(&run_exe_tests.step);
    const exe_tests_verbose = b.addTest(.{
        .root_module = exe.root_module,
        .filters = test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_exe_tests_verbose = b.addRunArtifact(exe_tests_verbose);
    const test_exe_verbose_step = b.step("test-exe-verbose", "Run executable-root tests with per-test progress output; accepts -Dtest-filter=<text>");
    test_exe_verbose_step.dependOn(&run_exe_tests_verbose.step);

    const tls_test_filters: []const []const u8 = &.{
        "TLS",
        "tls",
        "mTLS",
        "RFC 7250",
        "CertificateRequest",
        "Encrypted Client Hello",
        "delegated credential",
        "record_size_limit",
        "raw public key",
        "exploit:",
    };
    const tls_tests = b.addTest(.{
        .root_module = mod,
        .filters = tls_test_filters,
    });
    const run_tls_tests = b.addRunArtifact(tls_tests);
    const test_tls_step = b.step("test-tls", "Run focused Armor TLS, mTLS, ECH, RPK, DC, and record-size tests");
    test_tls_step.dependOn(&run_tls_tests.step);
    const tls_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = tls_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_tls_tests_verbose = b.addRunArtifact(tls_tests_verbose);
    const test_tls_verbose_step = b.step("test-tls-verbose", "Run focused TLS tests with per-test progress output");
    test_tls_verbose_step.dependOn(&run_tls_tests_verbose.step);

    const server_test_filters: []const []const u8 = &.{
        "threaded server:",
        "exploit:",
        "tls13Config",
        "banContextFor",
        "SASL EXTERNAL",
        "CertFP",
        "raw-public-key",
        "raw public key",
        "WEBAUTHN",
        "vhost",
        "cloak",
    };
    const server_tests = b.addTest(.{
        .root_module = mod,
        .filters = server_test_filters,
    });
    const run_server_tests = b.addRunArtifact(server_tests);
    const test_server_step = b.step("test-server", "Run focused daemon/server integration and auth tests");
    test_server_step.dependOn(&run_server_tests.step);
    const server_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = server_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_server_tests_verbose = b.addRunArtifact(server_tests_verbose);
    const test_server_verbose_step = b.step("test-server-verbose", "Run focused server tests with per-test progress output");
    test_server_verbose_step.dependOn(&run_server_tests_verbose.step);

    // The adversarial exploit/attack corpus: every `test "exploit: ..."` drives
    // a hostile input at a daemon surface and asserts it FAILS CLOSED (rejects /
    // bounds / survives). These are ordinary tests that also run in the full
    // `zig build test`; this focused step (alias `test-attack`) runs just the
    // corpus with the count visible.
    const exploit_tests = b.addTest(.{
        .root_module = mod,
        .filters = &.{"exploit:"},
    });
    const run_exploit_tests = b.addRunArtifact(exploit_tests);
    const test_exploit_step = b.step("test-exploit", "Run the adversarial exploit/attack fail-closed corpus");
    test_exploit_step.dependOn(&run_exploit_tests.step);
    const test_attack_step = b.step("test-attack", "Alias of test-exploit: the adversarial fail-closed corpus");
    test_attack_step.dependOn(&run_exploit_tests.step);

    const config_test_filters: []const []const u8 = &.{
        "parseToml",
        "config",
        "Config",
        "loadFromText",
        "reference config",
    };
    const config_tests = b.addTest(.{
        .root_module = mod,
        .filters = config_test_filters,
    });
    const run_config_tests = b.addRunArtifact(config_tests);
    const test_config_step = b.step("test-config", "Run focused TOML/config parsing, boot projection, and reference-config tests");
    test_config_step.dependOn(&run_config_tests.step);
    const config_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = config_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_config_tests_verbose = b.addRunArtifact(config_tests_verbose);
    const test_config_verbose_step = b.step("test-config-verbose", "Run focused config tests with per-test progress output");
    test_config_verbose_step.dependOn(&run_config_tests_verbose.step);

    const ircx_test_filters: []const []const u8 = &.{
        "IRCX",
        "ISIRCX",
        "PROP",
        "ACCESS",
        "LISTX",
        "DATA",
        "MODEX",
        "SACCESS",
    };
    const ircx_tests = b.addTest(.{
        .root_module = mod,
        .filters = ircx_test_filters,
    });
    const run_ircx_tests = b.addRunArtifact(ircx_tests);
    const test_ircx_step = b.step("test-ircx", "Run focused IRCX, PROP, ACCESS, DATA, LISTX, MODEX, and SACCESS tests");
    test_ircx_step.dependOn(&run_ircx_tests.step);
    const ircx_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = ircx_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_ircx_tests_verbose = b.addRunArtifact(ircx_tests_verbose);
    const test_ircx_verbose_step = b.step("test-ircx-verbose", "Run focused IRCX tests with per-test progress output");
    test_ircx_verbose_step.dependOn(&run_ircx_tests_verbose.step);

    const event_test_filters: []const []const u8 = &.{
        "event spine",
        "event routing:",
        "EventCategory",
        "EVENT",
        "event-playback",
        "observe",
        "POLICY event",
    };
    const event_tests = b.addTest(.{
        .root_module = mod,
        .filters = event_test_filters,
    });
    const run_event_tests = b.addRunArtifact(event_tests);
    const test_event_step = b.step("test-event-spine", "Run focused event-spine, EVENT, observe, and playback tests");
    test_event_step.dependOn(&run_event_tests.step);
    const event_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = event_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_event_tests_verbose = b.addRunArtifact(event_tests_verbose);
    const test_event_verbose_step = b.step("test-event-spine-verbose", "Run focused event-spine tests with per-test progress output");
    test_event_verbose_step.dependOn(&run_event_tests_verbose.step);

    const mesh_test_filters: []const []const u8 = &.{
        "S2S",
        "s2s",
        "mesh",
        "Mesh",
        "secured link",
        "Undertow",
        "REPAIR",
        "repair",
        "squit",
        "CONNECT opens",
    };
    const mesh_tests = b.addTest(.{
        .root_module = mod,
        .filters = mesh_test_filters,
    });
    const run_mesh_tests = b.addRunArtifact(mesh_tests);
    const test_mesh_step = b.step("test-mesh", "Run focused Undertow mesh, S2S, repair, and secured-link tests");
    test_mesh_step.dependOn(&run_mesh_tests.step);
    const mesh_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = mesh_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_mesh_tests_verbose = b.addRunArtifact(mesh_tests_verbose);
    const test_mesh_verbose_step = b.step("test-mesh-verbose", "Run focused mesh/S2S tests with per-test progress output");
    test_mesh_verbose_step.dependOn(&run_mesh_tests_verbose.step);

    const media_test_filters: []const []const u8 = &.{
        "MEDIA",
        "media",
        "DTLS-SRTP",
        "SFU",
        "NativeMediaTransport",
        "NativeMedia",
        "WebTransport",
        "webtransport",
        "quic conn snapshot",
        "http3 snapshot",
        "HXWT",
        "HXQC",
        "RTP",
        "RTCP",
    };
    const media_tests = b.addTest(.{
        .root_module = mod,
        .filters = media_test_filters,
    });
    const run_media_tests = b.addRunArtifact(media_tests);
    const test_media_step = b.step("test-media", "Run focused media, DTLS-SRTP, SFU, native-media, WebTransport, RTP, and RTCP tests");
    test_media_step.dependOn(&run_media_tests.step);
    const media_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = media_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_media_tests_verbose = b.addRunArtifact(media_tests_verbose);
    const test_media_verbose_step = b.step("test-media-verbose", "Run focused media tests with per-test progress output");
    test_media_verbose_step.dependOn(&run_media_tests_verbose.step);

    const services_test_filters: []const []const u8 = &.{
        "services",
        "Services",
        "REGISTER",
        "IDENTIFY",
        "SASL",
        "TOTP",
        "WEBAUTHN",
        "SESSION",
        "MEMO",
        "SUCCESSOR",
        "account",
    };
    const services_tests = b.addTest(.{
        .root_module = mod,
        .filters = services_test_filters,
    });
    const run_services_tests = b.addRunArtifact(services_tests);
    const test_services_step = b.step("test-services", "Run focused services, account, SASL, TOTP, WebAuthn, session, and MEMO tests");
    test_services_step.dependOn(&run_services_tests.step);
    const services_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = services_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_services_tests_verbose = b.addRunArtifact(services_tests_verbose);
    const test_services_verbose_step = b.step("test-services-verbose", "Run focused services/auth tests with per-test progress output");
    test_services_verbose_step.dependOn(&run_services_tests_verbose.step);

    // Reusable-session correctness spans SessionStore, World projection,
    // portable credentials, mesh replication, and Helix. Keep a dedicated gate
    // so lower-case allocation-failure tests are not accidentally omitted by
    // the broader services filter.
    const session_test_filters: []const []const u8 = &.{
        "session",
        "Session",
        "SESSION",
        "token bind",
        "portable detached",
        "PreparedSessionRestore",
        "handoffExactSessionIdentity",
        "migration",
        "reclaim",
        "replica",
    };
    const session_tests = b.addTest(.{
        .root_module = mod,
        .filters = session_test_filters,
    });
    const run_session_tests = b.addRunArtifact(session_tests);
    const test_session_step = b.step("test-session", "Run reusable-session, migration, replica, World restore, and Helix session tests");
    test_session_step.dependOn(&run_session_tests.step);
    const session_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = session_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_session_tests_verbose = b.addRunArtifact(session_tests_verbose);
    const test_session_verbose_step = b.step("test-session-verbose", "Run reusable-session tests with per-test progress output");
    test_session_verbose_step.dependOn(&run_session_tests_verbose.step);

    const helix_test_filters: []const []const u8 = &.{
        "Helix",
        "helix",
        "UPGRADE",
        "upgrade",
        "migration",
        "resume",
        "capsule",
        "handoff",
        "media graph checkpoint",
        "Windows active",
        "Windows media custody",
        "HXWT",
        "HXQC",
        "HSSN",
        "capability",
    };
    const helix_tests = b.addTest(.{
        .root_module = mod,
        .filters = helix_test_filters,
    });
    const run_helix_tests = b.addRunArtifact(helix_tests);
    const test_helix_step = b.step("test-helix", "Run focused Helix upgrade, migration, resume, capsule, and handoff tests");
    test_helix_step.dependOn(&run_helix_tests.step);
    const helix_tests_verbose = b.addTest(.{
        .root_module = mod,
        .filters = helix_test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_helix_tests_verbose = b.addRunArtifact(helix_tests_verbose);
    const test_helix_verbose_step = b.step("test-helix-verbose", "Run focused Helix/upgrade tests with per-test progress output");
    test_helix_verbose_step.dependOn(&run_helix_tests_verbose.step);

    const dst_test_filters: []const []const u8 = &.{
        "DST:",
        "DST ",
        " DST",
        "timer-guard",
        "multi-shard USR2",
        "same seed reproduces",
        "partition prevents delivery",
        "clock advances monotonically",
        "drop rate roughly",
        "node reactor remains valid",
    };
    const dst_tests = b.addTest(.{
        .root_module = mod,
        .filters = dst_test_filters,
    });
    const run_dst_tests = b.addRunArtifact(dst_tests);
    const test_dst_step = b.step("test-dst", "Run seed-replayable DST, Sim, and ≥2-reactor timer-guard tests");
    test_dst_step.dependOn(&run_dst_tests.step);

    // `armor` — the standalone Armor crypto toolkit CLI (openssl-parity verbs,
    // every one a thin front-end over the src/crypto substrate). Declared like
    // the daemon executable: its own root module importing "onyx_server".
    const armor_exe = b.addExecutable(.{
        .name = "armor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli/armor_main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .strip = strip_release,
            .imports = &.{
                .{ .name = "onyx_server", .module = mod },
            },
        }),
    });
    if (windows_self_hosted) armor_exe.use_llvm = false;
    b.installArtifact(armor_exe);

    const cli_tests = b.addTest(.{
        .root_module = armor_exe.root_module,
        .filters = test_filters,
    });
    const run_cli_tests = b.addRunArtifact(cli_tests);
    const test_cli_step = b.step("test-cli", "Run the armor CLI toolkit tests; accepts -Dtest-filter=<text>");
    test_cli_step.dependOn(&run_cli_tests.step);
    const cli_tests_verbose = b.addTest(.{
        .root_module = armor_exe.root_module,
        .filters = test_filters,
        .test_runner = verbose_test_runner,
    });
    const run_cli_tests_verbose = b.addRunArtifact(cli_tests_verbose);
    const test_cli_verbose_step = b.step("test-cli-verbose", "Run armor CLI tests with per-test progress output");
    test_cli_verbose_step.dependOn(&run_cli_tests_verbose.step);

    // Cross-compiled test runners are copied to the target machine explicitly.
    const test_artifacts = b.step("test-artifacts", "Build and install module, daemon, and CLI test runners without executing them");
    const test_exe_suffix = if (os_tag == .windows) ".exe" else "";
    var shard_install_steps: [shard_names.len]*std.Build.Step = undefined;
    var mod_install_step: ?*std.Build.Step = null;
    if (windows_full_shards) {
        for (test_shards, 0..) |shard, index| {
            const install = b.addInstallFile(
                shard.compile.getEmittedBin(),
                b.fmt("bin/onyx-server-module-tests-{s}{s}", .{ shard.name, test_exe_suffix }),
            );
            shard_install_steps[index] = &install.step;
            test_artifacts.dependOn(&install.step);
        }
    } else {
        const install = b.addInstallFile(mod_tests.getEmittedBin(), b.fmt("bin/onyx-server-module-tests{s}", .{test_exe_suffix}));
        mod_install_step = &install.step;
        test_artifacts.dependOn(&install.step);
    }
    const exe_install = b.addInstallFile(exe_tests.getEmittedBin(), b.fmt("bin/onyx-server-daemon-tests{s}", .{test_exe_suffix}));
    const cli_install = b.addInstallFile(cli_tests.getEmittedBin(), b.fmt("bin/onyx-server-cli-tests{s}", .{test_exe_suffix}));
    test_artifacts.dependOn(&exe_install.step);
    test_artifacts.dependOn(&cli_install.step);

    // A top level step for running all tests. dependOn can be called multiple
    // times and since the two run steps do not depend on one another, this will
    // make the two of them run in parallel.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(test_mod_step);
    test_step.dependOn(&run_exe_tests.step);
    test_step.dependOn(&run_cli_tests.step);
    const test_verbose_step = b.step("test-verbose", "Run full tests with per-test progress output");
    test_verbose_step.dependOn(test_mod_verbose_step);
    test_verbose_step.dependOn(&run_exe_tests_verbose.step);
    test_verbose_step.dependOn(&run_cli_tests_verbose.step);

    // `zig build wasm` — compile the CadenceVox/CadenceVis codecs to a freestanding
    // WASM module for the in-browser client (#11/#32). Pure-integer +
    // allocation-free, so it needs no WASI/libc; the JS side drives it through
    // linear memory.
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm/cadence_wasm.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
        .strip = true,
    });
    // The codecs depend only on std, so expose them as standalone wasm-targeted
    // modules (the full onyx root pulls in io_uring/sockets and won't build
    // freestanding).
    const wasm_cadencevox = b.createModule(.{ .root_source_file = b.path("src/substrate/cadencevox_adpcm.zig"), .target = wasm_target, .optimize = .ReleaseSmall, .strip = true });
    const wasm_cadencevis = b.createModule(.{ .root_source_file = b.path("src/substrate/cadencevis_delta.zig"), .target = wasm_target, .optimize = .ReleaseSmall, .strip = true });
    wasm_mod.addImport("cadencevox_adpcm", wasm_cadencevox);
    wasm_mod.addImport("cadencevis_delta", wasm_cadencevis);
    const wasm = b.addExecutable(.{ .name = "cadence", .root_module = wasm_mod });
    wasm.entry = .disabled; // a library of exports, not an entry-point program
    wasm.rdynamic = true; // keep the `export fn`s in the final module
    const wasm_step = b.step("wasm", "Build the Ocean browser WASM modules");
    wasm_step.dependOn(&b.addInstallArtifact(wasm, .{}).step);

    // Browser transport shim (#32): line framing + IRCv3 parse/escape over the
    // browser's WebSocket byte stream. Imports the std-only `irc_line` parser by
    // relative path, so no extra module wiring is needed.
    const wasm_transport_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm_transport_root.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
        .strip = true,
    });
    const wasm_transport = b.addExecutable(.{ .name = "onyx_transport", .root_module = wasm_transport_mod });
    wasm_transport.entry = .disabled;
    wasm_transport.rdynamic = true;
    wasm_step.dependOn(&b.addInstallArtifact(wasm_transport, .{}).step);

    // `zig build check` — semantic analysis without producing a binary. This is
    // the fast inner-loop / editor (ZLS) target: it surfaces type errors quickly
    // and skips the (slow) machine-code emit + link the default install does.
    const check_step = b.step("check", "Type-check the daemon without emitting a binary");
    const check_exe = b.addExecutable(.{
        .name = "onyx-server-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    check_exe.generated_bin = .none; // analyze only; do not codegen/link an artifact
    check_step.dependOn(&check_exe.step);

    // Native Windows gate: exercise the socket/IOCP lifetime cases and the
    // daemon entry point without compiling or running the full module suite.
    const windows_io_tests = b.addTest(.{
        .root_module = mod,
        .filters = &.{
            "Windows socket descriptors preserve pointer-sized handles and retire stale ids",
            "Windows accepted TCP keepalive sets state and per-socket timing",
            "configured runtime: real cold listeners and complete worker inventory stay inert behind one Gate",
            "configured runtime: every owned allocation failure refunds construction and permits the same frozen inputs and source borrows to retry",
            "configured runtime: original graph publishes inline and sharded real transports then joins every source before disposal",
            "configured runtime: cloned full Mail policy rejects TLS credential trust and journal lineage mutation",
            "managed core: Windows cold boot proof owns its parsed policy and refuses leased custody before allocation",
            "managed core: original policy and install seals normalize before actual Services and live IRC",
            "IOCP transfer completion cannot exceed the submitted buffer",
            "IOCP cancellation identifies the original request",
            "Windows IOCP associates each socket lifetime and drains cancellation",
            "Windows IOCP quiesce drains more than 64 pending requests",
            "Windows IOCP quiesce retains pending recv and send buffers",
            "Windows IOCP delivers exact timeout tokens and cancels only the target",
            "Windows IOCP reuses timer storage after repeated expiry",
            "Windows AFD adopted sockets can half-close with a TCP FIN",
            "Windows IOCP ConnectEx completes loopback and cancels exact outbound token",
            "Windows IOCP AFD poll reports native loopback readiness masks",
            "IOCP AFD poll decodes output events instead of IOSB byte count",
            "Windows reactor wake reaches IOCP poll and drains without blocking",
            "Windows IOCP keeps slab status addresses stable across 320 pending accepts",
            "IOCP ready queue preserves order while growing past one submit batch",
            "Windows IOCP quiesce releases never-posted token registrations",
            "Windows exclusive dual-stack listener accepts through IOCP",
            "Windows IO backend listener rejects a reuse-address competing bind",
            "MetricsServer native Windows serves observed loopback listener",
            "WebhookServer Windows Winsock serves and retains a paused listener",
            "Windows runtime shutdown uses opaque IOCP socket descriptor",
            "Windows runtime file HANDLE registry roundtrips UTF-8 paths and duplicates",
            "Windows node keyfile",
            "DNS Windows native UDP",
            "http_fetch Windows",
            "Windows private account store",
            "Windows private ACL rejects an unrelated object owner",
            "Windows private directory handle pins file creation across path replacement",
            "Windows backup set requires private directories and protects published and restored files",
            "DST GAP-D6 backup set lists families and restores into a scratch directory",
            "DNSBL strict startup refuses missing nameservers and zones",
            "Windows DNSBL worker resolves listed and clean addresses and stops during a silent query",
            "Windows DNSBL listed verdict refuses a remote client and leaves unresolved clients open",
            "Windows SMTP loopback rejection records a private failure WAL",
            "Windows ACME HTTP-01 listener serves a challenge and joins a silent client",
            "Windows ACME private key publication requires a private parent and preserves owner-only ACL",
            "Windows ACME HTTPS sends JWS request to pinned loopback and verifies CA",
            "Windows TLS ACME loopback issuance serves HTTP-01 and publishes a private matching key",
            "Windows ACME renewal worker starts and joins without a certificate path",
            "Windows OCSP worker starts and joins without a certificate path",
            "Windows OCSP service accepts current issuer-signed HTTPS response and hands off staple",
            "Windows OCSP publication reaches TLS config with exact DER and exclusive expiry",
            "webpush Windows VAPID key requires private parent and persists with private custody",
            "webpush Windows HTTPS delivers encrypted POST and records 201 and 410",
            "Windows OCG2AUTH cold boot and restart preserve private durable authority",
            "Windows geo news cache reads regular UTF-8 files and rejects reparse points",
            "Windows GeoIP loads a bounded UTF-8 MMDB file and validates its contents",
            "Windows geo checked startup refuses disabled and frozen workers then starts",
            "WebTransportListener: bind, port, and clean re-startable shutdown",
            "WebTransportListener: live UDP QUIC/H3/WT session bridges IRC bytes both ways",
            "WebTransportListener: native IPv6 QUIC/H3/WT bridges IRC with mandatory PROXY header",
            "companion runtime webtransport real pump preserves Retry replay reset state and active guard",
            "MediaPlane: threaded pump answers a STUN check and binds the peer",
            "MediaPlane: start/shutdown is clean and re-startable port is reported",
            "NativeMediaTransport: pump learns sender + forwards an cadence frame to the receiver",
            "NativeMediaTransport: start/shutdown is clean and re-startable",
            "Windows Helix",
            "Windows native Helix listener manifest",
            "Windows transferred private WAL",
            "Windows transferred listener",
            "history native Windows transferred listener",
            "Windows channel stats publish replacement and restore from disk",
            "GAP-O3 a fault writes the tracelog to the named file",
            "Windows full daemon preflight permits selected listeners and refuses unverified features",
            "PortableServer defers full-queue disconnect until fanout completes",
        },
    });
    const run_windows_io_tests = b.addRunArtifact(windows_io_tests);
    const windows_exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .filters = &.{},
    });
    const run_windows_exe_tests = b.addRunArtifact(windows_exe_tests);
    const stack_tool = if (windows_self_hosted) b.addExecutable(.{
        .name = "windows-pe-stack",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/windows_pe_stack.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    }) else null;
    // Several full-server fixtures still construct Server by value before
    // initInPlace can place it on the heap. Their Debug frames exceed the
    // default Windows PE stack, including in focused suites that reuse `mod`.
    if (os_tag == .windows) {
        const windows_test_steps = [_]*std.Build.Step.Compile{
            mod_tests,              mod_tests_verbose,
            exe_tests,              exe_tests_verbose,
            tls_tests,              tls_tests_verbose,
            server_tests,           server_tests_verbose,
            exploit_tests,          config_tests,
            config_tests_verbose,   ircx_tests,
            ircx_tests_verbose,     event_tests,
            event_tests_verbose,    mesh_tests,
            mesh_tests_verbose,     media_tests,
            media_tests_verbose,    services_tests,
            services_tests_verbose, session_tests,
            session_tests_verbose,  helix_tests,
            helix_tests_verbose,    dst_tests,
            cli_tests,              cli_tests_verbose,
            windows_io_tests,       windows_exe_tests,
        };
        for (windows_test_steps) |step| {
            step.stack_size = 64 * 1024 * 1024;
            if (windows_self_hosted) step.use_llvm = false;
        }
        if (windows_full_shards) {
            for (test_shards) |shard| {
                shard.compile.stack_size = 64 * 1024 * 1024;
                shard.verbose_compile.stack_size = 64 * 1024 * 1024;
                if (windows_self_hosted) {
                    shard.compile.use_llvm = false;
                    shard.verbose_compile.use_llvm = false;
                }
            }
        }
        if (windows_self_hosted) {
            // Zig's self-hosted PE writer currently emits a 16 MiB stack even
            // when `--stack 67108864` is present. Patch the validated header
            // after compilation, before each test runner starts.
            const TestRun = struct {
                compile: *std.Build.Step.Compile,
                run: *std.Build.Step.Run,
            };
            const runs = [_]TestRun{
                .{ .compile = mod_tests, .run = run_mod_tests },
                .{ .compile = mod_tests_verbose, .run = run_mod_tests_verbose },
                .{ .compile = exe_tests, .run = run_exe_tests },
                .{ .compile = exe_tests_verbose, .run = run_exe_tests_verbose },
                .{ .compile = tls_tests, .run = run_tls_tests },
                .{ .compile = tls_tests_verbose, .run = run_tls_tests_verbose },
                .{ .compile = server_tests, .run = run_server_tests },
                .{ .compile = server_tests_verbose, .run = run_server_tests_verbose },
                .{ .compile = exploit_tests, .run = run_exploit_tests },
                .{ .compile = config_tests, .run = run_config_tests },
                .{ .compile = config_tests_verbose, .run = run_config_tests_verbose },
                .{ .compile = ircx_tests, .run = run_ircx_tests },
                .{ .compile = ircx_tests_verbose, .run = run_ircx_tests_verbose },
                .{ .compile = event_tests, .run = run_event_tests },
                .{ .compile = event_tests_verbose, .run = run_event_tests_verbose },
                .{ .compile = mesh_tests, .run = run_mesh_tests },
                .{ .compile = mesh_tests_verbose, .run = run_mesh_tests_verbose },
                .{ .compile = media_tests, .run = run_media_tests },
                .{ .compile = media_tests_verbose, .run = run_media_tests_verbose },
                .{ .compile = services_tests, .run = run_services_tests },
                .{ .compile = services_tests_verbose, .run = run_services_tests_verbose },
                .{ .compile = session_tests, .run = run_session_tests },
                .{ .compile = session_tests_verbose, .run = run_session_tests_verbose },
                .{ .compile = helix_tests, .run = run_helix_tests },
                .{ .compile = helix_tests_verbose, .run = run_helix_tests_verbose },
                .{ .compile = dst_tests, .run = run_dst_tests },
                .{ .compile = cli_tests, .run = run_cli_tests },
                .{ .compile = cli_tests_verbose, .run = run_cli_tests_verbose },
                .{ .compile = windows_io_tests, .run = run_windows_io_tests },
                .{ .compile = windows_exe_tests, .run = run_windows_exe_tests },
            };
            for (runs) |entry| {
                const patch_stack = patchWindowsTestStack(b, stack_tool.?, entry.compile, entry.run);
                if (entry.compile == mod_tests) {
                    if (mod_install_step) |install| install.dependOn(patch_stack);
                } else if (entry.compile == exe_tests) {
                    exe_install.step.dependOn(patch_stack);
                } else if (entry.compile == cli_tests) {
                    cli_install.step.dependOn(patch_stack);
                }
            }
            if (windows_full_shards) {
                for (test_shards, 0..) |shard, index| {
                    const patch_stack = patchWindowsTestStack(b, stack_tool.?, shard.compile, shard.run);
                    shard_install_steps[index].dependOn(patch_stack);
                    _ = patchWindowsTestStack(b, stack_tool.?, shard.verbose_compile, shard.verbose_run);
                }
            }
        }
    }
    const test_windows_step = b.step("test-windows", "Run native Windows socket/IOCP and daemon entry-point tests");
    test_windows_step.dependOn(&check_exe.step);
    test_windows_step.dependOn(&run_windows_io_tests.step);
    test_windows_step.dependOn(&run_windows_exe_tests.step);

    const test_smoke_step = b.step("test-smoke", "Run fast semantic + TLS/server/config smoke tests for roadmap iteration");
    test_smoke_step.dependOn(&check_exe.step);
    test_smoke_step.dependOn(&run_tls_tests.step);
    test_smoke_step.dependOn(&run_server_tests.step);
    test_smoke_step.dependOn(&run_config_tests.step);
    const test_smoke_verbose_step = b.step("test-smoke-verbose", "Run smoke tests with per-test progress output");
    test_smoke_verbose_step.dependOn(&check_exe.step);
    test_smoke_verbose_step.dependOn(&run_tls_tests_verbose.step);
    test_smoke_verbose_step.dependOn(&run_server_tests_verbose.step);
    test_smoke_verbose_step.dependOn(&run_config_tests_verbose.step);

    const test_roadmap_step = b.step("test-roadmap", "Run semantic check plus focused server roadmap suites");
    test_roadmap_step.dependOn(&check_exe.step);
    test_roadmap_step.dependOn(&run_server_tests.step);
    test_roadmap_step.dependOn(&run_config_tests.step);
    test_roadmap_step.dependOn(&run_ircx_tests.step);
    test_roadmap_step.dependOn(&run_event_tests.step);
    test_roadmap_step.dependOn(&run_mesh_tests.step);
    test_roadmap_step.dependOn(&run_services_tests.step);
    test_roadmap_step.dependOn(&run_session_tests.step);
    test_roadmap_step.dependOn(&run_tls_tests.step);
    const test_roadmap_verbose_step = b.step("test-roadmap-verbose", "Run focused server roadmap suites with per-test progress output");
    test_roadmap_verbose_step.dependOn(&check_exe.step);
    test_roadmap_verbose_step.dependOn(&run_server_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_config_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_ircx_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_event_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_mesh_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_services_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_session_tests_verbose.step);
    test_roadmap_verbose_step.dependOn(&run_tls_tests_verbose.step);

    // `zig build ct-check` — the opt-in, dudect-style constant-time verification
    // harness (roadmap 0.4). It measures execution-time independence from secret
    // inputs for ECDSA-P256 sign, X25519 scalar-mult, and the blinded RSA-2048
    // private op, reporting a Welch t-statistic per primitive.
    //
    // Deliberately a SEPARATE step, NOT part of `zig build test`: a timing
    // measurement is inherently noisy and folding it into the ~6100-test suite
    // would make the suite flaky. Sample counts are tunable via the CT_ITERS /
    // CT_RSA_ITERS environment variables (see the harness's module doc comment).
    //
    // The imported onyx crypto is built ReleaseFast in its OWN module (not the
    // shared `mod`, which inherits -Doptimize and is Debug when unset): the CT
    // claim is about the codegen that ships, and ReleaseFast has surfaced bugs
    // Debug never did (e.g. the rsa_verify inline-asm earlyclobber regression).
    const ct_onyx_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = needs_libc,
    });
    ct_onyx_mod.addImport("build_info", build_info_mod);
    const ct_check_exe = b.addExecutable(.{
        .name = "onyx-server-ct-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/constant_time_check.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = ct_onyx_mod }},
        }),
    });
    if (windows_self_hosted) ct_check_exe.use_llvm = false;
    const ct_check_run = b.addRunArtifact(ct_check_exe);
    const ct_check_step = b.step("ct-check", "Run the opt-in dudect-style constant-time verification harness (roadmap 0.4)");
    ct_check_step.dependOn(&ct_check_run.step);

    // `zig build bench` — the 0.7 measurement harness (release plan P0-1). It
    // measures the inbound line parse, outbound cap-variant tag composition, the
    // channel fan-out framing shape at widths 1..4096, the cross-shard delivery
    // fabric round-trip, and the loopback connection-accept rate. See the module
    // doc comment in src/substrate/bench.zig for what each row does and does NOT
    // cover, and docs/dev/benchmarks.md for how to run and read it.
    //
    // Deliberately a SEPARATE step, NOT part of `zig build test` (and not part of
    // `all-checks`): a wall-clock measurement is inherently noisy and folding it
    // into the full suite would make the suite flaky. Wiring it as a regression
    // tripwire is future work, and only once a baseline has proven stable across
    // machines. Same separation `ct-check` already uses.
    //
    // The harness gets its OWN ReleaseFast module rather than importing the shared
    // `mod` (which inherits -Doptimize and is Debug when unset). A Debug-built
    // benchmark measures Debug codegen, which is not what ships — the same
    // reasoning that gives `ct-check` and `release` their own modules. `-Doptimize`
    // is honored when passed explicitly so a Debug-vs-ReleaseFast comparison is
    // still possible on purpose; the run prints the mode it measured.
    const bench_optimize = if (b.user_input_options.contains("optimize")) optimize else .ReleaseFast;
    const bench_onyx_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
        .link_libc = needs_libc,
    });
    bench_onyx_mod.addImport("build_info", build_info_mod);
    const bench_exe = b.addExecutable(.{
        .name = "onyx-server-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/substrate/bench.zig"),
            .target = target,
            .optimize = bench_optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = bench_onyx_mod }},
        }),
    });
    if (windows_self_hosted) bench_exe.use_llvm = false;
    // Installed into zig-out/bin so `tools/bench.sh` can invoke it directly (and
    // re-run it under `taskset`/`nice` without going through the build graph).
    const bench_install = b.addInstallArtifact(bench_exe, .{});
    const bench_run = b.addRunArtifact(bench_exe);
    bench_run.step.dependOn(&bench_install.step);
    const bench_step = b.step("bench", "Run the 0.7 measurement harness: parse, tag compose, fan-out framing, cross-shard handoff, accept rate (P0-1)");
    bench_step.dependOn(&bench_run.step);

    // `zig build bench-live` — throwaway loopback daemon for the P0-1 axes the
    // offline harness cannot see (TLS / shards / ring_entries×cqe_batch, JOIN/
    // PRIVMSG RTT, RSS). Not part of `zig build test` or `bench`. The daemon is
    // its own ReleaseFast image (same optimize rule as `bench`) so a Debug
    // `zig-out/bin/onyx-server` is never measured by accident. Pass `-- --quick`
    // for one plaintext cell.
    const bench_live_exe = b.addExecutable(.{
        .name = "onyx-server-bench-live",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = bench_optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = bench_onyx_mod }},
        }),
    });
    if (windows_self_hosted) bench_live_exe.use_llvm = false;
    const bench_live_run = b.addSystemCommand(&.{"python3"});
    bench_live_run.addFileArg(b.path("tools/bench_live.py"));
    bench_live_run.addArg("--bin");
    bench_live_run.addArtifactArg(bench_live_exe);
    bench_live_run.addPassthruArgs();
    const bench_live_step = b.step("bench-live", "Live-daemon P0-1 axes: TLS/shards/ring JOIN+PRIVMSG RTT + RSS (throwaway loopback; not orochi)");
    bench_live_step.dependOn(&bench_live_run.step);

    // GAP-X5. Separate from `bench` so the default harness does not compile
    // server.zig. ReleaseFast, same rule as `bench`. Not part of `zig build test`.
    const bench_x5_exe = b.addExecutable(.{
        .name = "onyx-server-bench-gap-x5",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/substrate/bench_x5.zig"),
            .target = target,
            .optimize = bench_optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = bench_onyx_mod }},
        }),
    });
    if (windows_self_hosted) bench_x5_exe.use_llvm = false;
    const bench_x5_run = b.addRunArtifact(bench_x5_exe);
    bench_x5_run.addPassthruArgs();
    const bench_x5_step = b.step("bench-gap-x5", "GAP-X5: bytes per connection and microseconds per fan-out recipient (no shrink)");
    bench_x5_step.dependOn(&bench_x5_run.step);

    // `zig build fuzz` — the coverage-guided fuzz targets (roadmap 0.2 follow-up).
    // These are the `cov-fuzz:` tests in src/crypto/tls_fuzz.zig: one
    // `std.testing.fuzz` target per attacker-facing wire parser (X.509, TLS
    // record, OCSP, ClientHello/handshake, cert-compression inflate, SNI).
    //
    // Two modes, one step:
    //   * `zig build fuzz`         — replay each target's seed corpus once
    //                                (bounded, fast: a compile-and-no-crash gate).
    //   * `zig build fuzz --fuzz`  — drive the SAME targets coverage-guided via
    //                                Zig's builtin fuzzer (runs until stopped).
    //
    // Toolchain status (Zig 0.17.0-dev, re-verified 2026-07-07): the bounded
    // `zig build fuzz` mode compiles and passes. Coverage-guided `--fuzz` now
    // BUILDS, LINKS, and starts fuzzing (the Zig 0.16 test_runner StackTrace build
    // error is gone), but the compiler's own fuzzer runtime then crashes
    // deterministically (`panic: start index 1 is larger than end index 0`, a
    // slice-bounds bug in lib/zig/fuzzer.zig — reproducible with a trivial
    // zero-onyx target). See the TOOLCHAIN NOTE in src/crypto/tls_fuzz.zig.
    //
    // Kept SEPARATE from `zig build test` (which still runs these targets, but
    // only in bounded corpus-replay mode) so the fuzz filter never perturbs the
    // full ~6280-test suite, mirroring the ct-check step above. The test filter
    // scopes the artifact to just the `cov-fuzz:` targets so `--fuzz` fuzzes the
    // TLS parsers in isolation rather than every fuzz test in the tree.
    const fuzz_tests = b.addTest(.{
        .root_module = mod,
        .filters = &.{"cov-fuzz:"},
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    if (os_tag == .windows) {
        fuzz_tests.stack_size = 64 * 1024 * 1024;
        if (windows_self_hosted) {
            fuzz_tests.use_llvm = false;
            _ = patchWindowsTestStack(b, stack_tool.?, fuzz_tests, run_fuzz_tests);
        }
    }
    const fuzz_step = b.step("fuzz", "Run the coverage-guided TLS-parser fuzz targets (roadmap 0.2); add --fuzz to drive them coverage-guided");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // `zig build quic-interop-server` — a standalone test harness binary that
    // stands up the real `WebTransportListener` (QUIC/HTTP3) on an ephemeral UDP
    // port with a self-signed cert and blocks, so `tools/quic_interop.sh` can run
    // a real third-party HTTP/3 client (curl --http3) against it. Built into
    // zig-out/bin so the script finds it deterministically.
    const interop_exe = b.addExecutable(.{
        .name = "quic_interop_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/quic_interop_server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) interop_exe.use_llvm = false;
    const interop_step = b.step("quic-interop-server", "Build the standalone QUIC/HTTP3 interop test server");
    interop_step.dependOn(&b.addInstallArtifact(interop_exe, .{}).step);

    // `zig build quic-interop-wt-server` — the WebTransport-specific interop
    // server for a real browser (Chromium): an ECDSA-P256 short-validity cert
    // (Chrome's serverCertificateHashes requirement), a loopback TCP echo bridge
    // target, and the listener's WT datagram-echo mode. Driven by
    // `tools/quic_interop_browser.{mjs,sh}`.
    const interop_wt_exe = b.addExecutable(.{
        .name = "quic_interop_wt_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/quic_interop_wt_server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) interop_wt_exe.use_llvm = false;
    const interop_wt_step = b.step("quic-interop-wt-server", "Build the standalone WebTransport (browser) interop test server");
    interop_wt_step.dependOn(&b.addInstallArtifact(interop_wt_exe, .{}).step);

    // `zig build bogo-shim` — the roadmap-0.3 BoGo shim: a standalone tool that
    // speaks BoringSSL's `ssl/test/runner` shim contract (dial the runner's TCP
    // port, drive onyx's TlsConn/tls_client engine, XOR-echo, exit 0/89/nonzero)
    // so the external Go harness can protocol-test the Armor TLS stack. Kept out
    // of `zig build test` (it's a separate harness, not a unit-test module) and
    // linked to nothing in the daemon — it reuses the engines via the shared
    // `onyx_server` module exactly as `tools/quic_interop_server.zig` does.
    const bogo_shim_exe = b.addExecutable(.{
        .name = "bogo_shim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bogo_shim.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) bogo_shim_exe.use_llvm = false;
    const bogo_shim_install = b.addInstallArtifact(bogo_shim_exe, .{});
    const bogo_shim_step = b.step("bogo-shim", "Build the standalone BoGo (BoringSSL runner) TLS shim");
    bogo_shim_step.dependOn(&bogo_shim_install.step);

    const windows_helix_early_client = b.addExecutable(.{
        .name = "windows-helix-early-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/windows_helix_early_client.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) windows_helix_early_client.use_llvm = false;
    const windows_helix_early_client_step = b.step("windows-helix-early-client", "Build the native Zig TLS 0-RTT smoke client");
    windows_helix_early_client_step.dependOn(&b.addInstallArtifact(windows_helix_early_client, .{}).step);

    const windows_ocsp_client = b.addExecutable(.{
        .name = "windows-ocsp-client",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/windows_ocsp_client.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) windows_ocsp_client.use_llvm = false;
    const windows_ocsp_client_step = b.step("windows-ocsp-client", "Build the native Zig OCSP staple smoke client");
    windows_ocsp_client_step.dependOn(&b.addInstallArtifact(windows_ocsp_client, .{}).step);

    const windows_mail_relay = b.addExecutable(.{
        .name = "windows-mail-relay",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/windows_mail_relay.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    if (windows_self_hosted) windows_mail_relay.use_llvm = false;
    const windows_mail_relay_step = b.step("windows-mail-relay", "Build the pure Zig Windows STARTTLS mail smoke relay");
    windows_mail_relay_step.dependOn(&b.addInstallArtifact(windows_mail_relay, .{}).step);

    // `zig build bogo-shim-test` — the self-driven proof: builds+installs the
    // shim, then runs the shim file's own `test` blocks (parse + framing units,
    // plus subprocess exit-code smokes that spawn the installed binary and drive
    // it with onyx's own loopback engines). BOGO_SHIM_BIN points the subprocess
    // tests at the freshly-built binary; without it they skip.
    const bogo_shim_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/bogo_shim.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "onyx_server", .module = mod }},
        }),
    });
    const run_bogo_shim_tests = b.addRunArtifact(bogo_shim_tests);
    if (os_tag == .windows) {
        bogo_shim_tests.stack_size = 64 * 1024 * 1024;
        if (windows_self_hosted) {
            bogo_shim_tests.use_llvm = false;
            _ = patchWindowsTestStack(b, stack_tool.?, bogo_shim_tests, run_bogo_shim_tests);
        }
    }
    // The subprocess smokes spawn the freshly-installed binary via BOGO_SHIM_BIN.
    // This assumes the DEFAULT install prefix (`<build_root>/zig-out`); a `-p`
    // override is not resolved here, so run this step without `-p`. (When the
    // shim test binary is run OUTSIDE this step — e.g. by hand — BOGO_SHIM_BIN is
    // unset and the subprocess smokes skip; the pure parse/framing tests run.)
    run_bogo_shim_tests.setEnvironmentVariable(
        "BOGO_SHIM_BIN",
        b.pathJoin(&.{ b.root.root_dir.path orelse ".", "zig-out", "bin", if (os_tag == .windows) "bogo_shim.exe" else "bogo_shim" }),
    );
    run_bogo_shim_tests.step.dependOn(&bogo_shim_install.step);
    const bogo_shim_test_step = b.step("bogo-shim-test", "Build + self-drive the BoGo shim (loopback exit-code smokes; no external harness)");
    bogo_shim_test_step.dependOn(&run_bogo_shim_tests.step);

    const all_checks_step = b.step("all-checks", "Run deterministic pre-push checks: check, wasm, full tests, bounded fuzz replay, and BoGo shim self-tests");
    all_checks_step.dependOn(&check_exe.step);
    all_checks_step.dependOn(wasm_step);
    all_checks_step.dependOn(&run_mod_tests.step);
    all_checks_step.dependOn(&run_exe_tests.step);
    all_checks_step.dependOn(&run_fuzz_tests.step);
    all_checks_step.dependOn(&run_bogo_shim_tests.step);
    const all_checks_verbose_step = b.step("all-checks-verbose", "Run deterministic pre-push checks with per-test progress output for the full suite");
    all_checks_verbose_step.dependOn(&check_exe.step);
    all_checks_verbose_step.dependOn(wasm_step);
    all_checks_verbose_step.dependOn(&run_mod_tests_verbose.step);
    all_checks_verbose_step.dependOn(&run_exe_tests_verbose.step);
    all_checks_verbose_step.dependOn(&run_fuzz_tests.step);
    all_checks_verbose_step.dependOn(&run_bogo_shim_tests.step);

    // `zig build release` — one-shot optimized, stripped daemon (ReleaseFast)
    // installed to zig-out/bin, independent of the default step's optimize mode.
    //
    // The daemon CORE gets its own ReleaseFast module here. Importing the shared
    // `mod` would inherit the default -Doptimize (Debug when unset) — the shim
    // main.zig would be ReleaseFast wrapping a Debug daemon core, which is
    // exactly the silent mis-deploy this step exists to prevent. (Shipped that
    // way twice before this was caught: the 351 VERSION line said `,Debug`.)
    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = needs_libc,
        .strip = true,
    });
    release_mod.addImport("build_info", build_info_mod);
    const release_step = b.step("release", "Build an optimized, stripped daemon (ReleaseFast)");
    const release_exe = b.addExecutable(.{
        .name = "onyx-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = needs_libc,
            .strip = true,
            .imports = &.{.{ .name = "onyx_server", .module = release_mod }},
        }),
    });
    if (windows_self_hosted) release_exe.use_llvm = false;
    const release_install = b.addInstallArtifact(release_exe, .{});
    release_step.dependOn(&release_install.step);

    // `zig build package` — a deployment bundle: the optimized daemon binary plus
    // the operational assets an operator needs to stand a node up, all staged into
    // the install prefix (`zig-out/` by default; override with `--prefix`). This
    // does NOT touch the default install step — it's an explicit, separate step so
    // `zig build` stays a plain binary install.
    //
    // Layout under <prefix>:
    //   bin/onyx-server                              (ReleaseFast, stripped)
    //   etc/onyx-server/onyx-server.reference.toml   (annotated reference config)
    //   etc/onyx-server/onyx-server.windows.quickstart.toml (Windows only)
    //   lib/systemd/system/onyx-server.service       (Linux only)
    //   libexec/onyx-server-helper                   (OpenBSD only)
    //   libexec/onyx-server-policy                   (OpenBSD only)
    //   etc/rc.d/onyx_server                        (OpenBSD only)
    // The helper is a separate, non-setuid executable. Keep its privileged
    // boundary in ReleaseSafe even when the daemon package uses ReleaseFast.
    const helper_step = b.step("native-service-helper", "Build and stage the OpenBSD service helper (ReleaseSafe) in libexec");
    const policy_step = b.step("native-service-policy", "Build and stage the strict OpenBSD NSCF policy compiler in libexec");
    const openbsd_assets = b.step("openbsd-service-assets", "Stage the OpenBSD helper, rc.d script and reference config");
    const reference_install = b.addInstallFile(b.path("etc/onyx-server.reference.toml"), "etc/onyx-server/onyx-server.reference.toml");
    const openbsd_package_permissions = if (os_tag == .openbsd) blk: {
        const helper_exe = b.addExecutable(.{
            .name = "onyx-server-helper",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/native_service_helper_main.zig"),
                .target = target,
                .optimize = .ReleaseSafe,
                .link_libc = true,
                .strip = true,
            }),
        });
        const install = b.addInstallArtifact(helper_exe, .{ .dest_dir = .{ .override = .{ .custom = "libexec" } } });
        const policy_exe = b.addExecutable(.{
            .name = "onyx-server-policy",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/native_service_policy_main.zig"),
                .target = target,
                .optimize = .ReleaseSafe,
                .link_libc = true,
                .strip = true,
            }),
        });
        const policy_install = b.addInstallArtifact(policy_exe, .{ .dest_dir = .{ .override = .{ .custom = "libexec" } } });
        const permission_tool = b.addExecutable(.{
            .name = "stage-openbsd-service",
            .root_module = b.createModule(.{
                .root_source_file = b.path("tools/stage_openbsd_service.zig"),
                .target = b.graph.host,
                .optimize = .ReleaseSafe,
                .link_libc = b.graph.host.result.os.tag != .linux and b.graph.host.result.os.tag != .windows,
            }),
        });
        const helper_permissions = b.addRunArtifact(permission_tool);
        helper_permissions.addArg("helper");
        helper_permissions.addDirectoryArg2(.{ .relative = .{ .base = .install_prefix } }, .{});
        helper_permissions.has_side_effects = true;
        helper_permissions.step.dependOn(&install.step);
        helper_step.dependOn(&helper_permissions.step);
        const policy_permissions = b.addRunArtifact(permission_tool);
        policy_permissions.addArg("policy");
        policy_permissions.addDirectoryArg2(.{ .relative = .{ .base = .install_prefix } }, .{});
        policy_permissions.has_side_effects = true;
        policy_permissions.step.dependOn(&policy_install.step);
        policy_step.dependOn(&policy_permissions.step);
        const asset_permissions = b.addRunArtifact(permission_tool);
        asset_permissions.addArg("assets");
        asset_permissions.addDirectoryArg2(.{ .relative = .{ .base = .install_prefix } }, .{});
        asset_permissions.has_side_effects = true;
        asset_permissions.step.dependOn(&helper_permissions.step);
        asset_permissions.step.dependOn(&policy_permissions.step);
        asset_permissions.step.dependOn(&b.addInstallFile(b.path("etc/rc.d/onyx_server"), "etc/rc.d/onyx_server").step);
        asset_permissions.step.dependOn(&reference_install.step);
        openbsd_assets.dependOn(&asset_permissions.step);
        const package_permissions = b.addRunArtifact(permission_tool);
        package_permissions.addArg("package");
        package_permissions.addDirectoryArg2(.{ .relative = .{ .base = .install_prefix } }, .{});
        package_permissions.has_side_effects = true;
        package_permissions.step.dependOn(&asset_permissions.step);
        package_permissions.step.dependOn(&release_install.step);
        break :blk package_permissions;
    } else blk: {
        helper_step.dependOn(&b.addFail("native-service-helper requires an OpenBSD target; use -Dtarget=x86_64-openbsd").step);
        policy_step.dependOn(&b.addFail("native-service-policy requires an OpenBSD target; use -Dtarget=x86_64-openbsd").step);
        openbsd_assets.dependOn(&b.addFail("openbsd-service-assets requires an OpenBSD target").step);
        break :blk null;
    };

    const package_step = b.step("package", "Stage the daemon, reference config and target-specific deployment assets into the install prefix");
    package_step.dependOn(&release_install.step);
    package_step.dependOn(&reference_install.step);
    if (os_tag == .linux) {
        package_step.dependOn(&b.addInstallFile(b.path("etc/systemd/onyx-server.service"), "lib/systemd/system/onyx-server.service").step);
    } else if (os_tag == .windows) {
        package_step.dependOn(&b.addInstallFile(b.path("packaging/onyx-server.windows.quickstart.toml"), "etc/onyx-server/onyx-server.windows.quickstart.toml").step);
    }
    if (openbsd_package_permissions) |permissions| package_step.dependOn(&permissions.step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}

fn patchWindowsTestStack(b: *std.Build, stack_tool: *std.Build.Step.Compile, compile: *std.Build.Step.Compile, run: *std.Build.Step.Run) *std.Build.Step {
    const patch_stack = b.addRunArtifact(stack_tool);
    patch_stack.addFileArg(compile.getEmittedBin());
    run.step.dependOn(&patch_stack.step);
    return &patch_stack.step;
}

/// Extract the semantic version from build.zig.zon — the manifest is the single
/// source of truth, embedded at comptime so the build script and the manifest
/// can never drift. (A typed `@import` of the manifest would break whenever a
/// field is added, e.g. the first dependency; a substring scan of the embedded
/// text is immune to that.)
fn manifestVersion() []const u8 {
    const manifest = @embedFile("build.zig.zon");
    const key = ".version = \"";
    const start = (std.mem.indexOf(u8, manifest, key) orelse return "0.0.0") + key.len;
    const end = std.mem.indexOfScalarPos(u8, manifest, start, '"') orelse return "0.0.0";
    return manifest[start..end];
}

/// Capture the current git revision at configure time: the short commit hash,
/// suffixed "-dirty" when the working tree has uncommitted changes. Returns
/// "unknown" when git is unavailable or this is not a checkout, so builds from a
/// source tarball still succeed. The `-C <build_root>` keeps it correct
/// regardless of the build's working directory.
/// Whether `rel` (relative to the build root, which is the process cwd during
/// `zig build`) exists as an accessible plain file. Guards the configure-time
/// `dependOnFileContents` calls so a `.git`-less tarball or a linked-worktree
/// checkout (where `.git` is a FILE, making `.git/HEAD` unresolvable) skips the
/// dependency instead of hard-failing the configure phase.
fn gitRefExists(b: *std.Build, rel: []const u8) bool {
    std.Io.Dir.cwd().access(b.graph.io, rel, .{}) catch return false;
    return true;
}

fn gitCommit(b: *std.Build) []const u8 {
    const root = b.root.root_dir.path orelse ".";
    const hash = b.runAllowFail(
        &.{ "git", "-C", root, "rev-parse", "--short", "HEAD" },
        &code,
        .ignore,
    ) catch return "unknown";
    const short = std.mem.trim(u8, hash, " \r\n\t");
    if (short.len == 0) return "unknown";

    const status = b.runAllowFail(
        &.{ "git", "-C", root, "status", "--porcelain", "--untracked-files=no" },
        &code,
        .ignore,
    ) catch "";
    const dirty = std.mem.trim(u8, status, " \r\n\t").len != 0;
    return if (dirty) b.fmt("{s}-dirty", .{short}) else b.dupe(short);
}

var code: u8 = 0;
