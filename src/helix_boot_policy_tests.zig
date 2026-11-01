// Focused boot-policy carry proof; full lifecycle acceptance remains required.
const std = @import("std");
const live = @import("daemon/helix/live.zig");
const t = std.testing;

fn equalPlans(left: live.ExecPlan, right: live.ExecPlan) !void {
    try t.expectEqual(left.arena_fd, right.arena_fd);
    try t.expectEqual(left.control_fd, right.control_fd);
    try t.expectEqual(left.argv.len, right.argv.len);
    try t.expectEqual(left.envp.len, right.envp.len);
    for (left.argv, right.argv) |a, b| try t.expectEqualStrings(a, b);
    for (left.envp, right.envp) |a, b| try t.expectEqualStrings(a, b);
}
test "boot policy empty wrappers preserve all four legacy vectors exactly" {
    const a = t.allocator;
    var old = try live.buildExecPlan(a, "/private/onyx-server", 10, 11);
    defer old.deinit(a);
    var new = try live.buildExecPlanWithBootPolicy(a, "/private/onyx-server", 10, 11, .{});
    defer new.deinit(a);
    try equalPlans(old, new);
    var ol = try live.buildExecPlanWithListener(a, "/private/onyx-server", 10, 11, 12);
    defer ol.deinit(a);
    var nl = try live.buildExecPlanWithListenerAndBootPolicy(a, "/private/onyx-server", 10, 11, 12, .{});
    defer nl.deinit(a);
    try equalPlans(ol, nl);
    var lr = try live.buildListenerExecPlan(a, "/private/onyx-server", 12, "/private/config");
    defer lr.deinit(a);
    var nr = try live.buildListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 12, "/private/config", .{});
    defer nr.deinit(a);
    try equalPlans(lr, nr);
    var la = try live.buildArenaListenerExecPlan(a, "/private/onyx-server", 10, &.{ 12, 13 }, &.{14}, "/private/config");
    defer la.deinit(a);
    var na = try live.buildArenaListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 10, &.{ 12, 13 }, &.{14}, "/private/config", .{});
    defer na.deinit(a);
    try equalPlans(la, na);
}
test "boot policy carries strict supervisor flag and only explicit stable config bindings" {
    const a = t.allocator;
    var secret = "private-config-value".*;
    defer std.crypto.secureZero(u8, &secret);
    const bindings = [_]live.EnvBinding{.{ .name = "ONYX_CONFIG_SECRET", .value = &secret }};
    var plan = try live.buildArenaListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 10, &.{12}, &.{}, "/private/config", .{ .strict_existing_identity = true, .config_env = &bindings });
    defer plan.deinit(a);
    try t.expectEqual(@as(usize, 4), plan.argv.len);
    try t.expectEqualStrings("--supervisor", plan.argv[1]);
    try t.expectEqualStrings("/private/config", plan.argv[2]);
    try t.expectEqualStrings(live.strict_existing_identity_arg, plan.argv[3]);
    try t.expectEqual(@as(usize, 3), plan.envp.len);
    secret[0] = 'X';
    try t.expectEqualStrings("ONYX_CONFIG_SECRET=private-config-value", plan.envp[2]);
    for (plan.argv) |arg| try t.expect(std.mem.indexOf(u8, arg, "private-config-value") == null);
    var env_only = try live.buildListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 12, null, .{ .config_env = &bindings });
    defer env_only.deinit(a);
    try t.expectEqual(@as(usize, 2), env_only.argv.len);
    try t.expectEqual(@as(usize, 2), env_only.envp.len);
}
test "boot policy rejects invalid reserved duplicate and oversized config bindings before allocation" {
    const long_value: [4097]u8 = @splat('x');
    const long_name: [129]u8 = @splat('A');
    const max_value: [4096]u8 = @splat('x');
    const cases = [_][]const live.EnvBinding{
        &.{.{ .name = "", .value = "v" }},
        &.{.{ .name = "1BAD", .value = "v" }},
        &.{.{ .name = "BAD=NAME", .value = "v" }},
        &.{.{ .name = "GOOD", .value = "bad\x00value" }},
        &.{.{ .name = "ONYX_HELIX_ARENA_FD", .value = "3" }},
        &.{.{ .name = "ONYX_WINDOWS_CANDIDATE", .value = "x" }},
        &.{.{ .name = "ONYX_REQUIRE_EXISTING_IDENTITY", .value = "0" }},
        &.{.{ .name = "LISTEN_FDS", .value = "4" }},
        &.{.{ .name = "NOTIFY_SOCKET", .value = "/private/socket" }},
        &.{.{ .name = "WATCHDOG_PID", .value = "3" }},
        &.{.{ .name = "WATCHDOG_USEC", .value = "100" }},
        &.{.{ .name = "WATCHDOG_DEVICE", .value = "/private/watchdog" }},
        &.{ .{ .name = "SAME", .value = "1" }, .{ .name = "SAME", .value = "2" } },
        &.{.{ .name = "LONG", .value = &long_value }},
        &.{.{ .name = &long_name, .value = "v" }},
    };
    var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    for (cases) |bindings| try t.expectError(error.InvalidBootPolicy, live.buildListenerExecPlanWithBootPolicy(failing.allocator(), "/private/onyx-server", 12, null, .{ .config_env = bindings }));
    try t.expect(!failing.has_induced_failure);
    var many: [65]live.EnvBinding = @splat(.{ .name = "A", .value = "v" });
    try t.expectError(error.InvalidBootPolicy, (live.BootPolicy{ .config_env = &many }).validate());
    const big = [_]live.EnvBinding{
        .{ .name = "A", .value = &max_value }, .{ .name = "B", .value = &max_value },
        .{ .name = "C", .value = &max_value }, .{ .name = "D", .value = &max_value },
        .{ .name = "E", .value = &max_value }, .{ .name = "F", .value = &max_value },
        .{ .name = "G", .value = &max_value }, .{ .name = "H", .value = &max_value },
    };
    try t.expectError(error.InvalidBootPolicy, (live.BootPolicy{ .config_env = &big }).validate());
    var base = try live.buildListenerExecPlan(t.allocator, "/private/onyx-server", 12, null);
    defer base.deinit(t.allocator);
    try t.expectError(error.InvalidBootPolicy, live.applyBootPolicy(failing.allocator(), &base, .{ .config_env = &.{.{ .name = live.env_listen_fd, .value = "9" }} }));
    try t.expectEqualStrings("ONYX_HELIX_LISTEN_FD=12", base.envp[0]);
}
test "boot policy requires distinct complete capability line only for explicit policy" {
    const old = live.upgrade_capability_token ++ "\n";
    try t.expect(live.hasUpgradeCapabilityForBootPolicy(old, .{}));
    try t.expect(!live.hasUpgradeCapabilityForBootPolicy(old, .{ .strict_existing_identity = true }));
    try t.expect(!live.hasUpgradeCapabilityForBootPolicy(old, .{ .config_env = &.{.{ .name = "SECRET", .value = "v" }} }));
    try t.expect(live.hasUpgradeCapabilityForBootPolicy(old ++ live.boot_policy_capability_token ++ "\r\n", .{ .strict_existing_identity = true }));
    try t.expect(!live.hasUpgradeCapabilityForBootPolicy(old ++ "prefix " ++ live.boot_policy_capability_token ++ "\n", .{ .strict_existing_identity = true }));
    try t.expect(!live.hasUpgradeCapabilityForBootPolicy(live.boot_policy_capability_token ++ "\n", .{ .strict_existing_identity = true }));
}
const WipeObserver = struct {
    backing: std.mem.Allocator,
    watched: ?[*]const u8 = null,
    freed: bool = false,
    zero: bool = false,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, len, ret);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, len, ret);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.watched) |ptr| if (ptr == memory.ptr) {
            self.freed = true;
            self.zero = true;
            for (memory) |byte| if (byte != 0) {
                self.zero = false;
            };
        };
        self.backing.rawFree(memory, alignment, ret);
    }
};
test "boot policy zeroes owned secret binding before allocator release" {
    var observer = WipeObserver{ .backing = t.allocator };
    const a = observer.allocator();
    var plan = try live.buildListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 12, null, .{ .config_env = &.{.{ .name = "SECRET", .value = "retained-secret" }} });
    observer.watched = plan.envp[1].ptr;
    plan.deinit(a);
    try t.expect(observer.freed and observer.zero);
    try t.expectEqual(@as(usize, 0), plan.envp.len);
}
fn allocationCuts(a: std.mem.Allocator) !void {
    const policy: live.BootPolicy = .{ .strict_existing_identity = true, .config_env = &.{ .{ .name = "CONFIG_ONE", .value = "private-one" }, .{ .name = "CONFIG_TWO", .value = "private-two" } } };
    var base = try live.buildListenerExecPlan(a, "/private/onyx-server", 12, "/private/config");
    defer base.deinit(a);
    var copied = try live.applyBootPolicy(a, &base, policy);
    defer copied.deinit(a);
    try t.expectEqual(@as(usize, 3), base.argv.len);
    try t.expectEqual(@as(usize, 1), base.envp.len);
    const env_only: live.BootPolicy = .{ .config_env = policy.config_env };
    var listener = try live.buildExecPlanWithListenerAndBootPolicy(a, "/private/onyx-server", 10, 11, 12, env_only);
    defer listener.deinit(a);
    var restart = try live.buildListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 12, "/private/config", policy);
    defer restart.deinit(a);
    var arena = try live.buildArenaListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 10, &.{ 12, 13 }, &.{14}, "/private/config", policy);
    defer arena.deinit(a);
    var ordinary = try live.buildExecPlanWithBootPolicy(a, "/private/onyx-server", 10, 11, env_only);
    defer ordinary.deinit(a);
    try t.expectEqualStrings("CONFIG_TWO=private-two", arena.envp[arena.envp.len - 1]);
}
test "boot policy allocation cuts preserve base vectors and release all staged secret ownership" {
    try t.checkAllAllocationFailures(t.allocator, allocationCuts, .{});
}

test "boot policy collector deduplicates stable owned bindings and refuses conflicting snapshots" {
    var collector = live.ConfigEnvCollector.init(t.allocator);
    defer collector.deinit();
    var value = "first".*;
    try collector.record("CONFIG_A", &value);
    value[0] = 'X';
    try t.expectEqualStrings("first", collector.view()[0].value);
    try collector.record("CONFIG_A", "first");
    try t.expectEqual(@as(usize, 1), collector.view().len);
    try t.expectError(error.ConflictingConfigEnvironment, collector.record("CONFIG_A", "different"));
    try t.expectError(error.InvalidBootPolicy, collector.record("ONYX_HELIX_STATE_FDS", "4"));
    try t.expectEqual(@as(usize, 1), collector.view().len);
    var owner = try live.OwnedBootPolicy.init(t.allocator, .{ .strict_existing_identity = true, .config_env = collector.view() });
    defer owner.deinit();
    collector.deinit();
    try t.expect(owner.borrow().strict_existing_identity);
    try t.expectEqualStrings("first", owner.borrow().config_env[0].value);
    try t.expect(live.sameConfigEnvironment(owner.borrow().config_env, &.{.{ .name = "CONFIG_A", .value = "first" }}));
    try t.expect(!live.sameConfigEnvironment(owner.borrow().config_env, &.{.{ .name = "CONFIG_A", .value = "changed" }}));
    try t.expect(!live.sameConfigEnvironment(owner.borrow().config_env, &.{.{ .name = "CONFIG_B", .value = "first" }}));
}
test "boot policy owned config collector wipes retained value before release" {
    var observer = WipeObserver{ .backing = t.allocator };
    var owner = try live.OwnedBootPolicy.init(observer.allocator(), .{ .strict_existing_identity = true, .config_env = &.{.{ .name = "CONFIG_A", .value = "secret-owned" }} });
    observer.watched = owner.borrow().config_env[0].value.ptr;
    owner.deinit();
    try t.expect(observer.freed and observer.zero);
}
fn collectorAllocationCuts(a: std.mem.Allocator) !void {
    var collector = live.ConfigEnvCollector.init(a);
    defer collector.deinit();
    try collector.record("CONFIG_A", "first");
    try collector.record("CONFIG_A", "first");
    try collector.record("CONFIG_B", "second");
    var owner = try live.OwnedBootPolicy.init(a, .{ .strict_existing_identity = true, .config_env = collector.view() });
    defer owner.deinit();
    try t.expect(live.sameConfigEnvironment(collector.view(), owner.borrow().config_env));
    try t.expect(live.sameConfigEnvironment(collector.view(), &.{ .{ .name = "CONFIG_B", .value = "second" }, .{ .name = "CONFIG_A", .value = "first" } }));
}
test "boot policy collector and owner allocation cuts leave no partial secret owner" {
    try t.checkAllAllocationFailures(t.allocator, collectorAllocationCuts, .{});
}

test "boot policy platform selection reserves explicit carry for Linux native exec" {
    try t.expect(live.supportsBootPolicyOn(.linux));
    try t.expect(!live.supportsBootPolicyOn(.windows));
    try t.expect(!live.supportsBootPolicyOn(.openbsd));
    // Policy validation/ownership itself remains portable. Unsupported native
    // routes must preserve their existing resolver and source-proof contracts;
    // they cannot install an implicit policy after an ordinary REHASH.
    var owner = try live.OwnedBootPolicy.init(t.allocator, .{ .config_env = &.{.{ .name = "CONFIG_A", .value = "value" }} });
    defer owner.deinit();
    try t.expect(owner.borrow().requiresCapability());
    try t.expect(!(live.BootPolicy{}).requiresCapability());
}

test "boot policy strict supervisor requires explicit nonoption config before any allocation" {
    const strict: live.BootPolicy = .{ .strict_existing_identity = true };
    var failing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    const a = failing.allocator();
    try t.expectError(error.InvalidBootPolicy, live.buildExecPlanWithBootPolicy(a, "/private/onyx-server", 10, 11, strict));
    try t.expectError(error.InvalidBootPolicy, live.buildExecPlanWithListenerAndBootPolicy(a, "/private/onyx-server", 10, 11, 12, strict));
    for ([_]?[]const u8{ null, "", "--strict-existing-identity", "--supervisor", "bad\x00path" }) |path| {
        try t.expectError(error.InvalidBootPolicy, live.buildListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 12, path, strict));
        try t.expectError(error.InvalidBootPolicy, live.buildArenaListenerExecPlanWithBootPolicy(a, "/private/onyx-server", 10, &.{12}, &.{}, path, strict));
    }
    var base = try live.buildExecPlan(t.allocator, "/private/onyx-server", 10, 11);
    defer base.deinit(t.allocator);
    try t.expectError(error.InvalidBootPolicy, live.applyBootPolicy(a, &base, strict));
    try t.expectEqual(@as(usize, 2), base.argv.len);
    try t.expectEqualStrings("--supervisor", base.argv[1]);
    try t.expectEqualStrings("ONYX_HELIX_ARENA_FD=10", base.envp[0]);
    try t.expect(!failing.has_induced_failure);
    var good = try live.buildListenerExecPlanWithBootPolicy(t.allocator, "/private/onyx-server", 12, "/private/config", strict);
    defer good.deinit(t.allocator);
    try t.expectEqualStrings("/private/config", good.argv[2]);
    try t.expectEqualStrings(live.strict_existing_identity_arg, good.argv[3]);
}
