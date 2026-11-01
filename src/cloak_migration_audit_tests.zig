// Focused pure audit iteration; full integration gates remain required.
test {
    _ = @import("daemon/cloak_migration_audit.zig");
    _ = @import("cli/cloak_audit_cmd.zig");
}
