//! Module root for the guest executable. `src/` has to be the module
//! directory so daemon imports of `proto/` stay inside the module.
//! The suite discovers the tests through `daemon/root.zig`, not this file.

const exec = @import("daemon/foreign_kernel_exec.zig");

pub fn main() !void {
    try exec.main();
}
