// Focused iteration only; full integration and release gates remain required.
test {
    _ = @import("proto/cloak.zig");
    _ = @import("proto/cloak_match.zig");
}
