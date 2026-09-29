// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sealed-room roster disclosure.
//!
//! The server still has to route a channel, name one abuse target, and keep
//! the Helix delivery membership for that channel. It must not emit the member
//! list in the clear. Ordinary channels stay enumerable. A sealed channel
//! refuses NAMES, WHO, and WHOX instead of sending an empty roster.

const std = @import("std");

pub const prop_key = "membership-visibility";

pub const Visibility = enum {
    ordinary,
    sealed,
};

pub fn visibilityValue(raw: []const u8) ?Visibility {
    if (std.ascii.eqlIgnoreCase(raw, "ordinary")) return .ordinary;
    if (std.ascii.eqlIgnoreCase(raw, "sealed")) return .sealed;
    return null;
}

pub const RosterDisclosure = enum {
    list,
    refuse,
};

pub fn rosterDisclosure(visibility: Visibility) RosterDisclosure {
    return switch (visibility) {
        .ordinary => .list,
        .sealed => .refuse,
    };
}

/// Helix keeps the channel's delivery membership. A sealed room does not
/// publish that membership as a clear roster.
pub fn helixPublishesClearRoster(visibility: Visibility) bool {
    return rosterDisclosure(visibility) == .list;
}
