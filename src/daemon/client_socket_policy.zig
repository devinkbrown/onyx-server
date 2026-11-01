// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One source for the Linux client keepalive window and its TCP abort budget.

pub const keepalive_idle_seconds: u32 = 30;
pub const keepalive_interval_seconds: u32 = 10;
pub const keepalive_probes: u32 = 3;

/// Linux TCP_USER_TIMEOUT overrides TCP_KEEPCNT once a keepalive probe is
/// outstanding. Include the idle period and every probe interval so the
/// inherited listener timeout cannot abort after the first missed probe.
/// This also bounds stalled unacknowledged data to one minute; IRC/S2S
/// application-level deadlines remain independent and may close sooner.
pub const user_timeout_ms: u32 =
    (keepalive_idle_seconds + keepalive_interval_seconds * keepalive_probes) * 1000;
