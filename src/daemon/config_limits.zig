// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Includes a maximum-size exact-fence policy and its active mesh roster.
/// File readers, typed parsing and retained source proofs share this bound.
pub const max_source_bytes: usize = 2 * 1024 * 1024;
