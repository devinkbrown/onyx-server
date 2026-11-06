// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bearer-credential scrubber for text that leaves the process: stderr and
//! the persistent daemon log (`dlog`), the trace flight recorder, the panic
//! crash artifact, and oper `DEBUG` dumps.
//!
//! Pure and allocation-free. It takes no locks, never logs, never recurses,
//! and uses a small fixed stack frame, so `flushFlightRecorderOnPanic` may
//! call it on the panic path.
//!
//! Recognized shapes:
//!   - session tokens: "sst_" + 32 hex (`services.session_token_prefix`,
//!     `services.session_token_len`), including a hex run cut off by the end
//!     of the input;
//!   - attachment resume credentials: "srm2l." / "srm2m." envelopes
//!     (`session_resume_credential.local_prefix` / `mesh_prefix`) through
//!     the end of their dotted run;
//!   - "Authorization:" and "Cookie:" header values (to end of line), and a
//!     bare "Bearer <tok>" (case-insensitive);
//!   - JWT-shaped "eyJ<b64url>.<b64url>.<b64url>";
//!   - IRC credential commands: AUTHENTICATE <payload> (kept when the
//!     payload is "+", "*" or a SASL mechanism name),
//!     "SESSIONTOKEN <acct> <tok>" and "SESSION TOKEN|MTOKEN|RESUME <tok>"
//!     (only the token field) anywhere; PASS, OPER, IDENTIFY, REGISTER,
//!     SETPASS, GHOST and LOGIN (everything after the verb) at a command
//!     position: line start, after a trailing-parameter ':', or after
//!     "@tags", ":prefix" or a verb prefix such as "NS" or "WEBPUSH";
//!   - secret-named fields: key=value, TOML-style "key = value" and JSON
//!     "key":"value" where the key is token/password/passwd/secret-like
//!     (case-insensitive, see `isSecretKey`).
//!
//! The input must be a whole line. A caller holding a prefix cut from a
//! longer line first applies `trimPartialField`, because a cut can turn a
//! secret into a kept word (an AUTHENTICATE payload that begins "PLAIN").
//!
//! `redactInto` copies verbatim only bytes that lie outside the union of all
//! detected spans; overlapping and nested detections are merged before any
//! byte is emitted. Every other output byte comes from the fixed marker, so
//! output truncation can never expose a partial credential.

const std = @import("std");

pub const redacted_marker = "<redacted>";

const session_token_prefix = "sst_";
const session_token_hex_len: usize = 32;
const resume_credential_prefix = "srm2";

const header_needles = [_][]const u8{ "authorization:", "cookie:" };
const bearer_needle = "bearer";
const jwt_needle = "eyJ";

/// SASL mechanism names and continuation markers that are not secrets.
const kept_authenticate_tokens = [_][]const u8{
    "+",
    "*",
    "PLAIN",
    "EXTERNAL",
    "ANONYMOUS",
    "OAUTHBEARER",
    "SCRAM-SHA-1",
    "SCRAM-SHA-1-PLUS",
    "SCRAM-SHA-256",
    "SCRAM-SHA-256-PLUS",
    "SCRAM-SHA-512",
    "SCRAM-SHA-512-PLUS",
};

/// Verbs whose every parameter may carry a password or bearer value.
const remainder_verbs = [_][]const u8{ "PASS", "OPER", "IDENTIFY", "REGISTER", "SETPASS", "GHOST", "LOGIN" };

/// "SESSION" subcommands whose next field is a bearer credential.
const session_token_subverbs = [_][]const u8{ "TOKEN", "MTOKEN", "RESUME" };

/// Words that may precede a credential verb: services aliases
/// ("NS IDENTIFY ...") and "WEBPUSH REGISTER <endpoint> <keys>", whose
/// endpoint is a capability URL and whose keys hold the push auth secret.
const verb_prefixes = [_][]const u8{
    "NS", "NICKSERV", "CS", "CHANSERV", "OS", "OPERSERV", "MS", "MEMOSERV", "HS", "HOSTSERV", "BS", "BOTSERV", "WEBPUSH",
};

/// One detection. `start..end` is the secret span (never empty); `resume_at`
/// is where the same matcher continues for its next detection and is always
/// strictly greater than the `from` that produced this span.
///
/// Matcher contract relied on by `redactInto`: successive detections of one
/// matcher (each found from the previous `resume_at`) have non-decreasing
/// `start`. Every span starts at or after its needle, and no matcher's next
/// needle can fall between its previous needle and that span's start (those
/// bytes are the needle itself, blanks, or a non-command field), so the
/// cached leftmost detection bounds every later one.
const Span = struct { start: usize, end: usize, resume_at: usize };

const Matcher = *const fn ([]const u8, usize) ?Span;

const matchers = [_]Matcher{
    findSessionToken,
    findResumeCredential,
    findHeader,
    findBearer,
    findJwt,
    findCommand,
    findKeyValue,
    findJsonField,
};

fn isWordByte(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

fn isBase64Url(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_';
}

fn isLineEnd(c: u8) bool {
    return c == '\r' or c == '\n';
}

fn isBlank(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn isFieldEnd(c: u8) bool {
    return isBlank(c) or isLineEnd(c);
}

fn eqlAnyIgnoreCase(word: []const u8, set: []const []const u8) bool {
    for (set) |item| {
        if (std.ascii.eqlIgnoreCase(word, item)) return true;
    }
    return false;
}

fn endsWithIgnoreCase(word: []const u8, suffix: []const u8) bool {
    return word.len >= suffix.len and std.ascii.eqlIgnoreCase(word[word.len - suffix.len ..], suffix);
}

fn indexOfIgnoreCasePos(haystack: []const u8, from: usize, needle: []const u8) ?usize {
    if (from > haystack.len or needle.len > haystack.len - from) return null;
    var i = from;
    while (i <= haystack.len - needle.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn scanUntilLineEnd(text: []const u8, from: usize) usize {
    var e = from;
    while (e < text.len and !isLineEnd(text[e])) e += 1;
    return e;
}

fn scanUntilFieldEnd(text: []const u8, from: usize) usize {
    var e = from;
    while (e < text.len and !isFieldEnd(text[e])) e += 1;
    return e;
}

fn skipBlanks(text: []const u8, from: usize) usize {
    var v = from;
    while (v < text.len and isBlank(text[v])) v += 1;
    return v;
}

/// Field names whose value is a credential. Matching is case-insensitive and
/// deliberately broad (refresh_token, client_secret, oper_password, ...):
/// over-redacting a diagnostic is acceptable, leaking a credential is not.
fn isSecretKey(word: []const u8) bool {
    if (word.len == 0) return false;
    if (endsWithIgnoreCase(word, "token") or endsWithIgnoreCase(word, "secret") or
        endsWithIgnoreCase(word, "password") or endsWithIgnoreCase(word, "passwd") or
        endsWithIgnoreCase(word, "_pass") or endsWithIgnoreCase(word, "_key")) return true;
    return eqlAnyIgnoreCase(word, &.{ "pass", "meshpass", "authorization", "apikey", "cookie" });
}

/// "sst_" + 32 hex (either case, fail-closed), extended over any directly
/// attached base64url bytes. A hex run that reaches the end of the input
/// before 32 characters is a truncated token and is still redacted.
fn findSessionToken(text: []const u8, from: usize) ?Span {
    var search = from;
    while (std.mem.indexOfPos(u8, text, search, session_token_prefix)) |p| {
        const hex_start = p + session_token_prefix.len;
        var e = hex_start;
        while (e < text.len and e - hex_start < session_token_hex_len and std.ascii.isHex(text[e])) e += 1;
        if (e - hex_start == session_token_hex_len) {
            while (e < text.len and isBase64Url(text[e])) e += 1;
            return .{ .start = p, .end = e, .resume_at = p + 1 };
        }
        if (e > hex_start and e == text.len) return .{ .start = p, .end = e, .resume_at = p + 1 };
        search = p + 1;
    }
    return null;
}

/// "srm2l." / "srm2m." resume envelope (any case, fail-closed) through the
/// end of its dotted base64url run. A bare prefix cut off by the end of the
/// input is still redacted.
fn findResumeCredential(text: []const u8, from: usize) ?Span {
    var search = from;
    while (indexOfIgnoreCasePos(text, search, resume_credential_prefix)) |p| {
        search = p + 1;
        const kind = p + resume_credential_prefix.len;
        if (kind + 1 >= text.len or text[kind + 1] != '.') continue;
        if (std.ascii.toLower(text[kind]) != 'l' and std.ascii.toLower(text[kind]) != 'm') continue;
        var e = kind + 2;
        while (e < text.len and (isBase64Url(text[e]) or text[e] == '.')) e += 1;
        return .{ .start = p, .end = e, .resume_at = p + 1 };
    }
    return null;
}

/// "Authorization:" / "Cookie:" header value through end of line, whatever
/// the scheme. The name must not be glued to a preceding word byte, which
/// still admits "Proxy-Authorization:" and "Set-Cookie:".
fn findHeader(text: []const u8, from: usize) ?Span {
    var best: ?Span = null;
    for (header_needles) |needle| {
        var search = from;
        while (indexOfIgnoreCasePos(text, search, needle)) |p| {
            search = p + 1;
            if (best) |b| if (p >= b.start) break;
            if (p > 0 and isWordByte(text[p - 1])) continue;
            const v = skipBlanks(text, p + needle.len);
            const e = scanUntilLineEnd(text, v);
            if (e == v) continue;
            // Any later header inside this value also ends at this line end.
            best = .{ .start = v, .end = e, .resume_at = e };
            break;
        }
    }
    return best;
}

/// Bare "Bearer <tok>" (any case). The word with nothing after it is kept.
fn findBearer(text: []const u8, from: usize) ?Span {
    var search = from;
    while (indexOfIgnoreCasePos(text, search, bearer_needle)) |p| {
        search = p + 1;
        const after = p + bearer_needle.len;
        if (p > 0 and isWordByte(text[p - 1])) continue;
        if (after < text.len and isWordByte(text[after])) continue;
        const v = skipBlanks(text, after);
        if (v == after) continue;
        const e = scanUntilFieldEnd(text, v);
        if (e == v) continue;
        return .{ .start = v, .end = e, .resume_at = p + 1 };
    }
    return null;
}

fn scanBase64Url(text: []const u8, from: usize) usize {
    var e = from;
    while (e < text.len and isBase64Url(text[e])) e += 1;
    return e;
}

/// JWT "eyJ<hdr>.<payload>.<sig>" (an empty signature is accepted). On a
/// miss the search skips the whole first-segment run: every later "eyJ" in
/// that run shares its end and therefore fails identically, which keeps the
/// scan linear on hostile "eyJeyJeyJ..." input.
fn findJwt(text: []const u8, from: usize) ?Span {
    var search = from;
    while (std.mem.indexOfPos(u8, text, search, jwt_needle)) |p| {
        const seg1_end = scanBase64Url(text, p);
        search = @max(p + 1, seg1_end);
        if (seg1_end >= text.len or text[seg1_end] != '.') continue;
        const seg2_end = scanBase64Url(text, seg1_end + 1);
        if (seg2_end == seg1_end + 1 or seg2_end >= text.len or text[seg2_end] != '.') continue;
        const seg3_end = scanBase64Url(text, seg2_end + 1);
        return .{ .start = p, .end = seg3_end, .resume_at = p + 1 };
    }
    return null;
}

/// Keys whose value is conventionally a whole raw protocol line in a log
/// field ("line=PASS x", "raw=OPER a b"); a verb right after `<key>=` is at
/// a command position whatever its case.
const raw_line_keys = [_][]const u8{ "line", "raw", "cmd", "command", "input", "msg", "message", "text", "payload", "request", "data", "client_line" };

/// True when the word at `q` is written entirely in upper case, the way a
/// client sends a verb or services alias.
fn isUpperWord(text: []const u8, q: usize) bool {
    var e = q;
    while (e < text.len and isWordByte(text[e])) : (e += 1) {
        if (std.ascii.isLower(text[e])) return false;
    }
    return e > q;
}

/// True when the word at `q` follows `<key>=` and either the key names a raw
/// line field or the word is an upper-case verb. Lower-case trace values
/// such as "category=oper" stay prose.
fn isAssignedCommand(text: []const u8, q: usize) bool {
    std.debug.assert(q > 0 and text[q - 1] == '=');
    var ks = q - 1;
    while (ks > 0 and isWordByte(text[ks - 1])) ks -= 1;
    return eqlAnyIgnoreCase(text[ks .. q - 1], &raw_line_keys) or isUpperWord(text, q);
}

/// True when the word at `p` sits where an IRC verb would: input start, after
/// a line break, after the trailing-parameter ':' or a "label:" (with blanks
/// between), after "<raw-line-key>=" or "<key>=" with an upper-case verb, or
/// after at most three leading "@tags", ":prefix" or services-alias tokens
/// that are themselves at such a position. Prose ("the PASS command") and
/// lower-case trace fields ("category=oper") do not qualify. Treating a
/// label colon as a command position over-redacts prose such as
/// "refused: OPER for alice"; leaking "line: PASS <pw>" would be worse.
fn isCommandPosition(text: []const u8, p: usize) bool {
    var q = p;
    var hops: u8 = 0;
    while (true) {
        if (q == 0) return true;
        const prev = text[q - 1];
        if (isLineEnd(prev) or prev == ':') return true;
        if (prev == '=') return isAssignedCommand(text, q);
        if (!isBlank(prev) or hops == 3) return false;
        var tok_end = q - 1;
        while (tok_end > 0 and isBlank(text[tok_end - 1])) tok_end -= 1;
        if (tok_end > 0 and text[tok_end - 1] == ':') return true;
        var tok_start = tok_end;
        while (tok_start > 0 and !isFieldEnd(text[tok_start - 1])) tok_start -= 1;
        if (tok_start == tok_end) return false;
        const tok = text[tok_start..tok_end];
        if (tok[0] != '@' and tok[0] != ':') {
            // "rx=NS IDENTIFY ...": a services alias assigned to a key.
            if (std.mem.lastIndexOfScalar(u8, tok, '=')) |eq| {
                const word_start = tok_start + eq + 1;
                return word_start < tok_end and
                    eqlAnyIgnoreCase(text[word_start..tok_end], &verb_prefixes) and
                    isAssignedCommand(text, word_start);
            }
            if (!eqlAnyIgnoreCase(tok, &verb_prefixes)) return false;
        }
        q = tok_start;
        hops += 1;
    }
}

/// IRC credential commands; see the module comment for the per-verb rules.
fn findCommand(text: []const u8, from: usize) ?Span {
    var p = from;
    while (p < text.len) {
        if (!std.ascii.isAlphabetic(text[p]) or (p > 0 and isWordByte(text[p - 1]))) {
            p += 1;
            continue;
        }
        var word_end = p;
        while (word_end < text.len and isWordByte(text[word_end])) word_end += 1;
        const word = text[p..word_end];
        const next = word_end;
        if (word_end >= text.len or !isBlank(text[word_end])) {
            p = next;
            continue;
        }
        // IRC allows any run of blanks between parameters.
        const param = skipBlanks(text, word_end);
        // AUTHENTICATE, SESSIONTOKEN and the SESSION token subcommands are
        // not prose, so their payloads are redacted wherever they appear
        // ("SASL via AUTHENTICATE <b64>"); the common-word verbs need a
        // command position.
        if (std.ascii.eqlIgnoreCase(word, "AUTHENTICATE")) {
            const e = scanUntilFieldEnd(text, param);
            if (e > param and !eqlAnyIgnoreCase(text[param..e], &kept_authenticate_tokens))
                return .{ .start = param, .end = e, .resume_at = p + 1 };
        } else if (std.ascii.eqlIgnoreCase(word, "SESSIONTOKEN")) {
            const acct_end = scanUntilFieldEnd(text, param);
            if (acct_end > param and acct_end < text.len and isBlank(text[acct_end])) {
                const tok = skipBlanks(text, acct_end);
                const e = scanUntilFieldEnd(text, tok);
                if (e > tok) return .{ .start = tok, .end = e, .resume_at = p + 1 };
            }
        } else if (std.ascii.eqlIgnoreCase(word, "SESSION")) {
            const sub_end = scanUntilFieldEnd(text, param);
            if (sub_end < text.len and isBlank(text[sub_end]) and
                eqlAnyIgnoreCase(text[param..sub_end], &session_token_subverbs))
            {
                const tok = skipBlanks(text, sub_end);
                const e = scanUntilFieldEnd(text, tok);
                if (e > tok) return .{ .start = tok, .end = e, .resume_at = p + 1 };
            }
        } else if (eqlAnyIgnoreCase(word, &remainder_verbs) and isCommandPosition(text, p)) {
            const e = scanUntilLineEnd(text, param);
            // Every command nested in this remainder ends by the same line
            // end, so resuming there loses nothing and keeps scans linear.
            if (e > param) return .{ .start = param, .end = e, .resume_at = e };
        }
        p = next;
    }
    return null;
}

/// Value of a quoted or bare field starting at `v`: a TOML triple-quoted
/// value ('"""' or "'''") runs, across line breaks, to its closing triple
/// (or end of input when unterminated); a quoted value runs to its closing
/// quote (or end of line when unterminated); a bare value stops at
/// whitespace, a line break or the query separator '&'. Bytes glued to a
/// closing quote (`""tail`) are not a separate field, so they extend the
/// value up to the next field end or JSON/query separator.
fn fieldValueEnd(text: []const u8, v: usize) usize {
    if (v < text.len and (text[v] == '"' or text[v] == '\'')) {
        const quote = text[v];
        if (v + 3 <= text.len and text[v + 1] == quote and text[v + 2] == quote) {
            // Only basic (double-quote) strings have escapes; a literal
            // triple-single-quote string ends at the first closing triple.
            const escapes = quote == '"';
            var e = v + 3;
            while (e < text.len) : (e += 1) {
                if (escapes and text[e] == '\\' and e + 1 < text.len) {
                    e += 1;
                    continue;
                }
                if (text[e] == quote and e + 3 <= text.len and text[e + 1] == quote and text[e + 2] == quote) {
                    e += 3;
                    // TOML lets one or two quote bytes of content sit
                    // directly before the closing triple.
                    var extra: u8 = 0;
                    while (extra < 2 and e < text.len and text[e] == quote) : (extra += 1) e += 1;
                    return quotedTail(text, e);
                }
            }
            return e;
        }
        var e = v + 1;
        while (e < text.len and text[e] != quote and !isLineEnd(text[e])) : (e += 1) {
            if (text[e] == '\\' and e + 1 < text.len and !isLineEnd(text[e + 1])) e += 1;
        }
        return if (e < text.len and text[e] == quote) quotedTail(text, e + 1) else e;
    }
    var e = v;
    while (e < text.len and !isFieldEnd(text[e]) and text[e] != '&') e += 1;
    return e;
}

/// Bytes glued directly to a closing quote belong to the same field.
fn quotedTail(text: []const u8, after_quote: usize) usize {
    var e = after_quote;
    while (e < text.len and !isFieldEnd(text[e]) and std.mem.indexOfScalar(u8, "&,;}]){", text[e]) == null) e += 1;
    return e;
}

/// "<secret-key>=<value>", e.g. a query parameter or a trace field, and the
/// TOML form "<secret-key> = <value>". Blanks after '=' are skipped only when
/// the key side is spaced too, so "token= x" stays an empty value; "==" is a
/// comparison, not an assignment.
fn findKeyValue(text: []const u8, from: usize) ?Span {
    var search = from;
    while (std.mem.indexOfScalarPos(u8, text, search, '=')) |eq| {
        search = eq + 1;
        var ke = eq;
        while (ke > 0 and isBlank(text[ke - 1])) ke -= 1;
        var ks = ke;
        while (ks > 0 and isWordByte(text[ks - 1])) ks -= 1;
        if (!isSecretKey(text[ks..ke])) continue;
        const v = if (ke < eq) skipBlanks(text, eq + 1) else eq + 1;
        if (v < text.len and text[v] == '=') continue;
        const e = fieldValueEnd(text, v);
        if (e == v) continue;
        return .{ .start = v, .end = e, .resume_at = eq + 1 };
    }
    return null;
}

/// JSON-style "\"<secret-key>\" : <value>".
fn findJsonField(text: []const u8, from: usize) ?Span {
    var search = from;
    while (std.mem.indexOfScalarPos(u8, text, search, '"')) |q| {
        search = q + 1;
        var ke = q + 1;
        while (ke < text.len and isWordByte(text[ke])) ke += 1;
        if (ke >= text.len or text[ke] != '"' or !isSecretKey(text[q + 1 .. ke])) continue;
        var c = skipBlanks(text, ke + 1);
        if (c >= text.len or text[c] != ':') continue;
        c = skipBlanks(text, c + 1);
        const e = fieldValueEnd(text, c);
        if (e == c) continue;
        return .{ .start = c, .end = e, .resume_at = q + 1 };
    }
    return null;
}

/// True if `text` contains any recognized credential shape. Does not
/// allocate; safe on the panic path.
pub fn containsBearer(text: []const u8) bool {
    for (matchers) |m| {
        if (m(text, 0) != null) return true;
    }
    return false;
}

/// Prepare a prefix cut from a longer line for `redactInto`: drop the
/// trailing partial field so no cut credential is judged without its tail.
/// Returns an empty slice when the cut holds no field separator at all.
pub fn trimPartialField(cut: []const u8) []const u8 {
    var i = cut.len;
    while (i > 0 and !isFieldEnd(cut[i - 1])) i -= 1;
    return cut[0..i];
}

fn appendBounded(out: []u8, w: usize, bytes: []const u8) usize {
    const n = @min(bytes.len, out.len - w);
    @memcpy(out[w .. w + n], bytes[0..n]);
    return w + n;
}

/// Drop or advance cached detections that end at or before `pos`.
fn refresh(input: []const u8, cache: *[matchers.len]?Span, pos: usize) void {
    for (matchers, cache) |m, *slot| {
        while (slot.*) |s| {
            if (s.end > pos) break;
            slot.* = m(input, s.resume_at);
        }
    }
}

/// Copy `input` into `out`, replacing every detected credential span with
/// `redacted_marker`. Overlapping or nested detections are merged into one
/// marker first, so no tail of a longer credential survives a shorter match.
/// Never allocates. On overflow the output is cut, but only inside a
/// non-secret gap or inside the marker, because raw secret bytes are never
/// copied. A zero-length `out` yields an empty slice.
pub fn redactInto(input: []const u8, out: []u8) []const u8 {
    var cache: [matchers.len]?Span = undefined;
    for (matchers, &cache) |m, *slot| slot.* = m(input, 0);
    var w: usize = 0;
    var pos: usize = 0;
    while (pos < input.len and w < out.len) {
        refresh(input, &cache, pos);
        var start: ?usize = null;
        var end: usize = 0;
        for (cache) |slot| {
            const s = slot orelse continue;
            const eff = @max(s.start, pos);
            if (start == null or eff < start.?) {
                start = eff;
                end = s.end;
            }
        }
        const s = start orelse {
            w = appendBounded(out, w, input[pos..]);
            break;
        };
        // Merge every detection that begins inside the span chosen so far.
        var grown = true;
        while (grown) {
            grown = false;
            for (matchers, &cache) |m, *slot| {
                while (slot.*) |span| {
                    if (@max(span.start, pos) >= end) break;
                    if (span.end > end) {
                        end = span.end;
                        grown = true;
                    }
                    slot.* = m(input, span.resume_at);
                }
            }
        }
        w = appendBounded(out, w, input[pos..s]);
        w = appendBounded(out, w, redacted_marker);
        pos = end;
    }
    return out[0..w];
}

const testing = std.testing;

fn expectRedacted(input: []const u8, secrets: []const []const u8, expected: ?[]const u8) !void {
    var out: [512]u8 = undefined;
    const safe = redactInto(input, &out);
    for (secrets) |secret| try testing.expect(std.mem.indexOf(u8, safe, secret) == null);
    try testing.expect(containsBearer(input));
    if (expected) |e| try testing.expectEqualStrings(e, safe);
}

fn expectUntouched(input: []const u8) !void {
    var out: [512]u8 = undefined;
    try testing.expectEqualStrings(input, redactInto(input, &out));
    try testing.expect(!containsBearer(input));
}

test "credential_redaction: session token canary matches the services token format" {
    const services = @import("services.zig");
    try testing.expectEqualStrings(services.session_token_prefix, session_token_prefix);
    try testing.expectEqual(services.session_token_len, session_token_prefix.len + session_token_hex_len);
}

test "credential_redaction: session token sst_<32hex> canary is replaced and never appears" {
    const canary = "sst_0123456789abcdef0123456789abcdef";
    try expectRedacted("issued token " ++ canary ++ " to client", &.{canary}, "issued token <redacted> to client");
    try expectRedacted("glued" ++ canary ++ "TAIL_x.end", &.{ canary, "TAIL" }, "glued<redacted>.end");
    // Cut off by the end of the input: the partial hex is still a secret.
    try expectRedacted("trailer sst_0123456789abcdef01234567", &.{"0123456789abcdef01234567"}, "trailer <redacted>");
    // Not a token: a short hex run followed by a non-hex byte.
    try expectUntouched("sst_12 is a label");
}

test "credential_redaction: Authorization Bearer, Cookie and lowercase bearer are redacted; bare Bearer is kept" {
    const canary = "sst_fedcba9876543210fedcba9876543210";
    try expectRedacted("GET /history HTTP/1.1\r\nAuthorization: Bearer " ++ canary ++ "\r\nHost: x\r\n", &.{canary}, "GET /history HTTP/1.1\r\nAuthorization: <redacted>\r\nHost: x\r\n");
    try expectRedacted("AuThOrIzAtIoN: BeArEr alice", &.{"alice"}, "AuThOrIzAtIoN: <redacted>");
    try expectRedacted("Proxy-Authorization: Basic YWxhZGRpbg==", &.{"YWxhZGRpbg=="}, null);
    try expectRedacted("Set-Cookie: sid=abc; HttpOnly", &.{"abc"}, "Set-Cookie: <redacted>");
    try expectRedacted("auth attempt bearer " ++ canary ++ "XYZ rejected", &.{ canary, "XYZ" }, "auth attempt bearer <redacted> rejected");
    try expectRedacted("bearer\tTOKVALUE", &.{"TOKVALUE"}, "bearer\t<redacted>");
    try expectUntouched("status line ends with the word Bearer");
    try expectUntouched("AUTHENTICATE OAUTHBEARER");
    try expectUntouched("Authorization:");
}

test "credential_redaction: resume credential envelopes and SESSION token subcommands are redacted" {
    const resume_credential = @import("../proto/session_resume_credential.zig");
    try testing.expect(std.mem.startsWith(u8, resume_credential.local_prefix, resume_credential_prefix));
    try testing.expect(std.mem.startsWith(u8, resume_credential.mesh_prefix, resume_credential_prefix));

    const group_hex = "0123456789abcdef0123456789abcdef";
    const local = "srm2l." ++ group_hex ++ ".00000000000000a1";
    try expectRedacted(":srv NOTICE alice :SESSION TOKEN " ++ local, &.{ group_hex, "a1" }, ":srv NOTICE alice :SESSION TOKEN <redacted>");
    try expectRedacted("SESSION MTOKEN srm2m.deadbeefdeadbeef.0000000000000002 expires=1999999999", &.{"deadbeef"}, "SESSION MTOKEN <redacted> expires=1999999999");
    try expectRedacted("adopt saw SRM2L." ++ group_hex ++ ".x on reattach", &.{group_hex}, "adopt saw <redacted> on reattach");
    // Cut off right after the envelope prefix: still redacted.
    try expectRedacted("tail srm2m.", &.{}, "tail <redacted>");
    // Legacy hex tokens carry no shape, only their SESSION context.
    try expectRedacted("SESSION RESUME " ++ group_hex ++ " ALL", &.{group_hex}, "SESSION RESUME <redacted> ALL");
    try expectRedacted("session mtoken " ++ group_hex, &.{group_hex}, "session mtoken <redacted>");
    try expectRedacted("SESSION RESUME :retry-token", &.{"retry-token"}, "SESSION RESUME <redacted>");

    try expectUntouched("SESSION RESUME: attached to live mesh session");
    try expectUntouched("SESSION LIST * #1 signon=5 attached sid=00ab scope=local-attachment");
    try expectUntouched("SESSION DROP sid=00ab ok");
    try expectUntouched("srm2 alone, srm2x.y and srm2l without a dot");
}

test "credential_redaction: JWT-shaped eyJ..x.y triple is redacted" {
    const canary = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    try expectRedacted("wire payload " ++ canary ++ " received", &.{ canary, "dBjftJeZ4CVP" }, "wire payload <redacted> received");
    // Nested/overlapping second JWT shape inside the first is merged.
    try expectRedacted("x eyJa.eyJb.c.d y", &.{ "eyJ", ".d" }, "x <redacted> y");
    try expectUntouched("eyJhbGciOiJIUzI1NiJ9 alone is only a header");
}

test "credential_redaction: AUTHENTICATE <base64> is redacted, + / * and mechanism names are kept" {
    try expectRedacted("AUTHENTICATE QWxhZGRpbjpvcGVuc2VzYW1l", &.{"QWxhZGRpbjpvcGVuc2VzYW1l"}, "AUTHENTICATE <redacted>");
    try expectRedacted("@label=7 AUTHENTICATE c2VjcmV0", &.{"c2VjcmV0"}, "@label=7 AUTHENTICATE <redacted>");
    try expectRedacted("sasl step via AUTHENTICATE YWxpY2UAYWxpY2UAcHc= failed", &.{"YWxpY2UAYWxpY2UAcHc="}, "sasl step via AUTHENTICATE <redacted> failed");
    for ([_][]const u8{ "AUTHENTICATE +", "AUTHENTICATE *", "AUTHENTICATE PLAIN", "authenticate scram-sha-256", "AUTHENTICATE EXTERNAL" }) |line| {
        try expectUntouched(line);
    }
}

test "credential_redaction: PASS and OPER <name> <pass> are redacted; SESSIONTOKEN keeps the account" {
    try expectRedacted("PASS hunter2secret", &.{"hunter2secret"}, "PASS <redacted>");
    try expectRedacted("OPER admin s3cr3t-pw", &.{ "admin", "s3cr3t-pw" }, "OPER <redacted>");
    try expectRedacted("first line\r\nPASS :real secret\r\nNICK x", &.{"real secret"}, "first line\r\nPASS <redacted>\r\nNICK x");
    try expectRedacted(":server NOTICE nick :OPER admin s3cr3t-pw", &.{"s3cr3t-pw"}, ":server NOTICE nick :OPER <redacted>");
    try expectRedacted("@time=x :nick!u@h PASS relayed", &.{"relayed"}, "@time=x :nick!u@h PASS <redacted>");
    try expectRedacted("NS IDENTIFY alice hunter2", &.{"hunter2"}, "NS IDENTIFY <redacted>");
    try expectRedacted("PRIVMSG NickServ :REGISTER pw1 a@b.c", &.{"pw1"}, "PRIVMSG NickServ :REGISTER <redacted>");
    try expectRedacted("WEBPUSH REGISTER https://push.example/cap/Zq9 p256dh=AAA;auth=Bq7", &.{ "Zq9", "Bq7" }, "WEBPUSH REGISTER <redacted>");

    const canary = "sst_00112233445566778899aabbccddeeff";
    try expectRedacted(":srv NOTICE alice :SESSIONTOKEN alice " ++ canary ++ " expires=1999999999", &.{canary}, ":srv NOTICE alice :SESSIONTOKEN alice <redacted> expires=1999999999");
    try expectRedacted("SESSIONTOKEN bob opaque-value", &.{"opaque-value"}, "SESSIONTOKEN bob <redacted>");

    // Prose and trace fields are not command positions.
    try expectUntouched("PASSWORD: this is a field label, not the PASS command");
    try expectUntouched("category=oper msg=link established");
    try expectUntouched("refused OPER for alice");
}

test "credential_redaction: credential fields after a run of blanks are still redacted" {
    const hex = "0123456789abcdef0123456789abcdef";
    const b64 = "QWxhZGRpbjpvcGVuc2VzYW1l";
    try expectRedacted("AUTHENTICATE  " ++ b64, &.{b64}, "AUTHENTICATE  <redacted>");
    try expectRedacted("AUTHENTICATE\t \t" ++ b64, &.{b64}, "AUTHENTICATE\t \t<redacted>");
    try expectRedacted("SESSION RESUME  " ++ hex, &.{hex}, "SESSION RESUME  <redacted>");
    try expectRedacted("SESSION  TOKEN " ++ hex, &.{hex}, "SESSION  TOKEN <redacted>");
    try expectRedacted("SESSION\tMTOKEN\t\t" ++ hex ++ " ALL", &.{hex}, "SESSION\tMTOKEN\t\t<redacted> ALL");
    try expectRedacted("SESSIONTOKEN alice  tok-secret", &.{"tok-secret"}, "SESSIONTOKEN alice  <redacted>");
    try expectRedacted("SESSIONTOKEN   alice\ttok-secret", &.{"tok-secret"}, "SESSIONTOKEN   alice\t<redacted>");
    try expectRedacted("PASS\thunter2", &.{"hunter2"}, "PASS\t<redacted>");
    try expectRedacted("PASS   hunter2 more", &.{ "hunter2", "more" }, "PASS   <redacted>");
    try expectRedacted("NS\tIDENTIFY  alice hunter2", &.{"hunter2"}, "NS\tIDENTIFY  <redacted>");
    try expectRedacted("@t=1  :n!u@h  OPER  admin pw", &.{"pw"}, "@t=1  :n!u@h  OPER  <redacted>");

    // Kept tokens and absent payloads stay untouched behind blank runs too.
    try expectUntouched("AUTHENTICATE  PLAIN");
    try expectUntouched("AUTHENTICATE\t+");
    try expectUntouched("SESSION RESUME   ");
    try expectUntouched("SESSIONTOKEN alice  ");
    try expectUntouched("refused  OPER for alice");
}

test "credential_redaction: token=/access_token=/password=/secret= values are redacted case-insensitively" {
    try expectRedacted("GET /x?token=abc123&next=1", &.{"abc123"}, "GET /x?token=<redacted>&next=1");
    try expectRedacted("GET /x?ACCESS_TOKEN=Zzz999&next=1", &.{"Zzz999"}, "GET /x?ACCESS_TOKEN=<redacted>&next=1");
    try expectRedacted("auth Password=correct-horse-battery", &.{"correct-horse-battery"}, "auth Password=<redacted>");
    try expectRedacted("cfg Secret=topsecretvalue end", &.{"topsecretvalue"}, "cfg Secret=<redacted> end");
    try expectRedacted("cfg client_secret=\"two words\" ok", &.{ "two", "words" }, "cfg client_secret=<redacted> ok");
    try expectRedacted("refresh_token=r1 meshpass=m2", &.{ "r1", "m2" }, "refresh_token=<redacted> meshpass=<redacted>");
    try expectRedacted("{\"access_token\": \"a\\\"b\", \"user\":\"bob\"}", &.{"a\\\"b"}, "{\"access_token\": <redacted>, \"user\":\"bob\"}");
    try expectRedacted("[mesh]\nmeshpass = \"s3cr3t mesh\"\noper_password\t=\thunter2\n", &.{ "s3cr3t", "hunter2" }, "[mesh]\nmeshpass = <redacted>\noper_password\t=\t<redacted>\n");
    try expectUntouched("bypass=1 compass=north token= empty");
    try expectUntouched("check token == expected and secret==other");
}

test "credential_redaction: TOML triple-quoted and glued secret values are redacted whole" {
    try expectRedacted("meshpass = \"\"\"s3cr3t\"\"\"", &.{"s3cr3t"}, "meshpass = <redacted>");
    try expectRedacted("oper_password = '''hunter2'''", &.{"hunter2"}, "oper_password = <redacted>");
    // Multi-line basic string spans its line breaks; an escaped quote run
    // does not close it early.
    try expectRedacted("[mesh]\nmeshpass = \"\"\"\nline1 \\\"\"\" still\nline2\"\"\"\nname = \"x\"", &.{ "line1", "still", "line2" }, "[mesh]\nmeshpass = <redacted>\nname = \"x\"");
    // Up to two quote bytes of content before the closing triple.
    try expectRedacted("secret = '''ab'''''\nnext = 1", &.{"ab"}, "secret = <redacted>\nnext = 1");
    // Literal strings have no escapes: a backslash does not hide the close.
    try expectRedacted("client_secret = '''c:\\'''\nok = 1", &.{"c:"}, "client_secret = <redacted>\nok = 1");
    // Unterminated triple-quoted value: redact to end of input.
    try expectRedacted("meshpass = \"\"\"never closed\nmore secret", &.{ "never", "closed", "more" }, "meshpass = <redacted>");
    // Bytes glued to an (empty) closing quote stay inside the value.
    try expectRedacted("meshpass = \"\"s3cr3t tail", &.{"s3cr3t"}, "meshpass = <redacted> tail");
    try expectRedacted("{\"token\":\"\"abc,\"user\":\"bob\"}", &.{"abc"}, "{\"token\":<redacted>,\"user\":\"bob\"}");
}

test "credential_redaction: label-colon and key= prefixes put credential verbs at a command position" {
    try expectRedacted("rejected client line: PASS hunter2", &.{"hunter2"}, "rejected client line: PASS <redacted>");
    try expectRedacted("rejected client line:\tPASS hunter2", &.{"hunter2"}, "rejected client line:\tPASS <redacted>");
    try expectRedacted("line=OPER admin pw", &.{ "admin", "pw" }, "line=OPER <redacted>");
    try expectRedacted("conn=7 line=PASS hunter2", &.{"hunter2"}, "conn=7 line=PASS <redacted>");
    try expectRedacted("conn=7 raw=pass hunter2", &.{"hunter2"}, "conn=7 raw=pass <redacted>");
    try expectRedacted("dropped cmd: NS IDENTIFY alice hunter2", &.{"hunter2"}, "dropped cmd: NS IDENTIFY <redacted>");
    try expectRedacted("rx=IDENTIFY alice hunter2", &.{"hunter2"}, "rx=IDENTIFY <redacted>");
    try expectRedacted("rx=NS IDENTIFY alice hunter2", &.{"hunter2"}, "rx=NS IDENTIFY <redacted>");
    // Lower-case trace values after a non-line key stay prose.
    try expectUntouched("category=oper msg=link established");
    try expectUntouched("kind=pass result=ok");
}

test "credential_redaction: non-secret lines pass through byte-identical and containsBearer is false" {
    for ([_][]const u8{
        "",
        "hello world, nothing secret here",
        "reactor 0 accepted connection from 198.51.100.7",
        "mesh S2S established (secured) peer=ircx.us",
        "PASSWORD policy updated for realm default",
        "s2s secured peer accepted (activation staged)",
        ":srv 433 * nick :Nickname is already in use",
    }) |line| try expectUntouched(line);
}

test "credential_redaction: output overflow truncates without a partial secret prefix; zero-length out is empty" {
    const canary = "sst_ffffffffffffffffffffffffffffffff";
    const line = "secret=" ++ canary ++ " trailing text";
    var small: [9]u8 = undefined;
    try testing.expectEqualStrings("secret=<r", redactInto(line, &small));

    var zero: [0]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), redactInto(canary, &zero).len);

    // Every possible output capacity yields a prefix of the full redacted
    // text and never any byte of the secret value.
    var full_buf: [128]u8 = undefined;
    const full = redactInto("PASS " ++ canary ++ "\r\nok", &full_buf);
    var cap: usize = 0;
    while (cap <= full.len + 2) : (cap += 1) {
        var buf: [128]u8 = undefined;
        const got = redactInto("PASS " ++ canary ++ "\r\nok", buf[0..cap]);
        try testing.expect(got.len <= cap);
        try testing.expect(std.mem.startsWith(u8, full, got));
        try testing.expect(std.mem.indexOfScalar(u8, got, 'f') == null);
    }
}

test "credential_redaction: a cut line is trimmed to whole fields before redaction" {
    // Cut inside an AUTHENTICATE payload that begins like a mechanism name:
    // judged alone, "PLAIN" would be kept, so the partial field is dropped.
    const line = "sasl via AUTHENTICATE PLAINbG9uZ3NlY3JldA==";
    const cut = line[0 .. std.mem.indexOf(u8, line, "PLAIN").? + 5];
    try testing.expectEqualStrings("sasl via AUTHENTICATE ", trimPartialField(cut));
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("sasl via AUTHENTICATE ", redactInto(trimPartialField(cut), &out));
    // Separators of every kind end a field; a cut with none yields nothing.
    try testing.expectEqualStrings("a\tb\r\n", trimPartialField("a\tb\r\ncd"));
    try testing.expectEqualStrings("whole ", trimPartialField("whole "));
    try testing.expectEqual(@as(usize, 0), trimPartialField("sst_0123").len);
    try testing.expectEqual(@as(usize, 0), trimPartialField("").len);
}

/// Independent reference for `redactInto`: enumerate every detection of every
/// matcher, sort, merge overlaps, then emit. Agreement on random input proves
/// the streaming cache never copies a byte the span union would hide, which
/// is exactly what the per-matcher monotonicity contract must guarantee.
fn referenceRedact(allocator: std.mem.Allocator, input: []const u8, out: *std.ArrayList(u8)) !void {
    var spans: std.ArrayList(Span) = .empty;
    defer spans.deinit(allocator);
    for (matchers) |m| {
        var from: usize = 0;
        while (m(input, from)) |span| {
            try testing.expect(span.start < span.end and span.resume_at > from);
            try spans.append(allocator, span);
            from = span.resume_at;
        }
    }
    std.mem.sort(Span, spans.items, {}, struct {
        fn lessThan(_: void, a: Span, b: Span) bool {
            return a.start < b.start;
        }
    }.lessThan);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < spans.items.len) {
        const start = @max(spans.items[i].start, pos);
        var end = spans.items[i].end;
        i += 1;
        while (i < spans.items.len and @max(spans.items[i].start, pos) < end) : (i += 1) end = @max(end, spans.items[i].end);
        if (end <= pos) continue;
        try out.appendSlice(allocator, input[pos..start]);
        try out.appendSlice(allocator, redacted_marker);
        pos = end;
    }
    try out.appendSlice(allocator, input[pos..]);
}

test "credential_redaction: streaming merge equals the sorted span-union reference" {
    const allocator = testing.allocator;
    const fragments = [_][]const u8{
        "eyJ",          "a.b",   ".",  "=",            " = ",            "token",   "secret",           "\"",     ":",     " ",       "\r\n",   "PASS",
        "OPER",         "@t=1",  ":p", "NS",           "Bearer",         "sst_",    "0123456789abcdef", "srm2l.", "srm2m", "SESSION", "RESUME", "TOKEN",
        "AUTHENTICATE", "PLAIN", "+",  "SESSIONTOKEN", "Authorization:", "cookie:", "&",                "'",      "\\",    "x",       "\t",
    };
    var prng = std.Random.DefaultPrng.init(0x7008_0002);
    const random = prng.random();
    var input_buf: [600]u8 = undefined;
    // Room for a marker per input byte, so the comparison never truncates.
    var out_buf: [input_buf.len * redacted_marker.len]u8 = undefined;
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(allocator);
    var round: usize = 0;
    while (round < 3000) : (round += 1) {
        var n: usize = 0;
        const target = random.uintLessThan(usize, 560);
        while (n < target) {
            const frag = fragments[random.uintLessThan(usize, fragments.len)];
            @memcpy(input_buf[n .. n + frag.len], frag);
            n += frag.len;
        }
        expected.clearRetainingCapacity();
        try referenceRedact(allocator, input_buf[0..n], &expected);
        try testing.expectEqualStrings(expected.items, redactInto(input_buf[0..n], &out_buf));
    }
}

test "credential_redaction: hostile inputs stay bounded and never leak an embedded canary" {
    // Deliberately not a self-identifying shape: only its context marks it.
    const canary = "Q7wQ7wQ7wQ7w";
    const fragments = [_][]const u8{
        "eyJ",     ".",        "=",      "token",   "\"",            ":",  " ", "\r\n", "PASS", "Bearer",
        "@t=1",    "sst_",     "a1",     "&",       "Authorization", "NS", "'", "\\",   "x",    "SESSIONTOKEN",
        "SESSION", " RESUME ", "srm2l.", "WEBPUSH", "==",            "\t",
    };
    const contexts = [_][]const u8{
        " token=",           "\nPASS ",          " bearer ",           "\nOPER op ",          "\r\nAuthorization: ",
        " SESSION RESUME ",  " srm2m.",          " password = ",       "\nWEBPUSH REGISTER ", " AUTHENTICATE  ",
        " SESSION RESUME  ", " SESSION  TOKEN ", " SESSIONTOKEN a  ",  " SESSION\tMTOKEN\t",  "\nPASS\t\t",
        " label: PASS ",     " line=PASS ",      " meshpass = \"\"\"", " secret = '''",       " x: OPER op ",
    };
    var prng = std.Random.DefaultPrng.init(0x7008);
    const random = prng.random();
    var input_buf: [1024]u8 = undefined;
    var out_buf: [2048]u8 = undefined;
    var round: usize = 0;
    while (round < 2000) : (round += 1) {
        var n: usize = 0;
        while (n < 900) {
            const frag = fragments[random.uintLessThan(usize, fragments.len)];
            @memcpy(input_buf[n .. n + frag.len], frag);
            n += frag.len;
        }
        // Plant a canary behind a credential-bearing context.
        const ctx = contexts[round % contexts.len];
        const at = random.uintLessThan(usize, n);
        var line_buf: [1024 + 64]u8 = undefined;
        const line = std.fmt.bufPrint(&line_buf, "{s}{s}{s} {s}", .{ input_buf[0..at], ctx, canary, input_buf[at..n] }) catch unreachable;
        const cap = random.uintLessThan(usize, out_buf.len + 1);
        const safe = redactInto(line, out_buf[0..cap]);
        try testing.expect(safe.len <= cap);
        try testing.expect(std.mem.indexOf(u8, safe, "Q7w") == null);
        try testing.expect(containsBearer(line));
    }
    // Quadratic-shaped inputs complete (linear-skip paths).
    @memset(&input_buf, 'x');
    var i: usize = 0;
    while (i + 3 <= input_buf.len) : (i += 3) @memcpy(input_buf[i .. i + 3], "eyJ");
    try testing.expectEqualStrings(input_buf[0..], redactInto(&input_buf, &out_buf));
}
