// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRC numeric replies and errors.
//!
//! Onyx Server keeps numerics as compile-time protocol metadata: the enum is the
//! source of truth, and `numericTable` is derived from it for lookup and
//! validation.
const std = @import("std");

/// IRC reply/error numeric code.
pub const Numeric = enum(u16) {
    RPL_WELCOME = 1,
    RPL_YOURHOST = 2,
    RPL_CREATED = 3,
    RPL_MYINFO = 4,
    RPL_ISUPPORT = 5,
    // RPL_SNOMASK (8) / RPL_REDIR (10) removed: snomask rides the Event Spine,
    // server-bounce is gone. MAP is KEPT — reimagined to render the Undertow
    // mesh topology (nodes/peers) rather than a TS6 spanning tree.
    RPL_MAP = 15,
    RPL_MAPMORE = 16,
    RPL_MAPEND = 17,
    RPL_SAVENICK = 43,

    RPL_TRACELINK = 200,
    RPL_TRACECONNECTING = 201,
    RPL_TRACEHANDSHAKE = 202,
    RPL_TRACEUNKNOWN = 203,
    RPL_TRACEOPERATOR = 204,
    RPL_TRACEUSER = 205,
    RPL_TRACESERVER = 206,
    RPL_TRACENEWTYPE = 208,
    RPL_TRACECLASS = 209,
    RPL_STATSLINKINFO = 211,
    RPL_STATSCOMMANDS = 212,
    RPL_STATSCLINE = 213,
    RPL_STATSNLINE = 214,
    RPL_STATSILINE = 215,
    RPL_STATSKLINE = 216,
    RPL_STATSQLINE = 217,
    RPL_STATSYLINE = 218,
    RPL_ENDOFSTATS = 219,
    RPL_STATSPLINE = 220,
    RPL_UMODEIS = 221,
    RPL_STATSFLINE = 224,
    RPL_STATSDLINE = 225,
    RPL_SERVLIST = 234,
    RPL_SERVLISTEND = 235,
    RPL_STATSLLINE = 241,
    RPL_STATSUPTIME = 242,
    RPL_STATSOLINE = 243,
    RPL_STATSHLINE = 244,
    RPL_STATSSLINE = 245,
    RPL_STATSXLINE = 247,
    RPL_STATSULINE = 248,
    RPL_STATSDEBUG = 249,
    RPL_STATSCONN = 250,
    RPL_LUSERCLIENT = 251,
    RPL_LUSEROP = 252,
    RPL_LUSERUNKNOWN = 253,
    RPL_LUSERCHANNELS = 254,
    RPL_LUSERME = 255,
    RPL_ADMINME = 256,
    RPL_ADMINLOC1 = 257,
    RPL_ADMINLOC2 = 258,
    RPL_ADMINEMAIL = 259,
    RPL_TRACELOG = 261,
    RPL_ENDOFTRACE = 262,
    RPL_LOAD2HI = 263,
    RPL_LOCALUSERS = 265,
    RPL_GLOBALUSERS = 266,
    RPL_PRIVS = 270,
    RPL_WHOISCERTFP = 276,
    RPL_WHOISSECURE = 671,
    RPL_ACCEPTLIST = 281,
    RPL_ENDOFACCEPT = 282,
    RPL_NONE = 300,
    RPL_AWAY = 301,
    RPL_USERHOST = 302,
    RPL_ISON = 303,
    RPL_TEXT = 304,
    RPL_UNAWAY = 305,
    RPL_NOWAWAY = 306,
    RPL_WHOISHELPOP = 310,
    RPL_WHOISUSER = 311,
    RPL_WHOISSERVER = 312,
    RPL_WHOISOPERATOR = 313,
    RPL_WHOWASUSER = 314,
    RPL_ENDOFWHO = 315,
    RPL_WHOISCHANOP = 316,
    RPL_WHOISIDLE = 317,
    RPL_ENDOFWHOIS = 318,
    RPL_WHOISCHANNELS = 319,
    RPL_WHOISSPECIAL = 320,
    RPL_LISTSTART = 321,
    RPL_LIST = 322,
    RPL_LISTEND = 323,
    RPL_CHANNELMODEIS = 324,
    RPL_CHANNELMLOCK = 325,
    RPL_CHANNELURL = 328,
    RPL_CREATIONTIME = 329,
    RPL_WHOISLOGGEDIN = 330,
    RPL_NOTOPIC = 331,
    RPL_TOPIC = 332,
    RPL_TOPICWHOTIME = 333,
    RPL_WHOISBOT = 335,
    RPL_WHOISACTUALLY = 338,
    RPL_INVITING = 341,
    RPL_SUMMONING = 342,
    RPL_WHOISCOUNTRY = 344,
    RPL_INVITELIST = 346,
    RPL_ENDOFINVITELIST = 347,
    RPL_EXCEPTLIST = 348,
    RPL_ENDOFEXCEPTLIST = 349,
    RPL_VERSION = 351,
    RPL_WHOREPLY = 352,
    RPL_NAMREPLY = 353,
    RPL_WHOSPCRPL = 354,
    RPL_WHOWASREAL = 360,
    RPL_KILLDONE = 361,
    RPL_CLOSING = 362,
    RPL_CLOSEEND = 363,
    // LINKS is KEPT — reimagined to list Undertow mesh peers (not a spanning
    // tree). See also RPL_MAP (15-17).
    RPL_LINKS = 364,
    RPL_ENDOFLINKS = 365,
    RPL_ENDOFNAMES = 366,
    RPL_BANLIST = 367,
    RPL_ENDOFBANLIST = 368,
    RPL_ENDOFWHOWAS = 369,
    RPL_INFO = 371,
    RPL_MOTD = 372,
    RPL_INFOSTART = 373,
    RPL_ENDOFINFO = 374,
    RPL_MOTDSTART = 375,
    RPL_ENDOFMOTD = 376,
    RPL_WHOISHOST = 378,
    RPL_YOUREOPER = 381,
    RPL_REHASHING = 382,
    RPL_MYPORTIS = 384,
    RPL_NOTOPERANYMORE = 385,
    RPL_RSACHALLENGE = 386,
    RPL_TIME = 391,
    RPL_USERSSTART = 392,
    RPL_USERS = 393,
    RPL_ENDOFUSERS = 394,
    RPL_NOUSERS = 395,
    RPL_HOSTHIDDEN = 396,

    ERR_NOSUCHNICK = 401,
    ERR_NOSUCHSERVER = 402,
    ERR_NOSUCHCHANNEL = 403,
    ERR_CANNOTSENDTOCHAN = 404,
    ERR_TOOMANYCHANNELS = 405,
    ERR_WASNOSUCHNICK = 406,
    ERR_TOOMANYTARGETS = 407,
    ERR_NOORIGIN = 409,
    ERR_INVALIDCAPCMD = 410,
    ERR_NORECIPIENT = 411,
    ERR_NOTEXTTOSEND = 412,
    ERR_NOTOPLEVEL = 413,
    ERR_WILDTOPLEVEL = 414,
    ERR_TOOMANYMATCHES = 416,
    ERR_INPUTTOOLONG = 417,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NOMOTD = 422,
    ERR_NOADMININFO = 423,
    ERR_FILEERROR = 424,
    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
    ERR_BANNICKCHANGE = 435,
    ERR_NICKCOLLISION = 436,
    ERR_UNAVAILRESOURCE = 437,
    ERR_NICKTOOFAST = 438,
    ERR_SERVICESDOWN = 440,
    ERR_USERNOTINCHANNEL = 441,
    ERR_NOTONCHANNEL = 442,
    ERR_USERONCHANNEL = 443,
    ERR_NOLOGIN = 444,
    ERR_SUMMONDISABLED = 445,
    ERR_USERSDISABLED = 446,
    ERR_NOTREGISTERED = 451,
    ERR_ACCEPTFULL = 456,
    ERR_ACCEPTEXIST = 457,
    ERR_ACCEPTNOT = 458,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTRED = 462,
    ERR_NOPERMFORHOST = 463,
    ERR_PASSWDMISMATCH = 464,
    ERR_YOUREBANNEDCREEP = 465,
    ERR_YOUWILLBEBANNED = 466,
    ERR_KEYSET = 467,
    ERR_INVALIDUSERNAME = 468,
    ERR_LINKCHANNEL = 470,
    ERR_CHANNELISFULL = 471,
    ERR_UNKNOWNMODE = 472,
    ERR_INVITEONLYCHAN = 473,
    ERR_BANNEDFROMCHAN = 474,
    ERR_BADCHANNELKEY = 475,
    ERR_BADCHANMASK = 476,
    ERR_NEEDREGGEDNICK = 477,
    ERR_BANLISTFULL = 478,
    ERR_BADCHANNAME = 479,
    ERR_THROTTLE = 480,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_CANTKILLSERVER = 483,
    ERR_ISCHANSERVICE = 484,
    ERR_BANNEDNICK = 485,
    ERR_NONONREG = 486,
    ERR_VOICENEEDED = 489,
    ERR_NOOPERHOST = 491,
    ERR_CANNOTSENDTOUSER = 492,
    ERR_OWNMODE = 494,
    ERR_UMODEUNKNOWNFLAG = 501,
    ERR_USERSDONTMATCH = 502,
    ERR_GHOSTEDCLIENT = 503,
    ERR_USERNOTONSERV = 504,
    ERR_WRONGPONG = 513,
    ERR_DISABLED = 517,
    ERR_HELPNOTFOUND = 524,
    ERR_INVALIDKEY = 525,
    ERR_NOCOMICDATA = 531,

    // Caller-id (usermode +g / ACCEPT). When a +g recipient has not accepted the
    // sender, the DM is dropped: the sender gets 716 (and optionally 717), and
    // the recipient is notified once with 718.
    ERR_CANTSENDTOUSER = 716,
    RPL_TARGNOTIFY = 717,
    RPL_UMODEGMSG = 718,

    RPL_EVENTADD = 808,
    RPL_EVENTLIST = 809,
    RPL_EVENTEND = 810,
    ERR_EVENTDUP = 821,
    ERR_EVENTMIS = 822,
    ERR_NOSUCHEVENT = 823,
    RPL_EVENTDELETE = 824,
    RPL_EVENTCHANGE = 825,

    RPL_LOGGEDIN = 900,
    RPL_LOGGEDOUT = 901,
    ERR_NICKLOCKED = 902,
    RPL_SASLSUCCESS = 903,
    ERR_SASLFAIL = 904,
    ERR_SASLTOOLONG = 905,
    ERR_SASLABORTED = 906,
    ERR_SASLALREADY = 907,
    RPL_SASLMECHS = 908,
};

/// Numeric enum values in declaration order.
pub const numericTable = buildNumericTable();

comptime {
    @setEvalBranchQuota(100_000);

    for (numericTable, 0..) |left, left_index| {
        for (numericTable[left_index + 1 ..]) |right| {
            if (code(left) == code(right)) {
                @compileError("duplicate IRC numeric code");
            }
        }
    }
}

fn buildNumericTable() [@typeInfo(Numeric).@"enum".field_names.len]Numeric {
    const field_values = @typeInfo(Numeric).@"enum".field_values;
    var table: [field_values.len]Numeric = undefined;
    for (field_values, 0..) |field_value, index| {
        table[index] = @as(Numeric, @fromBackingInt(@intCast(field_value)));
    }
    return table;
}

/// Return the integer code for `n`.
pub fn code(n: Numeric) u16 {
    return @backingInt(n);
}

/// Return the symbolic IRC name for `n`.
pub fn name(n: Numeric) []const u8 {
    return @tagName(n);
}

/// Look up a known IRC numeric by integer code.
pub fn fromCode(value: u16) ?Numeric {
    for (numericTable) |numeric| {
        if (code(numeric) == value) {
            return numeric;
        }
    }
    return null;
}

/// Format `n` as a three-digit, zero-padded IRC code into caller-owned storage.
pub fn formatCode(n: Numeric, buf: []u8) []const u8 {
    if (buf.len < 3) {
        return buf[0..0];
    }

    const value = code(n);
    buf[0] = @as(u8, '0') + @as(u8, @intCast((value / 100) % 10));
    buf[1] = @as(u8, '0') + @as(u8, @intCast((value / 10) % 10));
    buf[2] = @as(u8, '0') + @as(u8, @intCast(value % 10));
    return buf[0..3];
}

test "numeric code and name helpers round-trip" {
    const samples = [_]Numeric{
        .RPL_WELCOME,
        .RPL_LUSERCLIENT,
        .RPL_WHOISUSER,
        .RPL_NAMREPLY,
        .RPL_ENDOFNAMES,
        .ERR_NOSUCHNICK,
        .ERR_CHANOPRIVSNEEDED,
        .RPL_SASLSUCCESS,
        .ERR_SASLFAIL,
    };

    for (samples) |numeric| {
        try std.testing.expectEqual(numeric, fromCode(code(numeric)));
        try std.testing.expectEqualStrings(@tagName(numeric), name(numeric));
    }
}

test "fromCode returns null for unknown numeric" {
    try std.testing.expectEqual(@as(?Numeric, null), fromCode(999));
}

test "formatCode uses three-digit zero padding" {
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualStrings("001", formatCode(.RPL_WELCOME, &buf));
}

test "selected canonical codes are exact" {
    try std.testing.expectEqual(@as(u16, 1), code(.RPL_WELCOME));
    try std.testing.expectEqual(@as(u16, 366), code(.RPL_ENDOFNAMES));
    try std.testing.expectEqual(@as(u16, 401), code(.ERR_NOSUCHNICK));
    try std.testing.expectEqual(@as(u16, 808), code(.RPL_EVENTADD));
    try std.testing.expectEqual(@as(u16, 823), code(.ERR_NOSUCHEVENT));
    try std.testing.expectEqual(@as(u16, 825), code(.RPL_EVENTCHANGE));
}
