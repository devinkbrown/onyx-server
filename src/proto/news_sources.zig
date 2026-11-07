// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Working news/weather data sources — a curated set of proven, no-API-key
//! feeds. This module is *data only*: the source URLs and their metadata.
//! Fetching, caching, and parsing live elsewhere (`geo_fetch.zig` builds
//! requests / parses bodies; `geo_services` does the background I/O).
//!
//! Weather uses wttr.in (see `geo_fetch.weather_host`); news uses the RSS feeds
//! below. Keeping the source list in one typed table lets `!news`/`!localnews`
//! resolve a feed by key or by the user's GeoIP country.
const std = @import("std");

/// A general news feed with editorial leaning + topic tags.
pub const Source = struct {
    key: []const u8,
    name: []const u8,
    url: []const u8,
    leaning: []const u8,
    topics: []const []const u8,
};

/// A country's default headline feed, keyed by ISO 3166-1 alpha-2 code.
pub const CountryFeed = struct {
    cc: []const u8,
    name: []const u8,
    url: []const u8,
};

/// Countries that read weather in imperial units. Note:
/// `weather_units.forCountry` carries a broader list; this is the compact set
/// used for `!weather` unit selection.
pub const imperial_countries = [_][]const u8{ "US", "LR", "MM" };

/// Default general source when the user names none (a center wire; BBC World is
/// a safe, reliable pick).
pub const default_source_key = "bbc";

/// General news sources, verbatim URLs.
pub const sources = [_]Source{
    .{ .key = "abc", .name = "ABC News", .url = "https://abcnews.com/abcnews/topstories", .leaning = "center", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "bbc", .name = "BBC World", .url = "https://feeds.bbci.co.uk/news/rss.xml", .leaning = "center", .topics = &.{ "world", "uk" } },
    .{ .key = "aljazeera", .name = "Al Jazeera", .url = "https://www.aljazeera.com/xml/rss/all.xml", .leaning = "center", .topics = &.{ "world", "politics" } },
    .{ .key = "euronews", .name = "Euronews", .url = "https://www.euronews.com/rss?level=theme&name=news", .leaning = "center", .topics = &.{ "world", "politics" } },
    .{ .key = "guardian", .name = "The Guardian", .url = "https://www.theguardian.com/world/rss", .leaning = "center-left", .topics = &.{ "world", "us", "politics", "environment" } },
    .{ .key = "nyt", .name = "NY Times", .url = "https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml", .leaning = "center-left", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "npr", .name = "NPR", .url = "https://feeds.npr.org/1001/rss.xml", .leaning = "center-left", .topics = &.{ "us", "world" } },
    .{ .key = "hill", .name = "The Hill", .url = "https://thehill.com/news/feed/", .leaning = "center", .topics = &.{ "politics", "us" } },
    .{ .key = "fox", .name = "Fox News", .url = "https://moxie.foxnews.com/google-publisher/latest.xml", .leaning = "right", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "ars", .name = "Ars Technica", .url = "https://feeds.arstechnica.com/arstechnica/index", .leaning = "center", .topics = &.{ "tech", "science" } },
    .{ .key = "verge", .name = "The Verge", .url = "https://www.theverge.com/rss/index.xml", .leaning = "center-left", .topics = &.{ "tech", "science", "entertainment" } },
    .{ .key = "wired", .name = "Wired", .url = "https://www.wired.com/feed/rss", .leaning = "center-left", .topics = &.{ "tech", "science" } },
    .{ .key = "techcrunch", .name = "TechCrunch", .url = "https://techcrunch.com/feed/", .leaning = "center-left", .topics = &.{ "tech", "business" } },
    .{ .key = "sciam", .name = "Scientific American", .url = "https://www.scientificamerican.com/platform/syndication/rss/", .leaning = "center", .topics = &.{ "science", "health" } },
    .{ .key = "wsj", .name = "Wall Street Journal", .url = "https://feeds.content.dowjones.io/public/rss/RSSWorldNews", .leaning = "center-right", .topics = &.{ "world", "business", "finance" } },
    .{ .key = "cnbc", .name = "CNBC", .url = "https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114", .leaning = "center", .topics = &.{ "business", "finance" } },
    .{ .key = "bbcsport", .name = "BBC Sport", .url = "https://feeds.bbci.co.uk/sport/rss.xml", .leaning = "center", .topics = &.{"sports"} },
    .{ .key = "cbssports", .name = "CBS Sports", .url = "https://www.cbssports.com/rss/headlines/", .leaning = "center", .topics = &.{"sports"} },
    .{ .key = "cbs", .name = "CBS News", .url = "https://www.cbsnews.com/latest/rss/world", .leaning = "center", .topics = &.{ "world", "us" } },
    .{ .key = "sky", .name = "Sky News", .url = "https://feeds.skynews.com/feeds/rss/world.xml", .leaning = "center", .topics = &.{ "world", "uk" } },
    .{ .key = "wapo", .name = "Washington Post", .url = "https://feeds.washingtonpost.com/rss/world", .leaning = "center-left", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "dw", .name = "Deutsche Welle", .url = "https://rss.dw.com/rdf/rss-en-all", .leaning = "center", .topics = &.{ "world", "europe" } },
};

/// Pick a pseudo-random general source from `sources` for `seed` (e.g. a clock
/// tick mixed with the client). Used by the MOTD to vary the headline wire each
/// connect instead of always serving the default source.
pub fn randomSource(seed: u64) Source {
    return sources[seed % sources.len];
}

/// Per-country default headline feeds, verbatim URLs.
///
/// Every feed here (and in `sources`) must serve UTF-8. `geo_fetch` does no
/// charset transcoding, so a Latin-1 body would put invalid UTF-8 on the wire
/// of a UTF8ONLY server. Check `encoding=` and validate the body
/// (`iconv -f UTF-8 -t UTF-8`) before adding a feed. Probe a candidate the
/// way the daemon fetches: `curl --tlsv1.3 --http1.1 -A onyx-server-news/1`
/// without `-L` or `--compressed`. It must answer 200 directly (no redirect
/// is followed), stay under the 1 MiB fetch cap, and carry dated items.
/// `tools/news_update.sh --check` fails when its copy of these tables drifts.
pub const country_feeds = [_]CountryFeed{
    .{ .cc = "US", .name = "NPR News", .url = "https://feeds.npr.org/1001/rss.xml" },
    .{ .cc = "GB", .name = "BBC News", .url = "https://feeds.bbci.co.uk/news/rss.xml" },
    .{ .cc = "CA", .name = "CBC News", .url = "https://www.cbc.ca/webfeed/rss/rss-topstories" },
    .{ .cc = "AU", .name = "ABC News (Australia)", .url = "https://www.abc.net.au/news/feed/51120/rss.xml" },
    .{ .cc = "NZ", .name = "New Zealand Herald", .url = "https://www.nzherald.co.nz/arc/outboundfeeds/rss/curated/78/?outputType=xml" },
    .{ .cc = "IE", .name = "RTÉ News", .url = "https://www.rte.ie/feeds/rss/?index=/news/&limit=20" },
    .{ .cc = "IN", .name = "Times of India", .url = "https://timesofindia.indiatimes.com/rssfeedstopstories.cms" },
    .{ .cc = "DE", .name = "Der Spiegel", .url = "https://www.spiegel.de/international/index.rss" },
    .{ .cc = "FR", .name = "France 24", .url = "https://www.france24.com/en/rss" },
    .{ .cc = "JP", .name = "The Japan Times", .url = "https://www.japantimes.co.jp/feed/" },
    .{ .cc = "BR", .name = "BBC News Brasil", .url = "https://feeds.bbci.co.uk/portuguese/rss.xml" },
    .{ .cc = "ZA", .name = "Daily Maverick", .url = "https://www.dailymaverick.co.za/dmrss/" },
    .{ .cc = "KR", .name = "Korea Herald", .url = "https://www.koreaherald.com/rss/newsAll" },
    .{ .cc = "SG", .name = "Channel NewsAsia", .url = "https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml" },
    .{ .cc = "PH", .name = "Philippine Star", .url = "https://www.philstar.com/rss/headlines" },
    .{ .cc = "PK", .name = "Geo News", .url = "https://www.geo.tv/rss/1/1" },
    .{ .cc = "NG", .name = "Vanguard Nigeria", .url = "https://www.vanguardngr.com/feed/" },
    .{ .cc = "EG", .name = "Egypt Independent", .url = "https://www.egyptindependent.com/feed/" },
    .{ .cc = "AR", .name = "Buenos Aires Herald", .url = "https://buenosairesherald.com/feed" },
    .{ .cc = "SE", .name = "The Local Sweden", .url = "https://feeds.thelocal.com/rss/se" },
    .{ .cc = "NO", .name = "The Local Norway", .url = "https://feeds.thelocal.com/rss/no" },
    .{ .cc = "DK", .name = "The Local Denmark", .url = "https://feeds.thelocal.com/rss/dk" },
    .{ .cc = "FI", .name = "Yle News", .url = "https://yle.fi/rss/t/18-34837/en" },
    .{ .cc = "NL", .name = "DutchNews.nl", .url = "https://www.dutchnews.nl/feed/" },
    .{ .cc = "CH", .name = "SRF News", .url = "https://www.srf.ch/news/bnf/rss/1646" },
    .{ .cc = "AT", .name = "The Local Austria", .url = "https://feeds.thelocal.com/rss/at" },
    .{ .cc = "RU", .name = "The Moscow Times", .url = "https://www.themoscowtimes.com/rss/news" },
    .{ .cc = "IL", .name = "Jerusalem Post", .url = "https://www.jpost.com/rss/rssfeedsfrontpage.aspx" },
    .{ .cc = "SA", .name = "Saudi Gazette", .url = "https://saudigazette.com.sa/rssFeed/74" },
    .{ .cc = "AE", .name = "The National", .url = "https://www.thenationalnews.com/arc/outboundfeeds/rss/?outputType=xml&size=20" },
    .{ .cc = "GR", .name = "To Vima", .url = "https://www.tovima.com/feed/" },
    .{ .cc = "IT", .name = "The Local Italy", .url = "https://feeds.thelocal.com/rss/it" },
    .{ .cc = "ES", .name = "The Local Spain", .url = "https://feeds.thelocal.com/rss/es" },
    .{ .cc = "PT", .name = "The Portugal News", .url = "https://www.theportugalnews.com/rss" },
    .{ .cc = "MY", .name = "Malay Mail", .url = "https://www.malaymail.com/feed/rss/malaysia" },
    .{ .cc = "ID", .name = "ANTARA News", .url = "https://www.antaranews.com/rss/terkini.xml" },
    .{ .cc = "TH", .name = "Bangkok Post", .url = "https://www.bangkokpost.com/rss/data/topstories.xml" },
    .{ .cc = "VN", .name = "VnExpress International", .url = "https://e.vnexpress.net/rss/news.rss" },
    .{ .cc = "HK", .name = "SCMP", .url = "https://www.scmp.com/rss/91/feed/" },
    .{ .cc = "TW", .name = "Taipei Times", .url = "https://www.taipeitimes.com/xml/index.rss" },
    .{ .cc = "KE", .name = "Daily Nation Kenya", .url = "https://nation.africa/kenya/rss.xml" },
    .{ .cc = "MA", .name = "The North Africa Post", .url = "https://northafricapost.com/feed" },
    .{ .cc = "CL", .name = "La Tercera", .url = "https://www.latercera.com/arc/outboundfeeds/rss/?outputType=xml&size=20" },
    .{ .cc = "BE", .name = "VRT NWS", .url = "https://www.vrt.be/vrtnws/en.rss.articles.xml" },
    .{ .cc = "CN", .name = "CGTN", .url = "https://www.cgtn.com/subscribe/rss/section/china.xml" },
};

/// Look up a general source by its key (case-insensitive), or null.
pub fn sourceByKey(key: []const u8) ?Source {
    for (sources) |s| {
        if (std.ascii.eqlIgnoreCase(s.key, key)) return s;
    }
    return null;
}

/// The default general source (`default_source_key`).
pub fn defaultSource() Source {
    return sourceByKey(default_source_key).?;
}

/// Look up a country's default feed by ISO code (case-insensitive), or null.
pub fn countryFeed(cc: []const u8) ?CountryFeed {
    for (country_feeds) |f| {
        if (std.ascii.eqlIgnoreCase(f.cc, cc)) return f;
    }
    return null;
}

/// Whether a country reads weather in imperial units (the compact set).
pub fn usesImperial(cc: []const u8) bool {
    for (imperial_countries) |c| {
        if (std.ascii.eqlIgnoreCase(c, cc)) return true;
    }
    return false;
}

/// Headlines one `!news` reply may show. Matches `geo_services.max_headlines`.
pub const max_shown: u8 = 5;

/// Topic names a `!news` query can select. A source key of the same spelling
/// wins over the topic.
pub const topics = [_][]const u8{
    "world",       "us",      "uk",      "politics",
    "environment", "tech",    "science", "entertainment",
    "business",    "finance", "sports",  "health",
    "europe",
};

pub const NewsRequest = union(enum) {
    default_source: struct { count: u8 },
    source: struct { key: []const u8, count: u8 },
    topic: struct { name: []const u8, count: u8 },
    sources,
    usage,
};

/// Parse the argument of `!news`. `count` 0 means the caller picks its default
/// (a single source uses the configured headline count; a topic uses one).
pub fn parseNewsCommand(arg: []const u8) NewsRequest {
    var tokens: [4][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, arg, " \t");
    while (it.next()) |token| {
        if (n >= 3) return .usage;
        tokens[n] = token;
        n += 1;
    }
    if (n == 0) return .{ .default_source = .{ .count = 0 } };
    if (std.ascii.eqlIgnoreCase(tokens[0], "sources")) {
        if (n != 1) return .usage;
        return .sources;
    }
    if (std.ascii.eqlIgnoreCase(tokens[0], "topic")) {
        if (n < 2 or n > 3) return .usage;
        const name = canonicalTopic(tokens[1]) orelse return .usage;
        const count: u8 = if (n == 3) parseShownCount(tokens[2]) orelse return .usage else 0;
        return .{ .topic = .{ .name = name, .count = count } };
    }
    if (n > 2) return .usage;
    if (n == 2) {
        const count = parseShownCount(tokens[1]) orelse return .usage;
        if (sourceByKey(tokens[0])) |src| return .{ .source = .{ .key = src.key, .count = count } };
        if (canonicalTopic(tokens[0])) |name| return .{ .topic = .{ .name = name, .count = count } };
        return .usage;
    }
    if (allDigits(tokens[0])) {
        const count = parseShownCount(tokens[0]) orelse return .usage;
        return .{ .default_source = .{ .count = count } };
    }
    if (sourceByKey(tokens[0])) |src| return .{ .source = .{ .key = src.key, .count = 0 } };
    if (canonicalTopic(tokens[0])) |name| return .{ .topic = .{ .name = name, .count = 0 } };
    return .usage;
}

pub fn canonicalTopic(name: []const u8) ?[]const u8 {
    for (topics) |topic| if (std.ascii.eqlIgnoreCase(topic, name)) return topic;
    return null;
}

/// Fill `out` with indexes into `sources` that carry `topic`.
pub fn sourcesForTopic(topic: []const u8, out: []usize) usize {
    const name = canonicalTopic(topic) orelse return 0;
    var n: usize = 0;
    for (sources, 0..) |src, index| {
        if (n >= out.len) break;
        for (src.topics) |tag| if (std.ascii.eqlIgnoreCase(tag, name)) {
            out[n] = index;
            n += 1;
            break;
        };
    }
    return n;
}

pub const CatalogueLine = struct { text: []const u8, next: usize };

/// One catalogue line of `key (Name)` pairs, starting at `sources[start]`.
pub fn writeCatalogueLine(buf: []u8, start: usize) CatalogueLine {
    var n: usize = 0;
    var i = start;
    if (i >= sources.len or buf.len == 0) return .{ .text = buf[0..0], .next = i };
    while (i < sources.len) {
        var piece: [96]u8 = undefined;
        const one = std.fmt.bufPrint(&piece, "{s} ({s})", .{ sources[i].key, sources[i].name }) catch break;
        const sep: usize = if (n == 0) 0 else 2;
        if (n != 0 and n + sep + one.len > buf.len) break;
        if (n == 0 and one.len > buf.len) {
            const keep = @min(one.len, buf.len);
            @memcpy(buf[0..keep], one[0..keep]);
            return .{ .text = buf[0..keep], .next = i + 1 };
        }
        if (sep != 0) {
            buf[n] = ',';
            buf[n + 1] = ' ';
        }
        @memcpy(buf[n + sep ..][0..one.len], one);
        n += sep + one.len;
        i += 1;
    }
    return .{ .text = buf[0..n], .next = i };
}

pub fn formatTopics(buf: []u8) []const u8 {
    const head = "Topics: ";
    if (head.len > buf.len) return buf[0..0];
    @memcpy(buf[0..head.len], head);
    var n = head.len;
    for (topics, 0..) |topic, index| {
        const sep: usize = if (index == 0) 0 else 2;
        if (n + sep + topic.len > buf.len) break;
        if (sep != 0) {
            buf[n] = ',';
            buf[n + 1] = ' ';
        }
        @memcpy(buf[n + sep ..][0..topic.len], topic);
        n += sep + topic.len;
    }
    return buf[0..n];
}

fn parseShownCount(token: []const u8) ?u8 {
    if (!allDigits(token)) return null;
    const value = std.fmt.parseInt(u16, token, 10) catch return null;
    if (value < 1 or value > max_shown) return null;
    return @intCast(value);
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < '0' or c > '9') return false;
    return true;
}

// ---- tests ------------------------------------------------------------------

test "sourceByKey resolves a known source case-insensitively" {
    const s = sourceByKey("BBC").?;
    try std.testing.expectEqualStrings("BBC World", s.name);
    try std.testing.expectEqualStrings("https://feeds.bbci.co.uk/news/rss.xml", s.url);
    try std.testing.expect(sourceByKey("nope") == null);
}

test "defaultSource is a valid configured source" {
    const s = defaultSource();
    try std.testing.expectEqualStrings(default_source_key, s.key);
}

test "countryFeed maps ISO codes to feeds" {
    try std.testing.expectEqualStrings("The Japan Times", countryFeed("JP").?.name);
    try std.testing.expectEqualStrings("NPR News", countryFeed("us").?.name);
    try std.testing.expect(countryFeed("ZZ") == null);
}

test "usesImperial matches the imperial set" {
    try std.testing.expect(usesImperial("US"));
    try std.testing.expect(usesImperial("lr"));
    try std.testing.expect(!usesImperial("GB"));
    try std.testing.expect(!usesImperial("JP"));
}

test "every source and country feed has an https url" {
    for (sources) |s| try std.testing.expect(std.mem.startsWith(u8, s.url, "https://"));
    for (country_feeds) |f| try std.testing.expect(std.mem.startsWith(u8, f.url, "https://"));
}

test "retired feed URLs stay out of the catalogue" {
    // Each of these failed a live probe on 2026-11-07 (TLS failure, NXDOMAIN,
    // 3xx the fetcher does not follow, 404/410, a body over the 1 MiB fetch
    // cap, a 200 with no <item>/<entry>, or a non-UTF-8 body). None may come
    // back.
    const retired = [_][]const u8{
        "https://rss.cnn.com/rss/edition.rss",
        "https://feeds.24.com/articles/news24/TopStories/rss",
        "https://www.swissinfo.ch/eng/rss/headline_news",
        "https://thehill.com/rss/syndicator/19110/",
        "https://www.cbc.ca/cmlink/rss-topstories",
        "https://www.rte.ie/news/rss/news-headlines.xml",
        "https://feeds.yle.fi/uutiset/v1/majorHeadlines/YLE_UUTISET.rss",
        "https://www.thenationalnews.com/rss",
        "https://www.scmp.com/rss/91/feed",
        "https://santiagotimes.cl/feed/",
        "https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml",
        "https://www.thejakartapost.com/rss/dailyheadline.xml",
        "https://www.chinadaily.com.cn/rss/cndy_rss.xml",
        "https://www.koreaherald.com/rss/01.xml",
        "https://vietnamnews.vn/rss/20.rss",
        // Served as ISO-8859-1 with raw 0xA0 bytes in <title>; not UTF-8.
        "https://en.antaranews.com/rss/news.xml",
        // Second probe, 2026-11-07, in the daemon's own fetch style (TLS 1.3,
        // HTTP/1.1, `User-Agent: onyx-server-news/1`, no redirects, identity
        // coding). 301 Moved Permanently; the fetcher does not follow it.
        "https://feeds.abcnews.com/abcnews/topstories",
        "https://feeds.bbci.co.uk/portuguese/brasil/rss.xml",
        "https://egyptindependent.com/feed/",
        "https://www.thelocal.se/feeds/rss.php",
        "https://www.thelocal.no/feeds/rss.php",
        "https://www.thelocal.dk/feeds/rss.php",
        "https://www.thelocal.at/feeds/rss.php",
        "https://www.thelocal.it/feeds/rss.php",
        "https://www.thelocal.es/feeds/rss.php",
        // 403 bot challenge ("Just a moment...") to both curl and the daemon.
        "https://www.ekathimerini.com/rss",
        "https://www.moroccoworldnews.com/feed/",
        "https://www.arabnews.com/rss.xml",
        // 404.
        "https://www.malaymail.com/feed",
        "https://www.taiwannews.com.tw/ch/rss.php",
        // Server refuses TLS 1.3 (protocol_version alert to a 1.3-only hello).
        "https://www.sbs.com.au/news/feed",
        "https://www.rnz.co.nz/rss/news.xml",
        "https://www.dawn.com/feeds/home",
        // 200 text/html: the site's SPA shell, no <item>/<entry>.
        "https://www.brusselstimes.com/feed",
        // 200 but frozen: newest item 2025-01-27 (WSJ moved its feeds to
        // feeds.content.dowjones.io) and 2025-06-16 respectively.
        "https://feeds.a.dj.com/rss/RSSWorldNews.xml",
        "https://www.jpost.com/rss/rssfeedsheadlines.aspx",
        // AWS WAF answers the daemon's TLS client with an empty
        // `202 Accepted` + `x-amzn-waf-action: challenge`; curl gets 200.
        "https://www.espn.com/espn/rss/news",
    };
    for (retired) |dead| {
        for (sources) |s| try std.testing.expect(!std.mem.eql(u8, s.url, dead));
        for (country_feeds) |f| try std.testing.expect(!std.mem.eql(u8, f.url, dead));
    }
    // CNN publishes no live HTTPS feed (rss.cnn.com fails TLS; its plain-HTTP
    // feeds stopped updating in 2024), so the key resolves to nothing.
    try std.testing.expect(sourceByKey("cnn") == null);
    // ESPN's only feed host challenges the daemon's client; BBC Sport carries
    // the sports topic alongside CBS Sports.
    try std.testing.expect(sourceByKey("espn") == null);
    try std.testing.expectEqualStrings("https://feeds.bbci.co.uk/sport/rss.xml", sourceByKey("bbcsport").?.url);
}

test "catalogue keys, country codes, and URL shapes are well formed" {
    for (sources, 0..) |s, i| {
        for (sources[i + 1 ..]) |other| try std.testing.expect(!std.ascii.eqlIgnoreCase(s.key, other.key));
        const rest = s.url["https://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.TestUnexpectedResult;
        try std.testing.expect(slash > 0);
        try std.testing.expect(s.topics.len > 0);
        for (s.topics) |tag| try std.testing.expect(canonicalTopic(tag) != null);
    }
    for (country_feeds, 0..) |f, i| {
        try std.testing.expectEqual(@as(usize, 2), f.cc.len);
        for (f.cc) |c| try std.testing.expect(c >= 'A' and c <= 'Z');
        for (country_feeds[i + 1 ..]) |other| try std.testing.expect(!std.ascii.eqlIgnoreCase(f.cc, other.cc));
        const rest = f.url["https://".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.TestUnexpectedResult;
        try std.testing.expect(slash > 0);
        for (f.url) |c| try std.testing.expect(c > 0x20 and c < 0x7f);
    }
}

test "parseNewsCommand distinguishes sources, topics, counts, and usage" {
    const bare = parseNewsCommand("");
    try std.testing.expect(bare == .default_source);
    try std.testing.expectEqual(@as(u8, 0), bare.default_source.count);

    const counted = parseNewsCommand("4");
    try std.testing.expectEqual(@as(u8, 4), counted.default_source.count);
    try std.testing.expect(parseNewsCommand("0") == .usage);
    try std.testing.expect(parseNewsCommand("6") == .usage);
    try std.testing.expect(parseNewsCommand("99") == .usage);

    const bbc = parseNewsCommand("BBC");
    try std.testing.expectEqualStrings("bbc", bbc.source.key);
    try std.testing.expectEqual(@as(u8, 0), bbc.source.count);
    const bbc_n = parseNewsCommand("bbc 2");
    try std.testing.expectEqualStrings("bbc", bbc_n.source.key);
    try std.testing.expectEqual(@as(u8, 2), bbc_n.source.count);

    const sports = parseNewsCommand("Sports");
    try std.testing.expectEqualStrings("sports", sports.topic.name);
    try std.testing.expectEqual(@as(u8, 0), sports.topic.count);
    const topic = parseNewsCommand("topic europe 3");
    try std.testing.expectEqualStrings("europe", topic.topic.name);
    try std.testing.expectEqual(@as(u8, 3), topic.topic.count);

    try std.testing.expect(parseNewsCommand("sources") == .sources);
    try std.testing.expect(parseNewsCommand("sources 2") == .usage);
    try std.testing.expect(parseNewsCommand("topic") == .usage);
    try std.testing.expect(parseNewsCommand("bbc 2 extra") == .usage);
    try std.testing.expect(parseNewsCommand("nope") == .usage);

    var indexes: [sources.len]usize = undefined;
    const found = sourcesForTopic("tech", &indexes);
    try std.testing.expect(found >= 2);
    try std.testing.expectEqual(sources[indexes[0]].key, "ars");
    var line: [180]u8 = undefined;
    const first = writeCatalogueLine(&line, 0);
    try std.testing.expect(std.mem.startsWith(u8, first.text, "abc (ABC News)"));
    try std.testing.expect(first.next > 0);
    var topics_buf: [180]u8 = undefined;
    try std.testing.expect(std.mem.startsWith(u8, formatTopics(&topics_buf), "Topics: world, us, uk"));
}
