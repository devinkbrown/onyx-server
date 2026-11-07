#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

# news_update.sh — key-free headline updater for Onyx Server's !news bot.
#
# Fetches the RSS feeds bundled in src/proto/news_sources.zig with curl (which
# uses the system CA bundle, so it reaches every feed the in-daemon clean-room
# TLS cannot) and writes one headline per line into the directory Onyx Server reads
# via `[geo] news_cache_dir`. File names match the daemon's cache keys with
# ':' -> '_': general sources -> src_<key>.txt, country feeds -> cc_<cc>.txt.
#
# Each headline is either a plain title or `epoch<TAB>title<TAB>deck`. The daemon
# turns that into "  1. [2h] Title - deck". There is no byte-length prefix:
# `${#var}` counts characters on busybox and GNU bash alike.
#
# Usage:  news_update.sh <output_dir> [max_headlines]
#         news_update.sh --check [path/to/news_sources.zig]
# Cron:   */5 * * * * /path/to/news_update.sh /var/lib/onyx-server/news 5
#
# The tables below are a copy of the catalogue so the script runs on a host
# without the source tree. `--check` compares them, entry by entry and in
# order, with news_sources.zig (default: ../src/proto/news_sources.zig next to
# this script) and exits 1 on any drift.
#
# No API keys. Requires: bash, curl, awk, date. Optional: a feed is simply
# skipped if it is unreachable, leaving any previously written file intact.
set -uo pipefail

# General sources: key|url  (mirrors news_sources.sources)
SOURCES=(
  "abc|https://abcnews.com/abcnews/topstories"
  "bbc|https://feeds.bbci.co.uk/news/rss.xml"
  "aljazeera|https://www.aljazeera.com/xml/rss/all.xml"
  "euronews|https://www.euronews.com/rss?level=theme&name=news"
  "guardian|https://www.theguardian.com/world/rss"
  "nyt|https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml"
  "npr|https://feeds.npr.org/1001/rss.xml"
  "hill|https://thehill.com/news/feed/"
  "fox|https://moxie.foxnews.com/google-publisher/latest.xml"
  "ars|https://feeds.arstechnica.com/arstechnica/index"
  "verge|https://www.theverge.com/rss/index.xml"
  "wired|https://www.wired.com/feed/rss"
  "techcrunch|https://techcrunch.com/feed/"
  "sciam|https://www.scientificamerican.com/platform/syndication/rss/"
  "wsj|https://feeds.content.dowjones.io/public/rss/RSSWorldNews"
  "cnbc|https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114"
  "bbcsport|https://feeds.bbci.co.uk/sport/rss.xml"
  "cbssports|https://www.cbssports.com/rss/headlines/"
  "cbs|https://www.cbsnews.com/latest/rss/world"
  "sky|https://feeds.skynews.com/feeds/rss/world.xml"
  "wapo|https://feeds.washingtonpost.com/rss/world"
  "dw|https://rss.dw.com/rdf/rss-en-all"
)

# Country feeds: cc|url  (mirrors news_sources.country_feeds)
COUNTRY_FEEDS=(
  "US|https://feeds.npr.org/1001/rss.xml"
  "GB|https://feeds.bbci.co.uk/news/rss.xml"
  "CA|https://www.cbc.ca/webfeed/rss/rss-topstories"
  "AU|https://www.abc.net.au/news/feed/51120/rss.xml"
  "NZ|https://www.nzherald.co.nz/arc/outboundfeeds/rss/curated/78/?outputType=xml"
  "IE|https://www.rte.ie/feeds/rss/?index=/news/&limit=20"
  "IN|https://timesofindia.indiatimes.com/rssfeedstopstories.cms"
  "DE|https://www.spiegel.de/international/index.rss"
  "FR|https://www.france24.com/en/rss"
  "JP|https://www.japantimes.co.jp/feed/"
  "BR|https://feeds.bbci.co.uk/portuguese/rss.xml"
  "ZA|https://www.dailymaverick.co.za/dmrss/"
  "KR|https://www.koreaherald.com/rss/newsAll"
  "SG|https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml"
  "PH|https://www.philstar.com/rss/headlines"
  "PK|https://www.geo.tv/rss/1/1"
  "NG|https://www.vanguardngr.com/feed/"
  "EG|https://www.egyptindependent.com/feed/"
  "AR|https://buenosairesherald.com/feed"
  "SE|https://feeds.thelocal.com/rss/se"
  "NO|https://feeds.thelocal.com/rss/no"
  "DK|https://feeds.thelocal.com/rss/dk"
  "FI|https://yle.fi/rss/t/18-34837/en"
  "NL|https://www.dutchnews.nl/feed/"
  "CH|https://www.srf.ch/news/bnf/rss/1646"
  "AT|https://feeds.thelocal.com/rss/at"
  "RU|https://www.themoscowtimes.com/rss/news"
  "IL|https://www.jpost.com/rss/rssfeedsfrontpage.aspx"
  "SA|https://saudigazette.com.sa/rssFeed/74"
  "AE|https://www.thenationalnews.com/arc/outboundfeeds/rss/?outputType=xml&size=20"
  "GR|https://www.tovima.com/feed/"
  "IT|https://feeds.thelocal.com/rss/it"
  "ES|https://feeds.thelocal.com/rss/es"
  "PT|https://www.theportugalnews.com/rss"
  "MY|https://www.malaymail.com/feed/rss/malaysia"
  "ID|https://www.antaranews.com/rss/terkini.xml"
  "TH|https://www.bangkokpost.com/rss/data/topstories.xml"
  "VN|https://e.vnexpress.net/rss/news.rss"
  "HK|https://www.scmp.com/rss/91/feed/"
  "TW|https://www.taipeitimes.com/xml/index.rss"
  "KE|https://nation.africa/kenya/rss.xml"
  "MA|https://northafricapost.com/feed"
  "CL|https://www.latercera.com/arc/outboundfeeds/rss/?outputType=xml&size=20"
  "BE|https://www.vrt.be/vrtnws/en.rss.articles.xml"
  "CN|https://www.cgtn.com/subscribe/rss/section/china.xml"
)

# Print `<id>|<url>` for every entry of one table in news_sources.zig.
# $1 = file, $2 = table name (sources | country_feeds), $3 = id field (key | cc).
catalogue_table() {
  sed -n "/^pub const $2 = /,/^};/p" "$1" |
    sed -n -E "s/.*\\.$3 = \"([^\"]+)\", \\.name = \"[^\"]*\", \\.url = \"([^\"]+)\".*/\\1|\\2/p"
}

check_catalogue() {
  local zig="$1" rc=0
  if [[ ! -r "$zig" ]]; then
    echo "news_update.sh: cannot read $zig" >&2
    return 2
  fi
  if ! diff -u --label "news_sources.zig sources" --label "news_update.sh SOURCES" \
    <(catalogue_table "$zig" sources key) <(printf '%s\n' "${SOURCES[@]}"); then
    rc=1
  fi
  if ! diff -u --label "news_sources.zig country_feeds" --label "news_update.sh COUNTRY_FEEDS" \
    <(catalogue_table "$zig" country_feeds cc) <(printf '%s\n' "${COUNTRY_FEEDS[@]}"); then
    rc=1
  fi
  if [[ $rc -eq 0 ]]; then
    echo "ok   ${#SOURCES[@]} sources and ${#COUNTRY_FEEDS[@]} country feeds match $zig"
  fi
  return $rc
}

if [[ "${1:-}" == "--check" ]]; then
  check_catalogue "${2:-$(dirname "$0")/../src/proto/news_sources.zig}"
  exit $?
fi

OUT_DIR="${1:?usage: news_update.sh <output_dir> [max_headlines] | --check [news_sources.zig]}"
MAX="${2:-5}"
# Same User-Agent and Accept as the daemon (geo_fetch.buildNewsRequest). Some
# feeds (philstar.com, cbc.ca) stall a request whose UA carries a URL comment.
UA="onyx-server-news/1"
ACCEPT="application/rss+xml, application/xml, text/xml"
mkdir -p "$OUT_DIR"

# Extract up to $MAX items as title<RS>when<RS>deck. RS is ASCII 0x1e and never
# reaches the cache file. Channel and <image> titles are not items.
extract_items() {
  awk -v max="$MAX" '
    BEGIN { RS = "<item[ >]|<entry[ >]"; IGNORECASE = 1; n = 0 }
    function trim(s) {
      gsub(/\r/, "", s)
      gsub(/^[ \t\n]+/, "", s)
      gsub(/[ \t\n]+$/, "", s)
      gsub(/[ \t\n]+/, " ", s)
      return s
    }
    function unwrap(raw) {
      gsub(/<!\[CDATA\[/, "", raw)
      gsub(/\]\]>/, "", raw)
      return trim(raw)
    }
    function grab(s, name,   rest, raw) {
      if (!match(s, "<" name "[^>]*>")) return ""
      rest = substr(s, RSTART + RLENGTH)
      if (!match(rest, "</" name "[^>]*>")) return ""
      raw = substr(rest, 1, RSTART - 1)
      return unwrap(raw)
    }
    NR > 1 && n < max {
      title = grab($0, "title")
      if (title == "") next
      when = grab($0, "pubDate")
      if (when == "") when = grab($0, "updated")
      if (when == "") when = grab($0, "published")
      if (when == "") when = grab($0, "dc:date")
      deck = grab($0, "description")
      if (deck == "") deck = grab($0, "summary")
      gsub(/<[^>]*>/, " ", deck)
      deck = trim(deck)
      printf "%s\036%s\036%s\n", title, when, deck
      n++
    }'
}

decode_entities() {
  # Named entities only. The 80-character deck clip below is unchanged.
  # Numeric character references are decoded on the daemon's live RSS path.
  sed -E 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&#39;/'\''/g; s/&quot;/"/g; s/&apos;/'\''/g; s/&nbsp;/ /g; s/&rsquo;/'\''/g; s/&lsquo;/'\''/g; s/&rdquo;/"/g; s/&ldquo;/"/g; s/&hellip;/.../g; s/&ndash;/-/g; s/&mdash;/--/g'
}

pack_lines() {
  local title when deck rest epoch
  while IFS= read -r rec; do
    title="${rec%%$'\036'*}"
    rest="${rec#*$'\036'}"
    when="${rest%%$'\036'*}"
    deck="${rest#*$'\036'}"
    title="$(printf '%s' "$title" | decode_entities)"
    deck="$(printf '%s' "$deck" | decode_entities)"
    title="${title//$'\t'/ }"
    deck="${deck//$'\t'/ }"
    title="${title:0:110}"
    deck="${deck:0:80}"
    title="${title#"${title%%[![:space:]]*}"}"
    title="${title%"${title##*[![:space:]]}"}"
    deck="${deck#"${deck%%[![:space:]]*}"}"
    deck="${deck%"${deck##*[![:space:]]}"}"
    [[ -n "$title" ]] || continue
    epoch=0
    if [[ -n "$when" ]]; then
      epoch="$(date -u -d "$when" +%s 2>/dev/null || true)"
      [[ "$epoch" =~ ^[0-9]+$ ]] || epoch=0
    fi
    if [[ "$epoch" == 0 && -z "$deck" ]]; then
      printf '%s\n' "$title"
    elif [[ -n "$deck" ]]; then
      printf '%s\t%s\t%s\n' "$epoch" "$title" "$deck"
    else
      printf '%s\t%s\n' "$epoch" "$title"
    fi
  done
}

fetch_one() {
  local stem="$1" url="$2"
  local tmp body
  tmp="$(mktemp)"
  body="$(curl -fsSL --max-time 15 -A "$UA" -H "Accept: $ACCEPT" "$url" 2>/dev/null | extract_items | pack_lines)"
  if [[ -n "$body" ]]; then
    printf '# %s — updated %s\n%s\n' "$stem" "$(date -u +%FT%TZ)" "$body" > "$tmp"
    mv -f "$tmp" "$OUT_DIR/$stem.txt"
    echo "ok   $stem ($(printf '%s\n' "$body" | wc -l) headlines)"
  else
    rm -f "$tmp"
    echo "skip $stem (unreachable / empty)"
  fi
}

for entry in "${SOURCES[@]}"; do
  fetch_one "src_${entry%%|*}" "${entry#*|}"
done
for entry in "${COUNTRY_FEEDS[@]}"; do
  cc="${entry%%|*}"
  fetch_one "cc_$(echo "$cc" | tr '[:upper:]' '[:lower:]')" "${entry#*|}"
done
