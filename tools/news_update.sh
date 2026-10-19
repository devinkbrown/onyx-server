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
# Cron:   */5 * * * * /path/to/news_update.sh /var/lib/onyx-server/news 5
#
# No API keys. Requires: bash, curl, awk, date. Optional: a feed is simply
# skipped if it is unreachable, leaving any previously written file intact.
set -uo pipefail

OUT_DIR="${1:?usage: news_update.sh <output_dir> [max_headlines]}"
MAX="${2:-5}"
UA="OnyxServer-news/1 (+https://onyx.local)"
mkdir -p "$OUT_DIR"

# General sources: key|url  (mirrors news_sources.sources)
SOURCES=(
  "abc|https://feeds.abcnews.com/abcnews/topstories"
  "bbc|https://feeds.bbci.co.uk/news/rss.xml"
  "aljazeera|https://www.aljazeera.com/xml/rss/all.xml"
  "euronews|https://www.euronews.com/rss?level=theme&name=news"
  "guardian|https://www.theguardian.com/world/rss"
  "nyt|https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml"
  "npr|https://feeds.npr.org/1001/rss.xml"
  "hill|https://thehill.com/rss/syndicator/19110/"
  "fox|https://moxie.foxnews.com/google-publisher/latest.xml"
  "ars|https://feeds.arstechnica.com/arstechnica/index"
  "verge|https://www.theverge.com/rss/index.xml"
  "wired|https://www.wired.com/feed/rss"
  "techcrunch|https://techcrunch.com/feed/"
  "sciam|https://www.scientificamerican.com/platform/syndication/rss/"
  "wsj|https://feeds.a.dj.com/rss/RSSWorldNews.xml"
  "cnbc|https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114"
  "espn|https://www.espn.com/espn/rss/news"
  "cbssports|https://www.cbssports.com/rss/headlines/"
  "cbs|https://www.cbsnews.com/latest/rss/world"
  "sky|https://feeds.skynews.com/feeds/rss/world.xml"
  "wapo|https://feeds.washingtonpost.com/rss/world"
  "dw|https://rss.dw.com/rdf/rss-en-all"
  "cnn|https://rss.cnn.com/rss/edition.rss"
)

# Country feeds: cc|url  (mirrors news_sources.country_feeds)
COUNTRY_FEEDS=(
  "US|https://feeds.npr.org/1001/rss.xml"
  "GB|https://feeds.bbci.co.uk/news/rss.xml"
  "CA|https://www.cbc.ca/cmlink/rss-topstories"
  "AU|https://www.sbs.com.au/news/feed"
  "NZ|https://www.rnz.co.nz/rss/news.xml"
  "IE|https://www.rte.ie/news/rss/news-headlines.xml"
  "IN|https://timesofindia.indiatimes.com/rssfeedstopstories.cms"
  "DE|https://www.spiegel.de/international/index.rss"
  "FR|https://www.france24.com/en/rss"
  "JP|https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml"
  "BR|https://feeds.bbci.co.uk/portuguese/brasil/rss.xml"
  "ZA|https://feeds.24.com/articles/news24/TopStories/rss"
  "KR|https://www.koreaherald.com/rss/01.xml"
  "SG|https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml"
  "PH|https://www.philstar.com/rss/headlines"
  "PK|https://www.dawn.com/feeds/home"
  "NG|https://www.vanguardngr.com/feed/"
  "EG|https://egyptindependent.com/feed/"
  "AR|https://buenosairesherald.com/feed"
  "SE|https://www.thelocal.se/feeds/rss.php"
  "NO|https://www.thelocal.no/feeds/rss.php"
  "DK|https://www.thelocal.dk/feeds/rss.php"
  "FI|https://feeds.yle.fi/uutiset/v1/majorHeadlines/YLE_UUTISET.rss"
  "NL|https://www.dutchnews.nl/feed/"
  "CH|https://www.swissinfo.ch/eng/rss/headline_news"
  "AT|https://www.thelocal.at/feeds/rss.php"
  "RU|https://www.themoscowtimes.com/rss/news"
  "IL|https://www.jpost.com/rss/rssfeedsheadlines.aspx"
  "SA|https://www.arabnews.com/rss.xml"
  "AE|https://www.thenationalnews.com/rss"
  "GR|https://www.ekathimerini.com/rss"
  "IT|https://www.thelocal.it/feeds/rss.php"
  "ES|https://www.thelocal.es/feeds/rss.php"
  "PT|https://www.theportugalnews.com/rss"
  "MY|https://www.malaymail.com/feed"
  "ID|https://www.thejakartapost.com/rss/dailyheadline.xml"
  "TH|https://www.bangkokpost.com/rss/data/topstories.xml"
  "VN|https://vietnamnews.vn/rss/20.rss"
  "HK|https://www.scmp.com/rss/91/feed"
  "TW|https://www.taiwannews.com.tw/ch/rss.php"
  "KE|https://nation.africa/kenya/rss.xml"
  "MA|https://www.moroccoworldnews.com/feed/"
  "CL|https://santiagotimes.cl/feed/"
  "BE|https://www.brusselstimes.com/feed"
  "CN|https://www.chinadaily.com.cn/rss/cndy_rss.xml"
)

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
  body="$(curl -fsSL --max-time 15 -A "$UA" "$url" 2>/dev/null | extract_items | pack_lines)"
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
