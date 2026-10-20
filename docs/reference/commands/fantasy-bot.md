# Weather and news fantasy bot

*Server-answered in-channel `!` commands for weather and news, with no pseudo-clients.*

Mode +B and WHOIS 335 mark a bot. `announce_board` stays loaded and off the WHOIS and fantasy paths. `BOTGRANT` records the account in `bot_registry` so the grant counts as a bot, and that registry does not answer channel `!` commands. The in-channel commands are `!weather`, `!forecast`, and `!news`.

Onyx Server answers a small set of in-channel `!` fantasy commands directly from the
server, with no pseudo-clients (`src/daemon/server.zig:11150`, `handleFantasy`).
The triggering message reaches the channel normally; the server posts the answer
as a channel `PRIVMSG` sourced from this node's `server_name` and relays it once
across the mesh, so members on every node see a single reply from the replying
server (`src/daemon/server.zig:fantasyReply`).

All data sources are key-free. Weather and the three-day forecast come from
`wttr.in?format=j1` over plain HTTP (the old one-line body is still accepted).
News comes from the RSS feeds bundled in `src/proto/news_sources.zig`. Fetching
runs on a dedicated background thread (`src/daemon/geo_services.zig`) so the
reactor never blocks. A cache miss does not ask the user to retry: the same
command is answered with the report when the fetch finishes. A failed fetch
sends one "unavailable" `PRIVMSG` and is tried again after 30 seconds without
wiping a reading that was already cached. Enable the bot with
`[geo] enabled = true` (see [config.md](../config.md#geo)).

## !weather

- Syntax: `!weather [location]` (aliases `!w`, `!wx`)
- Description: Reports current conditions. Place order: the argument (80
  characters) → the user's `location` metadata → the channel's `!setweather`
  default → `[geo] default_location`. Units follow the user's `country`, unless
  `[weather] units` overrides them. Imperial (°F, mph, inches, inHg) is US, BS,
  BZ, KY, PW, FM, MH, LR, and MM. The UK stays °C, mph, mm, and hPa. Everyone
  else is metric.
- Privileges: Any channel member able to speak. Does not require `+W`.
- Replies: `Weather - Austin: 72°F, Partly cloudy, wind 12 mph` for a classic
  reading. A full report adds feels-like and wind direction on that line, then
  a second line such as `  humidity 45%, precip 0.20 in, 29.91 inHg, UV 6, vis 6 mi`
  when those fields are present. A precipitation amount that rounds to zero and
  a UV index of 0 are left off that line. Cloud cover, today's highest rain,
  snow, or thunder chance, and the observation time are added when wttr sends
  them. A failed fetch is `Weather for <place> is unavailable right now.`
- Sources: `src/daemon/server.zig:handleFantasyWeather`, `src/proto/weather_units.zig`, `src/proto/geo_fetch.zig`

## !forecast

- Syntax: `!forecast [location]` (aliases `!fc`, `!fcast`)
- Description: Up to three civil days from the same place and the same cache
  entry as `!weather`. Weekdays are computed from the date (1970-01-01 is Thursday).
- Privileges: Any channel member able to speak. Does not require `+W`.
- Replies: `Forecast - Austin:` followed by lines such as
  `  Mon 19: 77/57°F, Rain, precip 0.06 in`. A day also shows the highest rain,
  snow, or thunder chance (rain wins a tie) and sunrise and sunset when wttr
  sends them. A precipitation total that rounds to zero is omitted. A rich
  report with no days, or a classic row that is not being upgraded, replies
  `No multi-day forecast for <place>.` A failed fetch is
  `Forecast for <place> is unavailable right now.`
- Sources: `src/daemon/server.zig:handleFantasyForecast`

## !setweather

- Syntax: `!setweather <location>` / `!setweather clear` (alias `!sw`)
- Description: Sets (or clears) this channel's default `!weather` location, used
  when a member runs `!weather` with no argument and has no `location` metadata.
  Stored as the channel's `weather_location` metadata.
- Privileges: Channel operator (any op-or-higher tier) or server oper.
- Replies: A confirmation `PRIVMSG` to the channel. Not rate-limited.
- Sources: `src/daemon/server.zig:handleFantasySetWeather`

## !news

- Syntax: `!news` (alias `!n`), `!news sources`, `!news <count>`,
  `!news <source> [count]`, `!news <topic> [count]`, `!news topic <name> [count]`
- Description: Headlines from `src/proto/news_sources.zig`. With no argument the
  source is BBC World and the count is `[geo]`'s serve default (3). A count is
  1..5. A source key wins over a topic spelled the same way. Topics are world,
  us, uk, politics, environment, tech, science, entertainment, business,
  finance, sports, health, and europe. Topic mode shows at most four matching
  sources (one headline each unless a count is given) and warms a few more.
- Privileges: Channel member; **only responds in channels with mode `+W`**
  (news-wire — see [modes.md](../protocol/modes.md)), including `!news sources`.
  Silent otherwise.
- Replies: `News - BBC World:` then `  1. [2h] Title - deck`. A headline with no
  time or deck stays a plain title. Deck text has HTML tags removed, common
  entities decoded, and repeated spaces collapsed. `!news sources` lists keys
  and topics. Unknown grammar replies with the usage line.
- Sources: `src/daemon/server.zig:handleFantasyNews`, `src/proto/news_sources.zig`

## !localnews

- Syntax: `!localnews [CC]`
- Description: Like `!news` but for a country's default feed (ISO 3166-1 code,
  e.g. `JP`, `GB`); defaults to the user's GeoIP `country` metadata. A one-letter
  argument is an unknown country. `!localnews USA` uses the first two letters.
- Privileges: Channel member; requires `+W`.
- Replies: As `!news`, using the country feed.
- Sources: `src/daemon/server.zig:handleFantasyNews`, `src/proto/news_sources.zig` (`country_feeds`)

## Location metadata

On registration the daemon records two IRCv3 METADATA keys on the client's own
nick (`src/daemon/server.zig:setGeoLocation`):

- `location` — GeoIP city (or country), else `[geo] default_location`.
- `country` — GeoIP ISO country code, used for weather unit selection.

Users can override their location at any time with `METADATA SET location <place>`
or per-call with `!weather <place>` / `!forecast <place>`.

## News updater (full feed coverage)

The in-daemon TLS 1.3 stack (Armor) verifies ECDSA and RSA leaf certificates, so
it reaches the great majority of feeds directly; a TLS-1.2-only host is the main
exception. For guaranteed full coverage regardless, set `[geo] news_cache_dir`
and run the bundled key-free updater from cron. The updater uses `curl` with the
system CA bundle to fetch every feed and writes one-headline-per-line files the
daemon reads. Each stored line is a title, or `epoch<TAB>title<TAB>deck`:

```text
*/5 * * * * /path/to/onyx-server/tools/news_update.sh /var/lib/onyx-server/news 5
```

See `tools/news_update.sh` and [config.md](../config.md#geo).
