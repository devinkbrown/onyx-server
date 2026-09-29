# Weather and news fantasy bot

*Server-answered in-channel `!` commands for weather and news, with no pseudo-clients.*

Mode +B and WHOIS 335 mark a bot. `announce_board` stays loaded and off the WHOIS and fantasy paths. `BOTGRANT` records the account in `bot_registry` so the grant counts as a bot, and that registry does not answer channel `!` commands. The in-channel commands are `!weather` and `!news`.

Onyx Server answers a small set of in-channel `!` fantasy commands directly from the
server, with no pseudo-clients (`src/daemon/server.zig:11150`, `handleFantasy`).
The triggering message reaches the channel normally; the server posts the answer
as a `NOTICE` sourced from this node's `server_name` and relays it once across the
mesh, so members on every node see a single reply from the replying server
(`src/daemon/server.zig:fantasyReply`).

All data sources are key-free: weather comes from `wttr.in` over plain HTTP, and
news comes from the RSS feeds bundled in `src/proto/news_sources.zig`. Fetching
runs on a dedicated background thread (`src/daemon/geo_services.zig`) so the
reactor never blocks; the first request for a new location or feed replies
"fetching… try again in a moment", then serves from a TTL cache. Enable the bot
with `[geo] enabled = true` (see [config.md](../config.md#geo)).

## !weather

- Syntax: `!weather [location]` (aliases `!w`, `!wx`)
- Description: Reports current weather. Location resolution order: the command
  argument → the user's `location` metadata (set on connect from GeoIP) → the
  channel's `!setweather` default → `[geo] default_location`. The reading is
  localized to the user's `country` metadata — °F/mph for US/LR/MM, else °C/km·h.
- Privileges: Any channel member able to speak.
- Replies: A server `NOTICE` to the channel, e.g.
  `Weather — Austin: 72°F, Partly cloudy, wind 12 mph`, or a "fetching" notice on
  a cache miss.
- Sources: `src/daemon/server.zig:handleFantasyWeather`, `src/proto/weather_units.zig`

## !setweather

- Syntax: `!setweather <location>` / `!setweather clear` (alias `!sw`)
- Description: Sets (or clears) this channel's default `!weather` location, used
  when a member runs `!weather` with no argument and has no `location` metadata.
  Stored as the channel's `weather_location` metadata.
- Privileges: Channel operator (any op-or-higher tier) or server oper.
- Replies: A confirmation `NOTICE` to the channel. Not rate-limited.
- Sources: `src/daemon/server.zig:handleFantasySetWeather`

## !news

- Syntax: `!news [source]` (alias `!n`)
- Description: Posts the latest headlines for a named source (`bbc`, `npr`,
  `guardian`, … from `src/proto/news_sources.zig`), defaulting to BBC World.
- Privileges: Channel member; **only responds in channels with mode `+W`**
  (news-wire — see [modes.md](../protocol/modes.md)). Silent otherwise.
- Replies: A `News — <source>:` header followed by numbered headline `NOTICE`s.
- Sources: `src/daemon/server.zig:handleFantasyNews`

## !localnews

- Syntax: `!localnews [CC]`
- Description: Like `!news` but for a country's default feed (ISO 3166-1 code,
  e.g. `JP`, `GB`); defaults to the user's GeoIP `country` metadata.
- Privileges: Channel member; requires `+W`.
- Replies: As `!news`, using the country feed.
- Sources: `src/daemon/server.zig:handleFantasyNews`, `src/proto/news_sources.zig` (`country_feeds`)

## Location metadata

On registration the daemon records two IRCv3 METADATA keys on the client's own
nick (`src/daemon/server.zig:setGeoLocation`):

- `location` — GeoIP city (or country), else `[geo] default_location`.
- `country` — GeoIP ISO country code, used for weather unit selection.

Users can override their location at any time with `METADATA SET location <place>`
or per-call with `!weather <place>`.

## News updater (full feed coverage)

The in-daemon TLS 1.3 stack (Armor) verifies ECDSA and RSA leaf certificates, so
it reaches the great majority of feeds directly; a TLS-1.2-only host is the main
exception. For guaranteed full coverage regardless, set `[geo] news_cache_dir`
and run the bundled key-free updater from cron. The updater uses `curl` with the
system CA bundle to fetch every feed and writes one-headline-per-line files the
daemon reads:

```text
*/5 * * * * /path/to/onyx-server/tools/news_update.sh /var/lib/onyx-server/news 10
```

See `tools/news_update.sh` and [config.md](../config.md#geo).
