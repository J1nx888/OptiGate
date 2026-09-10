# Crunchyroll per-series whitelist — analysis (2026-09-10)

Distilled from a live interception-window trace on the one `bump_enabled`
device (a family tablet, Chrome/Android). **The raw trace (Squid
`access.log`/`cache.log` slices, AdGuard query log, CMS API dumps) was
deliberately NOT committed** — it contained full request URLs with
time-limited Cloudflare challenge tokens, an account UUID, and a minor's
browsing record. Only these findings are kept. Re-capture from the box if
the redesign needs raw data again.

`matthew`'s approved shows at capture time (`user_shows`):
- SPY x FAMILY `G4PH0WXVJ`
- Dr. STONE `GYEXQKJG6`

Test series that must be BLOCKED: **Black Clover `GRE50KV36`** (not approved).

## TL;DR — three stacked problems, in dependency order

1. **The bump itself fails on this device.** After a full browser restart,
   Squid cannot complete the TLS bump handshake with Chrome for
   `www.crunchyroll.com` — `cache.log` shows repeated
   `ERROR: failure while accepting a TLS connection on conn… local=104.18.34.202`
   and every `CONNECT 104.18.34.202:443` in `access.log` is `NONE_NONE/000`
   (client aborts immediately). **Zero Crunchyroll HTTP requests were
   decrypted during the entire 4-minute capture.** `authz_helper` logged
   **0** crunchyroll decisions. Yet Black Clover played — so playback
   traffic reaches Crunchyroll over a path OptiGate never inspected
   (spliced CDN the browser tolerates, and/or SPA-cached metadata).
   Likely cause: Chrome on Android 7+ ignores user-store CA certs for its
   own connections unless an app opts in — so the OptiGate CA is not
   trusted by this browser for MITM. (An earlier retest at ~16:51 DID
   briefly bump `www.crunchyroll.com` successfully — so trust state is
   inconsistent / context-dependent; needs checking what installed the CA
   and where.)

2. **`host_verify_strict` (Squid default `on`) breaks spliced multi-IP
   CDN traffic.** `cache.log` is full of
   `SECURITY ALERT: Host header forgery detected … (local IP does not
   match any domain IP)` for `clients2.google.com`, `clients4.google.com`,
   `encrypted-tbn0.gstatic.com`, `lh3.googleusercontent.com`,
   `waa-pa.clients6.google.com`, and `vod-*.crunchyrollcdn.com`. The
   client's cached DNS answer ≠ Squid's fresh re-resolution, so Squid
   kills the connection (`NONE_NONE/409`). This degrades the WHOLE
   device's browsing once all its 443 traffic is forced through Squid
   (see #3), and specifically breaks Crunchyroll's own video CDN.
   Fix: `host_verify_strict off` in `proxy/squid.conf.template` — the
   standard setting for intercept mode. (RoadMap finding #6.)

3. **Forcing ALL of a device's HTTPS through Squid is too blunt.** `.30`
   is a blanket `bump_v4` member, so nftables redirects every tcp/443 to
   Squid and (as of this session) drops its udp/443 QUIC. Combined with
   #1 and #2, the tablet's general browsing (Google services, Datadog,
   Bark, analytics) became broadly unreliable — a stream of
   `NONE_NONE/000` / `NONE_NONE/409` / `TCP_TUNNEL/500`. The device needs
   **selective bumping**: redirect only the Crunchyroll-family domains'
   traffic to Squid, splice/pass everything else. This is a new
   `phase3/nftables-manager` capability (destination-IP-scoped redirect
   for a per-domain bump list), not a config tweak.

**Net:** the classifier redesign (below) is necessary but not sufficient.
Order of operations for the fix: (a) make the CR bump reliable on the
device — CA trust and/or selective bump; (b) `host_verify_strict off`;
(c) redesign the classifier + path allowlist; (d) re-verify live.

## Sequence timeline (all UTC, 2026-09-10)

| Step | Window | Notes |
|---|---|---|
| home (`crunchyroll.com`) | 17:07:01–17:07:22 | no bumped CR requests; CF `104.18.34.202` → `NONE_NONE/000` |
| Dr. STONE series page | 17:07:22–17:07:54 | same |
| Dr. STONE play (~20s) | 17:07:54–17:08:32 | played; no CR request through Squid |
| Black Clover series page | 17:08:32–17:08:51 | same |
| Black Clover play (~20s) | 17:08:51–17:09:25 | **played** (should be blocked); no CR request through Squid |

## Current Crunchyroll config (prod DB, at capture)

`domains`:
- `crunchyroll\.com` (id 27) — `mode=bump`, `kind=crunchyroll`, `is_global=1`
- `gccrunchyroll\.com` (id 25) — `mode=trusted`
- `crunchyrollcdn\.com` (id 26) — `mode=trusted`
- `bitmovin\.com` (id 16) — `mode=splice`, `is_global=1`  ← DRM, already spliced

`domain_paths` for id 27 (the allowlist — **the blanket rules are the leak**):
```
^/$  ^/\?  ^/login  ^/auth  ^/api  ^/callback  ^/discover  ^/news
^/simulcastcalendar  ^/assets  ^/assets/  ^/browser  ^/build/  ^/config
^/config-delta/  ^/cdn  ^/css/  ^/js/  ^/images/  ^/i18n/  ^/skip-events/
^/accounts/v[0-9]+/  ^/f/v[0-9]+/  ^/subs/v[0-9]+/  ^/personalization/v[0-9]+/
^/playback/v[0-9]+/            ← blanket: any playback call allowed
^/content/v[0-9]+/             ← blanket: the ENTIRE modern API allowed
^/content/v[0-9]+/.*playheads
^/v1/track  ^/v1/p$  /v1/  /content-reviews/
\.(css|js|png|jpg|jpeg|gif|svg|webp|json|woff2?)$
```

## Modern Crunchyroll web API — observed shapes

From the Squid trace (the ~16:51 retest when the bump briefly worked) and
a direct CMS API probe with a fresh anonymous token:

| Method + path | Purpose | Carries series/episode id? |
|---|---|---|
| `POST /auth/v1/token` | anon/web token | no |
| `GET /content/v2/discover/browse?…` | catalogue browse | no |
| `GET /content/v2/discover/up_next/<SERIES_ID>?…` | **"continue / next episode" for a series** | **YES — series id in path** |
| `GET /content/v2/cms/objects/<ID[,ID…]>?…` | batch object metadata (series / season / episode) | **YES — ids in path** |
| `GET /content/v2/discover/<accountUuid>/history?…` | watch history | no (uuid only) |
| `GET /content/v2/<accountUuid>/watchlist?…` | watchlist | no |
| `GET /content/v2/discover/<accountUuid>/…` | personalised rows | no |
| `GET /f/v1/home?…` | homepage feed | no |
| `GET /personalization/v2/personalization?…` | recs | no |
| `GET /accounts/v1/me` | account | no |
| `GET /subs/v2/products/<sku>` | subscription | no |
| `GET /playback/v{1,2,3}/<MEDIA_ID>/web/<platform>/play` | **THE playback / manifest+DRM call** | **YES — media id in path** |

### `/content/v2/cms/objects/<id>` response shape (live probe, Dr. STONE `GYEXQKJG6`)

A **series** object:
```
id: GYEXQKJG6   type: "series"   title: "Dr. STONE"
top-level keys: channel_id, description, external_id, id, images,
  language_presentation, linked_resource_key, localized_images, rating,
  series_metadata, slug, slug_title, title, type
```
→ a `series` object has **`series_metadata`** (not `episode_metadata`), and
its own `id` IS the series id. `cr_api.series_id_of()` already handles
`type == "series"` → returns `id`. Good.

### `/content/v2/discover/up_next/<seriesId>` response shape (live probe)

```
panel id: G14U4E83J   type: "episode"
panel.episode_metadata.series_id: GYEXQKJG6
panel.episode_metadata.season_id: GYX0C4DGQ
```
→ the panel is an **episode** with `episode_metadata.series_id`. And the
**series id is already in the request URL path** — so this endpoint can be
gated with a pure path match, no API round-trip. Note the panel `id`
(`G14U4E83J`) is the **media id** the playback call below uses.

### `/playback/v{1,2,3}/<mediaId>/web/<platform>/play` (direct probe, 2026-09-10)

Confirmed by probe: every variant
(`/playback/v3/<id>/web/firefox/play`, `/playback/v2/<id>/web/firefox/play`,
`/playback/v1/<id>/web/firefox/play`, `…/console/switch/play`, with/without
`?queue=false`) returns a real playback-service JSON body
(`{"error": "the current subscription does not have access to this
content"}` / `{"error": …}` for the anon token — a 200 for a real
subscriber returns the DASH/HLS manifest url + DRM `token` + `versions`).
So the stable shape is:

```
GET https://www.crunchyroll.com/playback/v<N>/<MEDIA_ID>/web/<platform>/play
```

- `<MEDIA_ID>` = the episode/movie object id (same id `up_next` returns and
  `cms/objects` resolves).
- `<platform>` observed: `web/firefox`, `web/chrome`, also `console/switch`.
- Older `/content/v2/cms/videos/<id>/streams` now 404s; `streams_link` /
  `__links__` have been removed from the `cms/objects` episode object.

This is the unambiguous enforcement point: resolve `<MEDIA_ID>` → parent
series → `matching.user_has_show()`.

## Redesign direction (for the dedicated session)

Prereqs (must land first, see TL;DR): CR bump reliable on the device +
`host_verify_strict off`.

Then, in `common/cr_urls.py` + `proxy/authz_helper.py` +
`defaults/seed_defaults.py` + a live-DB `domain_paths` migration:

1. **New classifier shape `UP_NEXT`** — regex
   `^https://www\.crunchyroll\.com/content/v\d+/discover/up_next/([A-Za-z0-9]+)`
   → series id in group 1 → check `matching.user_has_show(user_id, id)`
   directly (no resolver call).
2. **`CMS_OBJECTS` must stop being blanket-allow.** Today
   `_decide_crunchyroll` returns `True` for it ("metadata only, matches
   v1"). Change: resolve every id via `series_resolve.resolve_series_ids`
   (which itself calls `/content/v2/cms/objects/` — guard against the
   helper's own call re-entering by keeping the helper's `_OPENER` proxy
   bypass, already in place) and check each. Allow a `series`-type id
   whose own id is approved; deny if any id resolves to a non-approved
   series. Careful: the browse/watchlist/home rows also batch-fetch
   objects for cards the user is only *looking at*, not playing — decide
   whether "viewing a card for a non-approved show" should be denied
   (breaks the catalogue UI) or allowed (only gate the play path).
   Leaning: gate `up_next` + the playback/streams call; leave plain
   `cms/objects` browse fetches allowed.
3. **New classifier shape `PLAYBACK`** — regex
   `^https://www\.crunchyroll\.com/playback/v\d+/([A-Za-z0-9]+)/`
   → media id in group 1 → `series_resolve.resolve_series_ids([id])` →
   `matching.user_has_show()`. This is the hard gate: no manifest, no
   video. Fail closed on resolution failure (same as v1's contract).
4. **Drop the blanket `^/content/v[0-9]+/` and `^/playback/v[0-9]+/`
   path rules** for domain 27. Replace with narrow allows for the
   genuinely id-free endpoints (`/content/v2/discover/browse`,
   `/content/v2/discover/*/history`, `/content/v2/*/watchlist`,
   `/content/v2/discover/*/…` personalised rows, `/f/v1/`,
   `/personalization/v2/`, `/subs/`, `/accounts/`, `/auth/`,
   `/config-delta/`, `/metal/v1/`, static). Everything else on
   `crunchyroll.com` → deny-by-default, so an unrecognised playback shape
   fails closed.
5. Tests in `tests/test_cr_urls.py` + `tests/test_helpers_protocol.py`
   against every shape above (`up_next/<series>`, `cms/objects/<ids>`,
   `playback/vN/<media>/web/<platform>/play`, and the id-free browse
   endpoints), plus the "browse a non-approved show's card without
   playing" case whichever way #2 is decided.

**Coverage note:** with `up_next` + `cms/objects` + `playback` all gated
and the blanket path rules gone, a non-approved series has no path to a
manifest: the player can't get `up_next` data, can't fetch the episode
object, and the `playback` call itself is denied. The `playback` gate
alone is sufficient for correctness; the other two are defence-in-depth
+ a cleaner UX (deny at series-open, not at press-play).
