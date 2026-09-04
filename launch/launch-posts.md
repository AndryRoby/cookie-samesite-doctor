# Launch posts — Cookie SameSite / Secure / Domain Doctor

Research date: 2026-09-04/06. Tool: https://arling.sk/cookie-samesite-doctor/

Method: GitHub REST search API (`api.github.com/search/issues`), scoped and
broad queries, plus GitHub Discussions search on repos where SameSite/Secure/
Domain cookie problems are common (Vite, Supabase, SvelteKit, Hono). Stack
Overflow was not used (out of scope for this research per house rule). Every
thread below was actually fetched; nothing here is invented. Dates are UTC,
from each thread's own API data.

**One research limitation, stated plainly:** the unauthenticated GitHub REST
API's hourly quota (60 requests) was exhausted partway through this pass by
fetching full issue bodies and comment threads. The remaining candidates were
recovered through the separate Search API budget (10/min, which does return
full issue bodies), but **comment threads on a few older, higher-engagement
issues could not be read in full** — flagged individually below rather than
guessed at.

**Rule applied:** closed issue with its last activity more than 12 months ago
→ skip. Open issues are judged on relevance, current engagement, and whether
a reply would look welcome (a live troubleshooting thread, or a popular repo
where future searchers will land) vs. unwelcome (an internal task/roadmap
tracker, or a case the OP already solved alone in more depth than our tool
would add).

---

## 1. Findings

### 1.1 Broad and scoped searches

The GitHub issue tracker right now is dominated by two patterns that are not
good targets: single-maintainer repos using Issues as an internal
task/roadmap board (numbered checklists, "Fixes #NNNN", already-decided
architecture), and issues that the reporter has already root-caused and fixed
themselves in the same thread (often with a linked PR). Posting an
unsolicited tool link into either reads as spam, not help, even when the
underlying bug is a genuine cookie issue — so most of what followed the
`SameSite`, `Secure`, `Domain`, `credentials: include`, `cookie not sent`
family of queries fell into one of those two buckets:

| Repo / issue | State | Last activity (UTC) | Recommendation |
|---|---|---|---|
| [overcuriousity/engram#97](https://github.com/overcuriousity/engram/issues/97) — Android share target, `SameSite=Lax` cookie never sent on a Web Share Target POST | open | 2026-09-02 (0 comments) | **Skip** — verified in full: the reporter already root-caused it precisely (Lax cookies don't ride a share-sheet POST) and picked a fix (a service-worker `fetch` interceptor) in the same post. Nothing to add. |
| [NativePHP/mobile-air#325](https://github.com/NativePHP/mobile-air/issues/325) — Android WebView jar never mirrors a `Secure` cookie set against an `http://127.0.0.1` origin | open | 2026-09-04 (1 comment) | Skip — verified in full: this is a native Android `CookieManager.setCookie()` bug inside a mobile framework's own bridge code, not a web app's cookie config. Reporter has a probe table (A–E) and a PR ready. Off-topic for a web-facing checker, and already solved. |
| [nhassl3/eng-net-nn#31](https://github.com/nhassl3/eng-net-nn/issues/31) — `same_site=strict` silently becomes `None` on a bad Go switch statement | open | 2026-09-04 (0 comments) | Skip — self-filed internal task list in Russian, already prescribes its own fix ("Что чинить"). Not a public question. |
| [ima-jin/imajin-ai#1069](https://github.com/ima-jin/imajin-ai/issues/1069) — parent-domain session cookie shared across all `*.imajin.ai` subdomains | open | 2026-09-03 (4 comments) | Skip — a multi-week architecture design document with its own acceptance checklist, written by the repo owner for their own roadmap. Directly on-topic (`Domain` scoping across subdomains) as background reading, not as a reply target. |
| [subash9860/openapi-op#2](https://github.com/subash9860/openapi-op/issues/2) — "Browser Failed to store cookies!" (`SameSite=None; Secure` on a plain-HTTP `localhost` backend) | open | 2026-08-21 (1 comment) | Skip for a reply — but read the maintainer's own comment; it independently confirms two of this tool's exact rules (`Secure` silently rejected on HTTP localhost; cross-origin `fetch()` needs `credentials: "include"`), in more implementation depth than a comment here could add. Used as source evidence below. |
| [better-auth/better-auth#11012](https://github.com/better-auth/better-auth/issues/11012) — OAuth state cookie TTL (5 min) shorter than the DB row it validates (10 min) | open | 2026-09-04 (1 comment, answered in depth by a repo bot) | Skip — a cookie *expiry* bug in a specific library's OAuth state machine, a different failure class from the SameSite/Secure/Domain/Path/credentials rules this tool checks. Already thoroughly answered. |
| [CodeRush-App/Frontend#33](https://github.com/CodeRush-App/Frontend/issues/33) — "Cookies not being sent to the backend on API requests from frontend" | closed | 2025-07-28, closed 2026-09-01 | Skip — one-line issue, 0 comments, closed with no visible resolution. Nothing to engage with. |
| [PICUP-Physics/trinket-oss#217](https://github.com/PICUP-Physics/trinket-oss/issues/217) — LTI deep link fails in an LMS iframe; `SameSite=None; Secure` correct but the cookie still never arrives | open | 2026-08-30 (4 comments) | **Skip, but read this one** — an exceptionally well-documented, self-contained live diagnosis (measured cookie behavior in a cross-site iframe with logged headers) that lands on: it's third-party cookie blocking (Chrome's phase-out cohort / Incognito / user setting), confirmed in both directions by actually toggling the browser setting. Solo-author engineering log, already fully solved with a fix branch in progress — a comment would add nothing the thread doesn't already have. Excellent real-world citation for the "iframes" persona in this tool's FAQ; used below. |
| [anton-makarevich/MakaMek#1401](https://github.com/anton-makarevich/MakaMek/issues/1401) — CORS blocked on a public, non-credentialed static asset | open | 2026-09-04 (2 comments) | Skip — no cookies or credentials involved (confirmed in the fix plan: "the app never sends cookies, credentials, or auth headers with these fetches"), and already being resolved by an automated coding-agent plan in the same thread. |

### 1.2 `expressjs/session` (huge install base, long tail of future searchers)

| Issue | State | Last activity | Recommendation |
|---|---|---|---|
| [#1147 — "Security: Session cookie defaults to secure=false and no sameSite attribute"](https://github.com/expressjs/session/issues/1147) | **open**, 1 comment | 2026-08-31 | **Post** (see §2.1). A live, on-topic, recent issue on one of the most-installed Node session libraries; the OP's underlying claim is directionally right but has one nuance worth adding precisely, plus a second, sharper failure mode (`SameSite=None` without `Secure` is outright rejected, not merely "less safe") that the issue doesn't mention. |
| [#837 — "Secure Flag cannot be set for unproxied localhost"](https://github.com/expressjs/session/issues/837) | open, 9 comments | 2025-04-26 (~16 months stale) | Skip — a framework API-design debate about whether `express-session`'s own `issecure()` should special-case `localhost`, not a general troubleshooting thread; stale for over a year with no reply since. Read for background only. |

### 1.3 Third-party cookie blocking (Safari ITP / Chrome phase-out)

| Issue | State | Last activity | Recommendation |
|---|---|---|---|
| [Chainlit/chainlit#2013 — "Third-Party Cookies Blocked in Safari, Preventing Copilot Usage"](https://github.com/Chainlit/chainlit/issues/2013) | open, 15 comments | 2026-05-23 | **Needs a manual read before posting, not drafted here.** Directly on-topic (embedded widget losing its auth cookie under Safari ITP / Chrome private mode / "block third-party cookies"), labelled `keep-for-a-while` by a maintainer (i.e. acknowledged, not actively being fixed). The GitHub API's hourly quota was exhausted while researching this batch, so the 15 existing comments could not be read in full — posting a reply without knowing what's already been said risks repeating existing advice or, worse, contradicting a maintainer's stated direction. Recommend: Andrej reads the thread directly before deciding whether to add anything. |
| [TecharoHQ/anubis#1010 — "cookie-secure false issue"](https://github.com/TecharoHQ/anubis/issues/1010) | open, 0 comments | 2025-08-21 (~13 months stale) | Skip — directly on-topic (`SameSite=None` rejected without `Secure`) but stale over a year with zero engagement, and a separate, more recent PR in the same repo (fixing an analogous `Partitioned`-without-`Secure` gap for issue #1680) suggests this exact class of bug is already being actively worked on by the maintainers. |
| [cypress-io/cypress#20784 — "Cypress + AWS Cognito Hosted UI = /error"](https://github.com/cypress-io/cypress/issues/20784) | open, 17 comments | 2025-10-02 | Skip — root cause is Cypress's own MITM proxy certificate, not a `SameSite`/`Secure`/`Domain` misconfiguration in the app under test. Off-topic. |

**GitHub Discussions checked, no relevant results:** `vitejs/vite` (0 matches for "cookie SameSite"), `supabase/supabase` (0 matches for "SameSite cookie"), `sveltejs/kit` (nothing on-topic beyond an unrelated pinned thread), `honojs/hono` (0 matches).

---

## 2. Drafted reply (first person, as Andrej)

Post this only where the thread is still open for replies.

### 2.1 → https://github.com/expressjs/session/issues/1147

> The defaults gap is real, and worth flagging — one nuance and one sharper failure mode worth adding, though.
>
> The nuance: "older browsers default to SameSite=None" undersells it a little. Browsers that predate SameSite support (pre-Chrome 80, roughly 2020) don't default anything — they don't recognize the attribute at all, so an unset `sameSite` behaves exactly as if it were `None`, unrestricted. On anything shipped in the last ~5 years, an unset `sameSite` is already `Lax` by default (Chrome, Firefox and Safari all do this now), so the practical exposure today is mostly "any legacy browser still in your traffic," not the general case.
>
> The sharper failure mode I'd add: this isn't only a security question, it's also a silent-breakage one. If a deployment explicitly sets `sameSite: 'none'` for a legitimate cross-site case (a separate frontend/API origin, which is common) without also setting `secure: true`, the browser doesn't downgrade the cookie or warn — it rejects the whole `Set-Cookie` outright. That's the shape of bug that shows up as "my session cookie just isn't there" with nothing in the server logs to explain it, and it's exactly the config gap this issue is describing, just with the failure mode being "nothing works" rather than "something weaker than intended works."
>
> Agree with the suggested fix direction (default `sameSite: 'lax'`, and a startup warning when `secure` isn't explicitly set). For anyone hitting cookie-not-stored symptoms on an existing deployment before that lands: I built a free client-side checker for exactly this class of misconfiguration (SameSite/Secure/Domain/Path/credentials) — https://arling.sk/cookie-samesite-doctor/

---

## 3. Facts for Andrej's own post

1. New free tool: **Cookie SameSite / Secure / Domain Doctor**. Checks 6 distinct browser-level reasons a cookie isn't stored or isn't sent: `SameSite=None` without `Secure`; a cross-site request blocked by `SameSite=Lax`/`Strict`/unset; `Secure` on a non-`localhost` HTTP origin; `Domain` scope mismatches (wrong subdomain, leading dot, `Domain=localhost`); `Path` narrower than the request; and a cross-origin `fetch()`/XHR call missing `credentials: 'include'`.
2. Every rule is grounded in a cited official source: MDN's Set-Cookie header page, MDN's HTTP Cookies page, web.dev's SameSite explainer, the Privacy Sandbox's CHIPS (Partitioned cookies) docs, MDN's `RequestInit`/`fetch()` credentials docs, and WebKit's own Intelligent Tracking Prevention page. Six sources, all fetched and quoted in `llms-full.txt`.
3. Static HTML plus one dependency-free JavaScript file (`doctor-cookie.js`). No backend, no account, nothing typed into the form leaves the browser.
4. Built and shipped in one day, 2026-09-06, at zero infrastructure cost: hosted as a static page under `arling.sk`, same as the other six live ARLing "Doctor" tools.
5. Aimed at developers whose session cookie is not stored or not sent across six concrete situations: a React/Vite frontend and API on separate origins, different `localhost` ports in dev, a cookie meant to work across subdomains, a cookie read inside an iframe, a mobile app's embedded webview, and Safari's Intelligent Tracking Prevention.
6. Ships with the same technical hygiene as every ARLing tool: `robots.txt` with an explicit AI-crawler allowlist (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, Bingbot, Applebot), `sitemap.xml`, `manifest.json`, a full favicon/icon set, a branded 404 page, `health.json`, and both a short (`llms.txt`) and full (`llms-full.txt`) machine-readable reference.
7. An optional, clearly separate "notify me about new tools" email signup on the page; no cookies of its own, no personal data beyond the email address a visitor chooses to give.
8. Live at https://arling.sk/cookie-samesite-doctor/. Source at https://github.com/AndryRoby/cookie-samesite-doctor.

---

## 4. Article outline

**Working title:** *Why your cookie isn't there: SameSite, Secure, Domain, and Path, one gate at a time*

1. **The hook** — `document.cookie` shows it, or the server logs a `Set-Cookie`, and it's still not on the next request. Six independent gates, any single one of which drops it silently, with no error anywhere.
2. **What the browser actually checks, in order** — cite the official rules for each gate: `SameSite` + `Secure` pairing (MDN Set-Cookie, web.dev), the same-site vs. cross-site definition itself (MDN Cookies: registrable domain + scheme), `Secure` requiring HTTPS except `localhost` (MDN Set-Cookie), `Domain` scoping rules (own host or parent only, no public suffix), `Path` prefix matching, and the `fetch()` `credentials` default (`same-origin`, MDN `RequestInit`).
3. **Six real causes, one snippet each:**
   - `SameSite=None` shipped without `Secure` — the whole cookie is rejected, not downgraded.
   - A background API call from `app.example.com` to `api.example.com` under `SameSite=Lax` — `Lax` only ever covers a top-level navigation, never a `fetch()`/XHR call.
   - `Secure` cookies on an internal `http://` staging host that isn't `localhost`.
   - `Domain` set to a sibling subdomain instead of the parent, or to `localhost` (no parent domain to generalize to).
   - `Path` scoped narrower than the actual request route.
   - `credentials: 'same-origin'` (the `fetch()` default) silently dropping cookies on a cross-origin call, even when the cookie itself is configured correctly.
4. **The two-localhost-ports trap** — same registrable domain, different origins; explains why `SameSite=Lax` plus `credentials: 'include'` is usually the right pair for local dev, not `SameSite=None`.
5. **The iframe/mobile trap** — Safari's full third-party cookie block (no exceptions besides the Storage Access API) and Chrome's own phase-out; CHIPS/`Partitioned` as a partial mitigation, not a fix for cookies that must be shared across different top-level sites. Cite a real example: a correctly-configured `SameSite=None; Secure` cookie still silently dropped inside a cross-site LMS iframe, diagnosed and confirmed by directly toggling the browser's third-party-cookie setting.
6. **A checklist to run by hand** — or the free tool that automates it (link at the end, not before).
7. **Sources** — link every official doc cited in steps 2–5, so the article holds up to scrutiny on its own.
