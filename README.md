# Cookie Doctor (SameSite, Secure, Domain)

A free tool that finds why a session cookie is not stored, or is stored but not sent: `SameSite`, `Secure`, `Domain`, and `Path` attribute mismatches, cross-site request blocking, and missing `fetch()` credentials, with the exact fix for each.

Live: https://arling.sk/cookie-samesite-doctor/

You describe your `Set-Cookie` attributes and the request context (page origin vs. API origin, HTTP vs. HTTPS, same-site vs. cross-site, whether the call is a `fetch()`/XHR request), and the tool reports precisely which browser rule is being enforced and what to change, in your `Set-Cookie` header or in your client's fetch call.

## What it checks

The engine (`doctor-cookie.js`) runs 27 distinct checks against the raw `Set-Cookie` header you paste, the page/API origins, and the request context. Each is grounded in MDN's, web.dev's, WebKit's, or the Privacy Sandbox's own documentation (full citations, quoted, in the file header and in [`llms-full.txt`](llms-full.txt)). Grouped by area:

- **`SameSite` / `Secure` pairing**: `SameSite=None` without `Secure` is rejected outright, not downgraded (`samesite_none_requires_secure`); `Secure` on a plain `http://` origin that isn't `localhost` is refused by the browser (`secure_on_http_origin`); no `SameSite` attribute at all defaults to `Lax` in every current browser, flagged as an informational note so it isn't mistaken for `None` (`samesite_default_lax`).
- **Cross-site / third-party**: a cross-site request (different registrable domain and/or scheme) blocked by `SameSite=Strict`/`Lax` (`samesite_blocks_cross_site`); inside a cross-site iframe, Safari's Intelligent Tracking Prevention can withhold a `SameSite=None` cookie regardless of the attribute (`itp_blocks_third_party`), and other browsers are moving the same direction (`third_party_cookies_deprecation`, with a `chips_suggestion` nudge toward the `Partitioned` attribute).
- **`Domain`**: set to a sibling/unrelated host instead of your own or a parent domain (`domain_mismatch`); a bare top-level label or a known multi-label public suffix like `co.uk`/`github.io` (`domain_public_suffix`); `Domain=localhost`, which has no parent domain to generalize to (`domain_localhost_invalid`); a harmless leading dot, flagged as informational only (`domain_leading_dot_ignored`).
- **`Path`**: narrower than the request path, so the cookie exists but isn't attached (`path_mismatch`); a `Path` value that doesn't start with `/` (`path_attr_not_absolute`).
- **Expiry**: `Max-Age <= 0` or an `Expires` date already in the past both delete the cookie immediately (`max_age_non_positive`, `expires_in_past`); an unparsable `Expires` date (`expires_unparsable`).
- **Cookie-name prefixes**: `__Host-`, `__Secure-`, and `__Http-`/`__Host-Http-` each carry their own hard requirements (`Secure`, no `Domain`, `Path=/`, `HttpOnly`); a violation gets the cookie rejected outright by a user agent that enforces prefixes (`host_prefix_violation`, `secure_prefix_violation`, `http_prefix_violation`).
- **`Partitioned` (CHIPS)**: requires `Secure` or the browser rejects it (`partitioned_requires_secure`); works best paired with `SameSite=None` for browsers that don't yet support partitioning (`partitioned_without_samesite_none`).
- **`fetch()`/XHR credentials**: the default `'same-origin'` mode drops cookies on a cross-origin call regardless of what the cookie's own attributes allow (`fetch_credentials_missing`); once `credentials: 'include'` is set, the API's CORS response must answer with an exact `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`, since a wildcard origin is incompatible with credentials (`cors_wildcard_credentials_risk`); `credentials: 'omit'` on a same-origin call still drops the cookie for no reason (`fetch_credentials_omitted_same_origin`).

## Who it's for

Any developer whose session cookie is not stored, or is stored but not sent: a React/Vite (or similar SPA) front end on one origin calling an API on another, different `localhost` ports in development, cookies meant to work across subdomains, a cookie read inside an iframe, a mobile app's embedded webview, and Safari's Intelligent Tracking Prevention (full third-party cookie blocking, plus a 7-day cap on JavaScript-set first-party cookies without user interaction).

## How it works

Everything runs in your browser. `doctor-cookie.js`, one dependency-free JavaScript file, exports a single pure function, `diagnose(config)`, which the page calls with the raw `Set-Cookie` value and request context you fill in and renders the result as a plain-language report. Nothing about your configuration is sent anywhere; the only network activity is loading the page's own static assets and anonymous Umami analytics events (see Privacy).

```js
import { diagnose } from './doctor-cookie.js';

diagnose({
  setCookie: 'session=abc123; Domain=api.example.com; Path=/; SameSite=Lax; Secure; HttpOnly',
  pageOrigin: 'https://app.example.com',
  apiOrigin: 'https://api.example.com',
  requestCredentials: 'same-origin',
  context: 'fetch-xhr',
});
```

Output (run against the code above):

```json
{
  "status": "fail",
  "summary": "1 blocking issue found. Most urgent: The request is cross-origin (fetch/XHR to a different scheme, host, or port), and requestCredentials is \"same-origin\". fetch()'s default credentials mode is \"same-origin\": a cross-origin call without credentials:'include' neither sends this cookie nor stores one from the response, no matter what SameSite says.",
  "problems": [
    {
      "severity": "high",
      "code": "fetch_credentials_missing",
      "message": "The request is cross-origin (fetch/XHR to a different scheme, host, or port), and requestCredentials is \"same-origin\". fetch()'s default credentials mode is \"same-origin\": a cross-origin call without credentials:'include' neither sends this cookie nor stores one from the response, no matter what SameSite says.",
      "fix": "Add credentials: 'include' to the fetch() call, or xhr.withCredentials = true for XMLHttpRequest."
    },
    {
      "severity": "low",
      "code": "httponly_hides_from_js",
      "message": "HttpOnly is set, so this cookie never shows up in document.cookie or the Cookie Store API. That's expected, not a bug: HttpOnly cookies are still read and sent by the browser on matching requests, JavaScript on the page just can't see them (that's the point: it blocks cookie theft via XSS)."
    },
    {
      "severity": "low",
      "code": "same_site_cross_origin_note",
      "message": "pageOrigin and apiOrigin are same-site but not same-origin (they differ by host (subdomain)). SameSite is satisfied either way, but that's not enough on its own: fetch/XHR still needs credentials:'include' (or xhr.withCredentials = true) to send or receive this cookie across origins, and the API's CORS headers still apply."
    }
  ],
  "fixes": [
    { "title": "Add credentials: 'include' to the fetch/XHR call", "value": "fetch(url, { credentials: 'include' })", "where": "Your front-end request code" }
  ],
  "disclaimer": "Read-only, client-side analysis of the values you entered. \"Site\" is computed with a small curated list of multi-label suffixes (co.uk, github.io, ...), not a full Public Suffix List, so unusual domains may be misjudged. Nothing is verified against your live server or a real browser: confirm in DevTools before shipping. Not affiliated with Google, Apple/Safari, Mozilla, or any browser vendor."
}
```

The catch here is the one this tool exists for: `app.example.com` and `api.example.com` share the same registrable domain (`example.com`), so they're **same-site** and `SameSite=Lax` never blocks the request, exactly as the low-severity note says. The actual, only blocking problem is a layer down: `app.example.com` and `api.example.com` are still different *origins*, and `fetch()`'s default `credentials: 'same-origin'` drops the cookie on any cross-origin call regardless of what `SameSite` allows. Same-site and same-origin are two different questions, and this pair only fails the second one.

## Run locally

No build step, no dependencies.

```bash
git clone https://github.com/AndryRoby/cookie-samesite-doctor.git
cd cookie-samesite-doctor
python -m http.server
# or just open index.html directly in a browser
```

## Tests

```bash
node tests.mjs
```

130 assertions, 130 passed, 0 failed as of this writing.

## Privacy

Everything runs client-side; nothing you type into the form is sent anywhere, ever. Product analytics (page views, "run check" clicked) go to a self-hosted Umami instance with no cookies and no personal data, event name and count only. Joining the "tell me about new tools" email list on the page is entirely optional and separate from using the tool. Full policy: https://arling.sk/privacy/.

## Sources

The rules this tool checks are drawn from:

- MDN: [Set-Cookie header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- MDN: [HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- web.dev: [SameSite cookies explained](https://web.dev/articles/samesite-cookies-explained)
- Privacy Sandbox: [CHIPS (Partitioned cookies)](https://privacysandbox.google.com/3pcd/chips)
- MDN: [RequestInit / fetch() `credentials`](https://developer.mozilla.org/en-US/docs/Web/API/RequestInit)
- MDN: [CORS error: credentials with a wildcard origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials)
- WebKit: [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention/)
- WebKit: [Full Third-Party Cookie Blocking and More](https://webkit.org/tracking-prevention/)

## Report a problem

Found a cookie-storage cause this tool doesn't catch, or a check that flags something that's actually fine? Open an issue: https://github.com/AndryRoby/cookie-samesite-doctor/issues, or write to andrej@arling.sk. Please redact anything sensitive (real domains, cookie values) before posting; issues are public.

## License

All rights reserved, see [LICENSE-NOTICE.md](LICENSE-NOTICE.md). Reading the source and learning from it is fine; deploying your own copy of it as a competing product is not.

---

ARLing s. r. o., Bratislava, Slovakia. andrej@arling.sk

Hub (more free tools): https://arling.sk/

Sibling tools:
- Google OAuth redirect_uri_mismatch: https://arling.sk/google-oauth-redirect-doctor/
- Supabase Auth on the web (Next.js / Vite / SvelteKit): https://arling.sk/supabase-redirect-doctor/
- Supabase Auth on Flutter: https://arling.sk/flutter-supabase-doctor/
- Stripe webhook signature failures: https://arling.sk/stripe-webhook-doctor/
- Expo Universal Links / App Links: https://arling.sk/expo-universal-links-doctor/
- SEPA pain.001 for Slovak banks: https://arling.sk/sepa-pain001-doctor/
- BookApp: https://arling.sk/bookapp/
