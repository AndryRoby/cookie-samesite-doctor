// doctor-cookie.js: Cookie Doctor (SameSite, Secure, Domain) core logic.
//
// Pure, deterministic, 100% client-side: given the raw Set-Cookie header your
// server sent, the origin of the page (or the parent frame, if this is an
// iframe), the origin that actually sent Set-Cookie, the fetch/XHR
// credentials mode, the request context (top-level navigation, iframe, or
// fetch/XHR), the browser, and whether an HTTPS-terminating reverse proxy
// sits in front of an http-looking origin, this works out exactly which
// attribute (or which piece of client code) is the reason a session cookie
// is never stored or never sent, and what to change.
//
// Nothing in this file makes a network request. It only reads the object you
// pass to diagnose().
//
// Rules implemented here are sourced from:
//  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
//      (SameSite=None: "The Secure attribute must also be set when using
//      this value"; Secure: "sent to the server only when a request is made
//      with the https: scheme (except on localhost)"; Domain: "must be the
//      domain of the server that sends the Set-Cookie response header, or a
//      parent domain of that server's domain... cannot be a public suffix
//      such as com, co.uk, or github.io"; leading dots in Domain "are
//      ignored"; Path matching: "/docs" matches "/docs", "/docs/",
//      "/docs/Web/" but not "/docsets"; Max-Age: "a zero or negative number
//      will expire the cookie immediately"; __Secure- "must be set with the
//      Secure attribute"; __Host- "must be set with the Secure attribute...
//      must not have a Domain attribute specified, and the Path attribute
//      must be set to /"; __Http- / __Host-Http- add the same HttpOnly
//      requirement; HttpOnly: "still be sent with JavaScript-initiated
//      requests... just [not visible via] Document.cookie"; some browsers
//      default missing SameSite to Lax)
//  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
//      ("site" = the registrable domain [+ scheme]; SameSite=Strict "only
//      sent... from the cookie's origin site"; SameSite=Lax "sends the
//      cookie when the user navigates to the cookie's origin site" but not
//      on embedded subrequests; SameSite=None "sent on both originating and
//      cross-site requests" and "requires a secure context"; Domain "can
//      only set... to its own domain or a parent domain")
//  - https://web.dev/articles/samesite-cookies-explained
//      ("site" = "the combination of the domain suffix and the part of the
//      domain just before it"; "cookies without a SameSite attribute are
//      treated as SameSite=Lax"; "SameSite=None must also specify Secure")
//  - https://privacysandbox.google.com/3pcd/chips (CHIPS / Partitioned)
//      ("Partitioned cookies must be set with Secure"; "It is recommended to
//      use the __Host- prefix when setting partitioned cookies"; partition
//      key = "the site... of the top-level URL the browser was visiting")
//  - https://webkit.org/blog/7675/intelligent-tracking-prevention/
//      (Safari's ITP purges or withholds third-party website data/cookies
//      for a domain the user has not interacted with directly, independent
//      of any SameSite value the cookie carries)
//  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS/Errors/CORSNotSupportingCredentials
//      ("the server is configured using the wildcard ("*") as the value of
//      Access-Control-Allow-Origin, which doesn't allow the use of
//      credentials"; fix: an exact origin plus Access-Control-Allow-Credentials: true)
//  - https://developer.mozilla.org/en-US/docs/Web/API/RequestInit
//      (fetch credentials: "omit" = never send/receive; "same-origin"
//      [default] = only for same-origin requests; "include" = always, but
//      cross-origin requires the server to agree via CORS and "* is not
//      allowed" as Access-Control-Allow-Origin alongside credentials)
//
// Works as an ES module (import { diagnose, expectedValues } from
// './doctor-cookie.js') and, when loaded with <script type="module">, also
// publishes window.CookieDoctor = { diagnose, expectedValues } for
// console/debug use.

// ───────────────────────── small string / host helpers ─────────────────────────

function safeStr(v) {
  return typeof v === 'string' ? v : '';
}

function isIpHost(host) {
  const h = safeStr(host);
  if (!h) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(':')) return true; // crude IPv6 detection
  return false;
}

function isLoopbackHost(host) {
  const h = safeStr(host).toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '[::1]' || /^127(\.\d{1,3}){3}$/.test(h);
}

// A small, curated set of multi-label public suffixes (not a full Public
// Suffix List, which would need a network fetch or a large bundled file).
// Good enough to catch the common real-world cases: co.uk-style ccTLDs and
// the "*.github.io"-style hosting platforms developers actually paste here.
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp',
  'co.nz', 'org.nz', 'net.nz', 'govt.nz',
  'co.za', 'org.za', 'net.za',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'com.br', 'net.br',
  'co.in', 'net.in', 'org.in', 'firm.in', 'gen.in', 'ind.in',
  'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw',
  'co.kr', 'or.kr',
  'github.io', 'gitlab.io', 'pages.dev', 'vercel.app', 'netlify.app',
  'herokuapp.com', 'web.app', 'firebaseapp.com', 'workers.dev',
  'fly.dev', 'onrender.com', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com',
  'repl.co', 'glitch.me', 'azurewebsites.net', 'ondigitalocean.app',
]);

// registrable domain: loopback/IP hosts are their own "site"; a known
// multi-label suffix (co.uk, github.io, ...) pulls in one extra label;
// otherwise the last two labels. This is a heuristic, not a full Public
// Suffix List lookup — see the tool's disclaimer.
function registrableDomain(hostname) {
  const h = safeStr(hostname).toLowerCase();
  if (!h) return h;
  if (isLoopbackHost(h) || isIpHost(h)) return h;
  const labels = h.split('.');
  if (labels.length <= 2) return h;
  const last2 = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(last2)) return labels.slice(-3).join('.');
  return last2;
}

function domainCoversHost(domainAttr, apiHostname) {
  const normalized = safeStr(domainAttr).trim().replace(/^\./, '').toLowerCase();
  const host = safeStr(apiHostname).toLowerCase();
  if (!normalized || !host) return false;
  if (normalized === host) return true;
  return host.endsWith('.' + normalized);
}

// MDN: "for Path=/docs, the request paths /docs, /docs/, /docs/Web/, and
// /docs/Web/HTTP will all match. /, /docsets, /fr/docs will not match."
function pathMatches(cookiePath, requestPath) {
  let c = safeStr(cookiePath) || '/';
  if (!c.startsWith('/')) c = '/' + c;
  if (c.length > 1 && c.endsWith('/')) c = c.slice(0, -1);
  const r = safeStr(requestPath) || '/';
  if (r === c) return true;
  const prefix = c === '/' ? '/' : c + '/';
  return r.startsWith(prefix);
}

// ───────────────────────── origin parsing + "site" ─────────────────────────

function parseOrigin(raw) {
  const s = safeStr(raw).trim();
  if (!s) return { provided: false, valid: false, raw: s };
  let u = null;
  try {
    u = new URL(s);
  } catch (e) {
    try {
      u = new URL('https://' + s);
    } catch (e2) {
      u = null;
    }
  }
  if (!u || !/^https?:$/.test(u.protocol)) return { provided: true, valid: false, raw: s };
  return {
    provided: true,
    valid: true,
    raw: s,
    scheme: u.protocol.replace(/:$/, '').toLowerCase(),
    hostname: u.hostname.toLowerCase(),
    port: u.port || '',
    host: u.host.toLowerCase(),
    origin: u.origin.toLowerCase(),
    path: u.pathname || '/',
  };
}

function siteOf(o) {
  if (!o || !o.valid) return null;
  return `${o.scheme}://${registrableDomain(o.hostname)}`;
}

// Decides whether SameSite lets this cookie ride along on a cross-site
// request, given the request's context.
function sameSiteVerdict(effectiveSameSite, isCrossSite, context) {
  if (!isCrossSite) return { sent: true, reason: 'same-site request: SameSite does not restrict it' };
  if (effectiveSameSite === 'None') return { sent: true, reason: 'SameSite=None allows cross-site sending' };
  if (effectiveSameSite === 'Strict') {
    return { sent: false, reason: 'SameSite=Strict blocks every cross-site request, including a top-level link or redirect' };
  }
  // Lax (explicit or default)
  if (context === 'top-level') {
    return { sent: true, reason: 'SameSite=Lax still allows a cross-site top-level navigation (a clicked link or a 3xx redirect)' };
  }
  return { sent: false, reason: 'SameSite=Lax blocks cross-site subrequests (fetch, XHR, iframes): only a top-level navigation is exempt' };
}

// ───────────────────────── Set-Cookie parsing ─────────────────────────

/**
 * Parses one raw Set-Cookie header value into its attributes. Tolerant of a
 * leading "Set-Cookie:" / "set-cookie:" label (as pasted straight out of
 * DevTools' Headers panel) and of several stacked lines (only the first is
 * analyzed; the rest are counted in extraLines).
 */
function parseSetCookie(raw) {
  const lines = safeStr(raw).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) {
    return { provided: false, invalid: false, extraLines: 0 };
  }
  const first = lines[0].replace(/^set-cookie\s*:\s*/i, '');
  const parts = first.split(';').map((p) => p.trim()).filter((p) => p.length > 0);
  if (parts.length === 0) {
    return { provided: true, invalid: true, invalidReason: 'empty header', raw: first, extraLines: lines.length - 1 };
  }

  const nvPart = parts[0];
  const eqIdx = nvPart.indexOf('=');
  const name = (eqIdx === -1 ? nvPart : nvPart.slice(0, eqIdx)).trim();
  const value = eqIdx === -1 ? '' : nvPart.slice(eqIdx + 1).trim();

  const attrs = {
    provided: true,
    raw: first,
    name,
    value,
    hasDomain: false, domain: '',
    hasPath: false, path: '',
    hasExpires: false, expiresRaw: '', expiresDate: null, expiresValid: false,
    hasMaxAge: false, maxAgeRaw: '', maxAge: null,
    secure: false,
    httpOnly: false,
    hasSameSite: false, sameSite: null, sameSiteRaw: '',
    partitioned: false,
    unknownAttrs: [],
    extraLines: lines.length - 1,
    invalid: !name,
    invalidReason: !name ? 'no cookie name found before "="' : null,
    prefixKind: null,
  };

  for (let i = 1; i < parts.length; i++) {
    const p = parts[i];
    const eq = p.indexOf('=');
    const key = (eq === -1 ? p : p.slice(0, eq)).trim();
    const keyLower = key.toLowerCase();
    const val = eq === -1 ? '' : p.slice(eq + 1).trim();
    switch (keyLower) {
      case 'domain':
        attrs.hasDomain = true;
        attrs.domain = val;
        break;
      case 'path':
        attrs.hasPath = true;
        attrs.path = val;
        break;
      case 'expires': {
        attrs.hasExpires = true;
        attrs.expiresRaw = val;
        const d = new Date(val);
        attrs.expiresValid = !isNaN(d.getTime());
        attrs.expiresDate = attrs.expiresValid ? d : null;
        break;
      }
      case 'max-age': {
        attrs.hasMaxAge = true;
        attrs.maxAgeRaw = val;
        const n = Number(val);
        attrs.maxAge = Number.isFinite(n) ? n : null;
        break;
      }
      case 'secure':
        attrs.secure = true;
        break;
      case 'httponly':
        attrs.httpOnly = true;
        break;
      case 'samesite': {
        attrs.hasSameSite = true;
        attrs.sameSiteRaw = val;
        const norm = val.trim().toLowerCase();
        attrs.sameSite = norm === 'strict' ? 'Strict' : norm === 'lax' ? 'Lax' : norm === 'none' ? 'None' : null;
        break;
      }
      case 'partitioned':
        attrs.partitioned = true;
        break;
      default:
        if (key) attrs.unknownAttrs.push(key);
    }
  }

  if (name.startsWith('__Host-Http-')) attrs.prefixKind = '__Host-Http-';
  else if (name.startsWith('__Host-')) attrs.prefixKind = '__Host-';
  else if (name.startsWith('__Secure-')) attrs.prefixKind = '__Secure-';
  else if (name.startsWith('__Http-')) attrs.prefixKind = '__Http-';

  return attrs;
}

function serializeCookie(a) {
  let out = `${a.name}=${a.value}`;
  if (a.hasDomain) out += `; Domain=${a.domain}`;
  out += `; Path=${a.hasPath && a.path ? a.path : '/'}`;
  if (a.hasExpires) out += `; Expires=${a.expiresRaw}`;
  if (a.hasMaxAge) out += `; Max-Age=${a.maxAgeRaw}`;
  if (a.secure) out += '; Secure';
  if (a.httpOnly) out += '; HttpOnly';
  if (a.sameSite) out += `; SameSite=${a.sameSite}`;
  if (a.partitioned) out += '; Partitioned';
  return out;
}

// ───────────────────────── expected-value builder ─────────────────────────

function computeExpected(config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const cookie = parseSetCookie(cfg.setCookie);
  const page = parseOrigin(cfg.pageOrigin);
  const api = parseOrigin(cfg.apiOrigin);
  const requestCredentials = ['omit', 'same-origin', 'include'].includes(cfg.requestCredentials) ? cfg.requestCredentials : '';
  const context = ['top-level', 'iframe', 'fetch-xhr'].includes(cfg.context) ? cfg.context : '';
  const browser = ['chrome', 'safari', 'firefox'].includes(cfg.browser) ? cfg.browser : '';
  const proxyBehindHttps = cfg.proxyBehindHttps === true ? true : cfg.proxyBehindHttps === false ? false : null;

  const pageSite = siteOf(page);
  const apiSite = siteOf(api);
  const isCrossOrigin = page.valid && api.valid ? page.origin !== api.origin : null;
  const isCrossSite = pageSite && apiSite ? pageSite !== apiSite : null;
  const effectiveSameSite = cookie.provided && !cookie.invalid ? cookie.sameSite || 'Lax' : null;

  let correctedSetCookieLine = null;
  if (cookie.provided && !cookie.invalid) {
    const fixed = Object.assign({}, cookie);
    let changed = false;

    if (fixed.sameSite === 'None' && !fixed.secure) {
      fixed.secure = true;
      changed = true;
    }
    if (fixed.prefixKind === '__Host-' || fixed.prefixKind === '__Host-Http-') {
      if (!fixed.secure) { fixed.secure = true; changed = true; }
      if (fixed.hasDomain) { fixed.hasDomain = false; fixed.domain = ''; changed = true; }
      if (!fixed.hasPath || fixed.path !== '/') { fixed.hasPath = true; fixed.path = '/'; changed = true; }
    }
    if (fixed.prefixKind === '__Secure-' && !fixed.secure) {
      fixed.secure = true;
      changed = true;
    }
    if (fixed.prefixKind === '__Http-' || fixed.prefixKind === '__Host-Http-') {
      if (!fixed.secure) { fixed.secure = true; changed = true; }
      if (!fixed.httpOnly) { fixed.httpOnly = true; changed = true; }
    }
    if (fixed.partitioned && !fixed.secure) {
      fixed.secure = true;
      changed = true;
    }
    if (fixed.hasDomain) {
      const normalized = fixed.domain.trim().replace(/^\./, '').toLowerCase();
      const badDomain =
        normalized === 'localhost' ||
        !normalized.includes('.') ||
        MULTI_LABEL_SUFFIXES.has(normalized) ||
        (api.valid && !domainCoversHost(fixed.domain, api.hostname));
      if (badDomain) {
        fixed.hasDomain = false;
        fixed.domain = '';
        changed = true;
      }
    }
    if (fixed.hasPath && fixed.path && !fixed.path.startsWith('/')) {
      fixed.path = '/' + fixed.path;
      changed = true;
    }

    if (changed) correctedSetCookieLine = serializeCookie(fixed);
  }

  return {
    cookie, page, api,
    pageSite, apiSite,
    isCrossOrigin, isCrossSite,
    effectiveSameSite,
    requestCredentials, context, browser, proxyBehindHttps,
    correctedSetCookieLine,
  };
}

// ───────────────────────── diagnose() ─────────────────────────

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

function sortProblems(problems) {
  return problems
    .map((p, idx) => ({ p, idx }))
    .sort((a, b) => (SEVERITY_ORDER[a.p.severity] - SEVERITY_ORDER[b.p.severity]) || (a.idx - b.idx))
    .map((x) => x.p);
}

function pushProblem(problems, { severity, code, message, path, value, fix }) {
  problems.push({ severity, code, message, path: path || null, value: value == null ? null : value, fix: fix || null, where: path || null });
}

/**
 * @param {object} config
 * @param {string} [config.setCookie] raw Set-Cookie header value
 * @param {string} [config.pageOrigin] the tab's (or parent frame's) origin
 * @param {string} [config.apiOrigin] the origin that sent Set-Cookie
 * @param {'omit'|'same-origin'|'include'|''} [config.requestCredentials]
 * @param {'top-level'|'iframe'|'fetch-xhr'|''} [config.context]
 * @param {'chrome'|'safari'|'firefox'|''} [config.browser]
 * @param {boolean|null} [config.proxyBehindHttps]
 * @returns {{status:'pass'|'warn'|'fail', summary:string, expected:object, problems:Array, fixes:Array, checklist:string[], disclaimer:string}}
 */
export function diagnose(config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const problems = [];
  const fixes = [];
  const checklist = [];

  const expected = computeExpected(cfg);
  const { cookie, page, api, isCrossOrigin, isCrossSite, effectiveSameSite, requestCredentials, context, browser, proxyBehindHttps } = expected;

  if (!cookie.provided) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'set_cookie_missing',
      message: "setCookie is empty, so nothing can be diagnosed yet. Paste the raw Set-Cookie value: DevTools → Network → the response → Response Headers → Set-Cookie (or your server logs).",
      path: 'setCookie',
    });
  } else if (cookie.invalid) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'cookie_unparsable',
      message: `Couldn't find a cookie name before "=" in "${cookie.raw}". Paste the value exactly as it appears after "Set-Cookie:", starting with the cookie's name.`,
      path: 'setCookie',
      value: cookie.raw,
    });
  } else {
    if (cookie.extraLines > 0) {
      pushProblem(problems, {
        severity: 'low',
        code: 'multiple_lines_pasted',
        message: `${cookie.extraLines + 1} lines were pasted. A browser sends one Set-Cookie header per cookie, so only the first one ("${cookie.name}=...") is analyzed here: diagnose the others separately.`,
        path: 'setCookie',
      });
    }

    // ── SameSite=None requires Secure ───────────────────────────────────
    if (cookie.sameSite === 'None' && !cookie.secure) {
      pushProblem(problems, {
        severity: 'high',
        code: 'samesite_none_requires_secure',
        message: 'SameSite=None is set without Secure. Since Chrome 80 (and per the current spec), a SameSite=None cookie without Secure is rejected outright: the browser never stores it at all.',
        path: 'setCookie',
        value: 'SameSite=None',
        fix: 'Add Secure to the Set-Cookie header.',
      });
      if (expected.correctedSetCookieLine) {
        fixes.push({ title: 'Add Secure (required by SameSite=None)', value: expected.correctedSetCookieLine, where: 'Set-Cookie header, server response' });
      }
    }

    // ── Secure on an http origin ─────────────────────────────────────────
    if (cookie.secure && api.valid && api.scheme === 'http' && !isLoopbackHost(api.hostname) && proxyBehindHttps !== true) {
      pushProblem(problems, {
        severity: 'high',
        code: 'secure_on_http_origin',
        message: `The Secure attribute is set, but apiOrigin ("${api.raw}") is plain http, not https. A browser refuses to store a Secure cookie from an insecure response; localhost is the only built-in exemption, and even that exemption "is not supported by Safari".`,
        path: 'apiOrigin',
        value: api.raw,
        fix: 'Serve the API over https, or tick "behind an HTTPS-terminating proxy" if a reverse proxy already terminates TLS in front of it.',
      });
    }

    // ── Domain ────────────────────────────────────────────────────────────
    if (cookie.hasDomain) {
      const normalizedDomain = cookie.domain.trim().replace(/^\./, '').toLowerCase();
      if (cookie.domain.trim().startsWith('.')) {
        pushProblem(problems, {
          severity: 'low',
          code: 'domain_leading_dot_ignored',
          message: `Domain="${cookie.domain}" has a leading dot. That's harmless: modern browsers ignore a leading dot in Domain and treat it exactly like "${normalizedDomain}".`,
          path: 'setCookie',
        });
      }
      if (normalizedDomain === 'localhost') {
        pushProblem(problems, {
          severity: 'high',
          code: 'domain_localhost_invalid',
          message: 'Domain=localhost is invalid. Browsers treat "localhost" the way they treat a public suffix and reject a cookie with an explicit Domain=localhost. Omit the Domain attribute on localhost entirely: without it the cookie becomes host-only and still works.',
          path: 'setCookie',
          value: cookie.domain,
          fix: 'Remove the Domain attribute when running on localhost.',
        });
      } else if (!normalizedDomain.includes('.') || MULTI_LABEL_SUFFIXES.has(normalizedDomain)) {
        pushProblem(problems, {
          severity: 'high',
          code: 'domain_public_suffix',
          message: `Domain="${cookie.domain}" is a public suffix${normalizedDomain.includes('.') ? ` ("${normalizedDomain}", the same kind of entry as "co.uk" or "github.io")` : ' (a bare top-level label, the same kind of entry as "com")'}, not a real registrable domain. Browsers reject a cookie scoped this broadly.`,
          path: 'setCookie',
          value: cookie.domain,
          fix: 'Use your actual registrable domain, e.g. "example.com".',
        });
      } else if (api.valid && !domainCoversHost(cookie.domain, api.hostname)) {
        pushProblem(problems, {
          severity: 'high',
          code: 'domain_mismatch',
          message: `Domain="${cookie.domain}" was sent by a response from "${api.hostname}", but "${api.hostname}" is neither equal to "${normalizedDomain}" nor a subdomain of it. A server can only set Domain to its own host or a parent of it, so the browser rejects this cookie outright.`,
          path: 'setCookie',
          value: cookie.domain,
          fix: `Set Domain to "${api.hostname}" itself, omit Domain entirely for a host-only cookie, or use a real parent domain of "${api.hostname}".`,
        });
        if (expected.correctedSetCookieLine) {
          fixes.push({ title: 'Remove the mismatched Domain attribute (host-only cookie)', value: expected.correctedSetCookieLine, where: 'Set-Cookie header, server response' });
        }
      }
    } else if (api.valid && page.valid && api.hostname !== page.hostname && isCrossSite === false) {
      pushProblem(problems, {
        severity: 'low',
        code: 'host_only_cookie_note',
        message: `No Domain attribute: this is a host-only cookie, sent only to "${api.hostname}" exactly, never to "${page.hostname}" even though both share the same registrable domain. That's fine when only the API needs it; add Domain="${registrableDomain(api.hostname)}" only if the cookie must also be visible on "${page.hostname}".`,
        path: 'setCookie',
      });
    }

    // ── Path ──────────────────────────────────────────────────────────────
    if (cookie.hasPath && cookie.path && !cookie.path.startsWith('/')) {
      pushProblem(problems, {
        severity: 'low',
        code: 'path_attr_not_absolute',
        message: `Path="${cookie.path}" doesn't start with "/". Browsers ignore a malformed Path attribute like this and fall back to the default (the request URL's own directory) rather than rejecting the cookie, so behavior may not match what you intended.`,
        path: 'setCookie',
      });
    }
    if (cookie.hasPath && cookie.path && cookie.path !== '/' && api.valid && api.path && api.path !== '/' && !pathMatches(cookie.path, api.path)) {
      pushProblem(problems, {
        severity: 'medium',
        code: 'path_mismatch',
        message: `Path="${cookie.path}" doesn't cover "${api.path}" (apiOrigin's path). A cookie is only attached to requests whose path starts with the cookie's Path, so requests to "${api.path}" will not carry this cookie.`,
        path: 'setCookie',
        value: cookie.path,
        fix: `Set Path="/" (or a prefix that actually covers "${api.path}").`,
      });
    }

    // ── Expiry ────────────────────────────────────────────────────────────
    if (cookie.hasMaxAge && cookie.maxAge !== null && cookie.maxAge <= 0) {
      pushProblem(problems, {
        severity: 'high',
        code: 'max_age_non_positive',
        message: `Max-Age=${cookie.maxAgeRaw} is zero or negative. Per spec, that expires the cookie immediately: the browser deletes it (or never keeps it) instead of storing it.`,
        path: 'setCookie',
        value: cookie.maxAgeRaw,
        fix: 'Use a positive Max-Age (seconds from now), or omit Max-Age/Expires entirely for a session cookie.',
      });
    }
    if (cookie.hasExpires) {
      if (!cookie.expiresValid) {
        pushProblem(problems, {
          severity: 'medium',
          code: 'expires_unparsable',
          message: `Expires="${cookie.expiresRaw}" isn't a date the browser can parse reliably. Use an exact HTTP-date, e.g. "Wed, 09 Jun 2027 10:18:14 GMT".`,
          path: 'setCookie',
          value: cookie.expiresRaw,
        });
      } else if (cookie.expiresDate.getTime() <= Date.now()) {
        pushProblem(problems, {
          severity: 'high',
          code: 'expires_in_past',
          message: `Expires="${cookie.expiresRaw}" is in the past. A Set-Cookie with a past Expires date deletes the cookie (or never stores it), exactly like Max-Age<=0.`,
          path: 'setCookie',
          value: cookie.expiresRaw,
          fix: 'Set Expires to a future date, use Max-Age instead, or omit both for a session cookie.',
        });
      }
    }

    // ── Cookie-name prefixes ─────────────────────────────────────────────
    if (cookie.prefixKind === '__Host-' || cookie.prefixKind === '__Host-Http-') {
      const violations = [];
      if (!cookie.secure) violations.push('Secure is missing');
      if (cookie.hasDomain) violations.push('a Domain attribute is present');
      if (!cookie.hasPath || cookie.path !== '/') violations.push('Path is not exactly "/"');
      if (violations.length) {
        pushProblem(problems, {
          severity: 'high',
          code: 'host_prefix_violation',
          message: `"${cookie.name}" uses the ${cookie.prefixKind} prefix, which requires Secure, no Domain attribute, and Path=/ exactly: ${violations.join('; ')}. A user agent that enforces cookie prefixes rejects this cookie entirely.`,
          path: 'setCookie',
          value: cookie.name,
          fix: 'Add Secure, remove Domain, and set Path=/.',
        });
        if (expected.correctedSetCookieLine) {
          fixes.push({ title: `Fix the ${cookie.prefixKind} prefix requirements`, value: expected.correctedSetCookieLine, where: 'Set-Cookie header, server response' });
        }
      }
    }
    if (cookie.prefixKind === '__Secure-' && !cookie.secure) {
      pushProblem(problems, {
        severity: 'high',
        code: 'secure_prefix_violation',
        message: `"${cookie.name}" uses the __Secure- prefix, which requires Secure. Without it, a user agent that enforces cookie prefixes rejects this cookie entirely.`,
        path: 'setCookie',
        value: cookie.name,
        fix: 'Add Secure to the Set-Cookie header.',
      });
      if (expected.correctedSetCookieLine) {
        fixes.push({ title: 'Add Secure (required by the __Secure- prefix)', value: expected.correctedSetCookieLine, where: 'Set-Cookie header, server response' });
      }
    }
    if ((cookie.prefixKind === '__Http-' || cookie.prefixKind === '__Host-Http-') && (!cookie.secure || !cookie.httpOnly)) {
      pushProblem(problems, {
        severity: 'high',
        code: 'http_prefix_violation',
        message: `"${cookie.name}" uses the ${cookie.prefixKind} prefix, which requires both Secure and HttpOnly to prove it was set via a real Set-Cookie header. ${!cookie.secure ? 'Secure is missing. ' : ''}${!cookie.httpOnly ? 'HttpOnly is missing.' : ''}`.trim(),
        path: 'setCookie',
        value: cookie.name,
        fix: 'Add both Secure and HttpOnly.',
      });
    }

    // ── Partitioned / CHIPS ───────────────────────────────────────────────
    if (cookie.partitioned && !cookie.secure) {
      pushProblem(problems, {
        severity: 'high',
        code: 'partitioned_requires_secure',
        message: 'Partitioned is set without Secure. CHIPS requires Secure on every partitioned cookie: "Partitioned cookies must be set with Secure". Without it the browser rejects the cookie.',
        path: 'setCookie',
        fix: 'Add Secure to the Set-Cookie header.',
      });
      if (expected.correctedSetCookieLine) {
        fixes.push({ title: 'Add Secure (required by Partitioned)', value: expected.correctedSetCookieLine, where: 'Set-Cookie header, server response' });
      }
    }
    if (cookie.partitioned && cookie.sameSite !== 'None') {
      pushProblem(problems, {
        severity: 'low',
        code: 'partitioned_without_samesite_none',
        message: "Partitioned is set but SameSite isn't explicitly None. Add SameSite=None so a browser that doesn't yet support Partitioned still sends this cookie in the third-party context it was meant for.",
        path: 'setCookie',
      });
    }

    // ── HttpOnly note ─────────────────────────────────────────────────────
    if (cookie.httpOnly) {
      pushProblem(problems, {
        severity: 'low',
        code: 'httponly_hides_from_js',
        message: "HttpOnly is set, so this cookie never shows up in document.cookie or the Cookie Store API. That's expected, not a bug: HttpOnly cookies are still read and sent by the browser on matching requests, JavaScript on the page just can't see them (that's the point: it blocks cookie theft via XSS).",
        path: 'setCookie',
      });
    }

    // ── default SameSite note ────────────────────────────────────────────
    if (!cookie.hasSameSite) {
      pushProblem(problems, {
        severity: 'low',
        code: 'samesite_default_lax',
        message: 'No SameSite attribute is set. Chrome, Edge, Firefox (69+), and Safari (13+) all default a cookie with no SameSite to Lax, not None: it will NOT be sent on cross-site subrequests (fetch, XHR, iframes) even though nothing here says so explicitly.',
        path: 'setCookie',
      });
    }

    // ── cross-site enforcement ───────────────────────────────────────────
    if (isCrossSite === true) {
      const verdict = sameSiteVerdict(effectiveSameSite, true, context);
      if (!verdict.sent) {
        pushProblem(problems, {
          severity: 'high',
          code: 'samesite_blocks_cross_site',
          message: `pageOrigin and apiOrigin are cross-site (different registrable domain and/or scheme), and SameSite=${effectiveSameSite}${cookie.hasSameSite ? '' : ' (the default, since none was set)'} in a "${context || 'unspecified'}" context: ${verdict.reason}. The cookie will not be attached to this request.`,
          path: 'setCookie',
          value: effectiveSameSite,
          fix: 'If cross-site use is intentional, set SameSite=None; Secure. If it is not, the request should not be cross-site in the first place: check pageOrigin/apiOrigin.',
        });
        const noneVariant = Object.assign({}, cookie, { sameSite: 'None', hasSameSite: true, secure: true });
        fixes.push({ title: 'If cross-site is intentional: SameSite=None; Secure', value: serializeCookie(noneVariant), where: 'Set-Cookie header, server response' });
      } else if (effectiveSameSite === 'None' && context === 'iframe') {
        if (browser === 'safari') {
          pushProblem(problems, {
            severity: 'high',
            code: 'itp_blocks_third_party',
            message: "SameSite=None allows cross-site sending in theory, but Safari's Intelligent Tracking Prevention purges or withholds storage for a third party the user hasn't interacted with directly, independent of SameSite: this cookie may still never reach the server inside a cross-site iframe.",
            path: 'browser',
            value: 'safari',
            fix: 'Do not rely on a third-party cookie in a Safari iframe: proxy the request through a first-party domain, or use the Storage Access API.',
          });
        } else {
          pushProblem(problems, {
            severity: 'medium',
            code: 'third_party_cookies_deprecation',
            message: `SameSite=None works today in "${browser || 'this browser'}", but third-party cookies in a cross-site iframe are being restricted or partitioned in most browsers. Don't build new functionality that depends on a plain third-party cookie surviving here.`,
            path: 'browser',
            fix: 'Add the Partitioned attribute (CHIPS) for forward compatibility, or route the request through a first-party domain.',
          });
        }
        if (cookie.secure && !cookie.partitioned) {
          pushProblem(problems, {
            severity: 'low',
            code: 'chips_suggestion',
            message: 'This cookie is cross-site, in an iframe, with SameSite=None; Secure: a good candidate for the Partitioned attribute (CHIPS), which keeps per-top-level-site storage working as third-party cookies get phased out. The __Host- prefix is recommended alongside it.',
            path: 'setCookie',
            fix: 'Add ; Partitioned to the Set-Cookie header (and consider the __Host- prefix).',
          });
        }
      }
    } else if (isCrossSite === false && isCrossOrigin === true) {
      const differsBy = page.hostname !== api.hostname ? 'host (subdomain)' : 'port';
      pushProblem(problems, {
        severity: 'low',
        code: 'same_site_cross_origin_note',
        message: `pageOrigin and apiOrigin are same-site but not same-origin (they differ by ${differsBy}). SameSite is satisfied either way, but that's not enough on its own: fetch/XHR still needs credentials:'include' (or xhr.withCredentials = true) to send or receive this cookie across origins, and the API's CORS headers still apply.`,
        path: 'pageOrigin',
      });
    }

    // ── fetch/XHR credentials ─────────────────────────────────────────────
    if (context === 'fetch-xhr' && isCrossOrigin === true) {
      if (requestCredentials !== 'include') {
        pushProblem(problems, {
          severity: 'high',
          code: 'fetch_credentials_missing',
          message: `The request is cross-origin (fetch/XHR to a different scheme, host, or port), and requestCredentials is "${requestCredentials || 'not set'}". fetch()'s default credentials mode is "same-origin": a cross-origin call without credentials:'include' neither sends this cookie nor stores one from the response, no matter what SameSite says.`,
          path: 'requestCredentials',
          value: requestCredentials,
          fix: "Add credentials: 'include' to the fetch() call, or xhr.withCredentials = true for XMLHttpRequest.",
        });
        fixes.push({ title: "Add credentials: 'include' to the fetch/XHR call", value: "fetch(url, { credentials: 'include' })", where: 'Your front-end request code' });
      } else {
        pushProblem(problems, {
          severity: 'high',
          code: 'cors_wildcard_credentials_risk',
          message: 'requestCredentials is \'include\' on a cross-origin call: the API\'s CORS response must set Access-Control-Allow-Credentials: true and an exact Access-Control-Allow-Origin naming pageOrigin, not "*". A wildcard Access-Control-Allow-Origin is incompatible with credentials, and the browser blocks the whole response if the server sends both.',
          path: 'requestCredentials',
          value: 'include',
          fix: `Set Access-Control-Allow-Origin: ${page.valid ? page.origin : '<exact pageOrigin>'} and Access-Control-Allow-Credentials: true on the API response (never a wildcard).`,
        });
      }
    } else if (context === 'fetch-xhr' && isCrossOrigin === false && requestCredentials === 'omit') {
      pushProblem(problems, {
        severity: 'high',
        code: 'fetch_credentials_omitted_same_origin',
        message: 'requestCredentials is explicitly "omit" even though pageOrigin and apiOrigin are the same origin. "omit" always excludes cookies, same-origin or not: this request will never send or receive this cookie.',
        path: 'requestCredentials',
        value: 'omit',
        fix: "Remove credentials: 'omit' (the default, 'same-origin', already sends cookies here), or set it to 'include' if you meant a different origin.",
      });
    }
  }

  checklist.push("Open DevTools → Application/Storage → Cookies for the API's origin right after the response and confirm the cookie is actually there, with the attributes you expect.");
  checklist.push('Reproduce the real cross-origin/cross-site scenario (a second origin, or an actual iframe), not just localhost same-origin: SameSite and third-party blocking only show up once origins genuinely differ.');
  checklist.push("Read the exact Set-Cookie header your server actually sent, not what your code intended: a framework default or a reverse proxy sometimes strips or rewrites attributes in transit.");
  if (context === 'fetch-xhr') {
    checklist.push("Both sides of a credentialed cross-origin request must agree: credentials:'include' on the client AND Access-Control-Allow-Credentials: true plus an exact Access-Control-Allow-Origin on the server.");
  }

  const sorted = sortProblems(problems);
  const highCount = sorted.filter((p) => p.severity === 'high').length;
  const medCount = sorted.filter((p) => p.severity === 'medium').length;
  const lowCount = sorted.filter((p) => p.severity === 'low').length;

  let status = 'pass';
  if (highCount > 0) status = 'fail';
  else if (medCount > 0 || lowCount > 0) status = 'warn';

  let summary;
  if (status === 'pass') {
    summary = 'No blocking or informational issues found: this cookie should be stored and sent exactly as configured.';
  } else if (status === 'fail') {
    const top = sorted.find((p) => p.severity === 'high');
    summary = `${highCount} blocking issue${highCount > 1 ? 's' : ''} found. Most urgent: ${top.message}`;
  } else {
    const top = sorted[0];
    summary = `Nothing blocking, but ${medCount + lowCount} thing${medCount + lowCount > 1 ? 's' : ''} worth checking. Top of the list: ${top.message}`;
  }

  return {
    status,
    summary,
    expected,
    problems: sorted,
    fixes,
    checklist,
    disclaimer:
      'Read-only, client-side analysis of the values you entered. "Site" is computed with a small curated list of multi-label suffixes (co.uk, github.io, ...), not a full Public Suffix List, so unusual domains may be misjudged. Nothing is verified against your live server or a real browser: confirm in DevTools before shipping. Not affiliated with Google, Apple/Safari, Mozilla, or any browser vendor.',
  };
}

/**
 * Standalone helper: just the parsed cookie, origin comparison, and
 * suggested corrected Set-Cookie line for a config, without running the full
 * diagnostic. Handy for live-updating a preview as the user types.
 */
export function expectedValues(config) {
  return computeExpected(config);
}

// Also expose as a plain browser global when loaded via <script type="module">.
if (typeof window !== 'undefined') {
  window.CookieDoctor = { diagnose, expectedValues };
}
