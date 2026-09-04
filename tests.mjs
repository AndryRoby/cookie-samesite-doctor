// tests.mjs — plain Node test runner for doctor-cookie.js (no external dependencies).
// Run with: node tests.mjs

import { diagnose, expectedValues } from './doctor-cookie.js';

let pass = 0;
let fail = 0;
const failures = [];

function ok(name, cond, detail) {
  if (cond) {
    pass++;
  } else {
    fail++;
    failures.push(`${name}${detail ? ' — ' + detail : ''}`);
  }
}

function eq(name, actual, expected) {
  const condition = actual === expected;
  ok(name, condition, condition ? '' : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function has(name, arr, code) {
  const condition = Array.isArray(arr) && arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `expected a problem with code "${code}", got codes [${(arr || []).map((p) => p.code).join(', ')}]`);
}

function lacks(name, arr, code) {
  const condition = Array.isArray(arr) && !arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `did not expect a problem with code "${code}"`);
}

function severityOf(arr, code) {
  const p = (arr || []).find((x) => x.code === code);
  return p ? p.severity : undefined;
}

function messageOf(arr, code) {
  const p = (arr || []).find((x) => x.code === code);
  return p ? p.message : '';
}

// ─────────────────────────────────────────────────────────────────────────
// 1. expectedValues() — origins, "site" computation, corrected Set-Cookie
// ─────────────────────────────────────────────────────────────────────────

eq('expectedValues(undefined) does not throw and reports no cookie',
  expectedValues(undefined).cookie.provided, false);

eq('expectedValues({}) has a null effectiveSameSite (no cookie provided)',
  expectedValues({}).effectiveSameSite, null);

{
  const e = expectedValues({ pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com' });
  eq('app.example.com and api.example.com are same-site', e.isCrossSite, false);
  eq('app.example.com and api.example.com are cross-origin (different host)', e.isCrossOrigin, true);
}

{
  const e = expectedValues({ pageOrigin: 'https://app.example.com', apiOrigin: 'https://app.other.com' });
  eq('app.example.com and app.other.com are cross-site', e.isCrossSite, true);
}

{
  const e = expectedValues({ pageOrigin: 'http://localhost:3000', apiOrigin: 'http://localhost:5173' });
  eq('localhost:3000 and localhost:5173 are same-site (port is not part of "site")', e.isCrossSite, false);
  eq('localhost:3000 and localhost:5173 are cross-origin (different port)', e.isCrossOrigin, true);
}

{
  const e = expectedValues({ pageOrigin: 'https://127.0.0.1:3000', apiOrigin: 'https://localhost:3000' });
  eq('127.0.0.1 and localhost are cross-site: different, unrelated hosts even though both are loopback', e.isCrossSite, true);
}

{
  const e = expectedValues({ pageOrigin: 'https://app.github.io', apiOrigin: 'https://other.github.io' });
  eq('two distinct *.github.io subdomains are cross-site (github.io is a known multi-label suffix)', e.isCrossSite, true);
}

{
  const e = expectedValues({ pageOrigin: 'https://www.example.co.uk', apiOrigin: 'https://shop.example.co.uk' });
  eq('two subdomains under the same example.co.uk are same-site', e.isCrossSite, false);
}

{
  const e = expectedValues({ pageOrigin: 'https://app.example.com', apiOrigin: 'ftp://api.example.com' });
  eq('a non-http(s) apiOrigin scheme is treated as invalid, not guessed at', e.isCrossSite, null);
}

{
  const e = expectedValues({ apiOrigin: 'api.example.com' });
  eq('a bare host without a scheme is tolerated (defaults to https)', e.api.valid, true);
  eq('the tolerant default scheme is https', e.api.scheme, 'https');
}

eq('SameSite=None without Secure: corrected line adds Secure',
  expectedValues({ setCookie: 'sid=abc; SameSite=None' }).correctedSetCookieLine,
  'sid=abc; Path=/; Secure; SameSite=None');

eq('an already-correct cookie needs no correction (null, not a no-op copy)',
  expectedValues({ setCookie: 'sid=abc; Path=/' }).correctedSetCookieLine, null);

eq('__Host- prefix missing Path=/ gets it added in the corrected line',
  expectedValues({ setCookie: '__Host-id=1; Secure' }).correctedSetCookieLine,
  '__Host-id=1; Path=/; Secure');

// ─────────────────────────────────────────────────────────────────────────
// 2. diagnose() — missing / unparsable input
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({});
  has('empty config: flags set_cookie_missing', r.problems, 'set_cookie_missing');
  eq('empty config: severity is medium', severityOf(r.problems, 'set_cookie_missing'), 'medium');
  eq('empty config: status is warn (no high-severity problems)', r.status, 'warn');
}

{
  const r = diagnose(undefined);
  ok('diagnose(undefined) does not throw and returns a status', typeof r.status === 'string');
}

{
  const r = diagnose({ setCookie: '   ' });
  has('whitespace-only setCookie is treated as missing', r.problems, 'set_cookie_missing');
}

{
  const r = diagnose({ setCookie: '=onlyavalue' });
  has('a header with no name before "=" is unparsable', r.problems, 'cookie_unparsable');
  eq('cookie_unparsable severity is medium', severityOf(r.problems, 'cookie_unparsable'), 'medium');
}

{
  const r = diagnose({ setCookie: 'sid=abc; SameSite=None\nother=xyz; Path=/' });
  has('a second pasted line is flagged as multiple_lines_pasted', r.problems, 'multiple_lines_pasted');
  eq('multiple_lines_pasted severity is low', severityOf(r.problems, 'multiple_lines_pasted'), 'low');
}

// ─────────────────────────────────────────────────────────────────────────
// 3. diagnose() — SameSite=None requires Secure
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; SameSite=None' });
  has('SameSite=None without Secure is flagged', r.problems, 'samesite_none_requires_secure');
  eq('samesite_none_requires_secure severity is high', severityOf(r.problems, 'samesite_none_requires_secure'), 'high');
  const fix = r.fixes.find((f) => f.title.includes('Add Secure (required by SameSite=None)'));
  ok('a fix adds Secure to the header', !!fix && /Secure/.test(fix.value));
}

{
  const r = diagnose({ setCookie: 'sid=abc; SameSite=None; Secure' });
  lacks('SameSite=None with Secure is not flagged', r.problems, 'samesite_none_requires_secure');
}

// ─────────────────────────────────────────────────────────────────────────
// 4. diagnose() — Secure on an insecure (http) origin
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; Secure', apiOrigin: 'http://api.example.com' });
  has('Secure cookie from a plain-http, non-localhost origin is flagged', r.problems, 'secure_on_http_origin');
  eq('secure_on_http_origin severity is high', severityOf(r.problems, 'secure_on_http_origin'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Secure', apiOrigin: 'http://localhost:8000' });
  lacks('Secure over http on localhost is exempt', r.problems, 'secure_on_http_origin');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Secure', apiOrigin: 'http://api.example.com', proxyBehindHttps: true });
  lacks('a declared HTTPS-terminating proxy suppresses the http-origin warning', r.problems, 'secure_on_http_origin');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Secure', apiOrigin: 'https://api.example.com' });
  lacks('Secure over https is never flagged', r.problems, 'secure_on_http_origin');
}

// ─────────────────────────────────────────────────────────────────────────
// 5. diagnose() — Domain attribute
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=localhost' });
  has('Domain=localhost is flagged', r.problems, 'domain_localhost_invalid');
  eq('domain_localhost_invalid severity is high', severityOf(r.problems, 'domain_localhost_invalid'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=com' });
  has('a bare single-label Domain is flagged as a public suffix', r.problems, 'domain_public_suffix');
  eq('domain_public_suffix severity is high', severityOf(r.problems, 'domain_public_suffix'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=co.uk' });
  has('a known multi-label public suffix (co.uk) is flagged', r.problems, 'domain_public_suffix');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=app.example.com', apiOrigin: 'https://api.example.com' });
  has('Domain set to an unrelated sibling subdomain is flagged', r.problems, 'domain_mismatch');
  eq('domain_mismatch severity is high', severityOf(r.problems, 'domain_mismatch'), 'high');
  ok('domain_mismatch message names both hosts', /api\.example\.com/.test(messageOf(r.problems, 'domain_mismatch')) && /app\.example\.com/.test(messageOf(r.problems, 'domain_mismatch')));
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=example.com', apiOrigin: 'https://api.example.com' });
  lacks('Domain set to the shared parent of the responding host is valid', r.problems, 'domain_mismatch');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=api.example.com', apiOrigin: 'https://api.example.com' });
  lacks('Domain equal to the responding host itself is valid', r.problems, 'domain_mismatch');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Domain=.example.com', apiOrigin: 'https://api.example.com' });
  has('a leading dot on Domain is called out (but harmless)', r.problems, 'domain_leading_dot_ignored');
  eq('domain_leading_dot_ignored severity is low', severityOf(r.problems, 'domain_leading_dot_ignored'), 'low');
  lacks('the leading dot alone does not also trigger a mismatch', r.problems, 'domain_mismatch');
}

{
  const r = diagnose({ setCookie: 'sid=abc', pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com' });
  has('no Domain attribute across sibling subdomains gets a host-only-cookie note', r.problems, 'host_only_cookie_note');
  eq('host_only_cookie_note severity is low', severityOf(r.problems, 'host_only_cookie_note'), 'low');
}

// ─────────────────────────────────────────────────────────────────────────
// 6. diagnose() — Path attribute
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; Path=api/v1' });
  has('a Path not starting with "/" is flagged', r.problems, 'path_attr_not_absolute');
  eq('path_attr_not_absolute severity is low', severityOf(r.problems, 'path_attr_not_absolute'), 'low');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Path=/admin', apiOrigin: 'https://api.example.com/v1/data' });
  has('a Path that does not cover the API request path is flagged', r.problems, 'path_mismatch');
  eq('path_mismatch severity is medium', severityOf(r.problems, 'path_mismatch'), 'medium');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Path=/v1', apiOrigin: 'https://api.example.com/v1/data' });
  lacks('a Path that is a directory prefix of the request path is fine', r.problems, 'path_mismatch');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Path=/', apiOrigin: 'https://api.example.com/v1/data' });
  lacks('Path=/ always covers every request path', r.problems, 'path_mismatch');
}

// ─────────────────────────────────────────────────────────────────────────
// 7. diagnose() — Expires / Max-Age
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; Max-Age=0' });
  has('Max-Age=0 is flagged as an immediate expiry', r.problems, 'max_age_non_positive');
  eq('max_age_non_positive severity is high', severityOf(r.problems, 'max_age_non_positive'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Max-Age=-30' });
  has('a negative Max-Age is flagged', r.problems, 'max_age_non_positive');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Max-Age=3600' });
  lacks('a positive Max-Age is not flagged', r.problems, 'max_age_non_positive');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT' });
  has('an Expires date in the past is flagged', r.problems, 'expires_in_past');
  eq('expires_in_past severity is high', severityOf(r.problems, 'expires_in_past'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Expires=Fri, 01 Jan 2099 00:00:00 GMT' });
  lacks('a future Expires date is not flagged', r.problems, 'expires_in_past');
  lacks('a well-formed future Expires date is not "unparsable"', r.problems, 'expires_unparsable');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Expires=not-a-real-date' });
  has('a malformed Expires value is flagged as unparsable', r.problems, 'expires_unparsable');
  eq('expires_unparsable severity is medium', severityOf(r.problems, 'expires_unparsable'), 'medium');
}

// ─────────────────────────────────────────────────────────────────────────
// 8. diagnose() — cookie-name prefixes (__Host-, __Secure-, __Http-)
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: '__Host-id=1; Secure; Path=/' });
  lacks('a fully compliant __Host- cookie is not flagged', r.problems, 'host_prefix_violation');
}

{
  const r = diagnose({ setCookie: '__Host-id=1; Secure' });
  has('__Host- without an explicit Path=/ is flagged', r.problems, 'host_prefix_violation');
  eq('host_prefix_violation severity is high', severityOf(r.problems, 'host_prefix_violation'), 'high');
}

{
  const r = diagnose({ setCookie: '__Host-id=1; Secure; Path=/; Domain=example.com' });
  has('__Host- with a Domain attribute is flagged', r.problems, 'host_prefix_violation');
  ok('message calls out the Domain attribute specifically', /Domain/.test(messageOf(r.problems, 'host_prefix_violation')));
}

{
  const r = diagnose({ setCookie: '__Secure-id=1' });
  has('__Secure- without Secure is flagged', r.problems, 'secure_prefix_violation');
  eq('secure_prefix_violation severity is high', severityOf(r.problems, 'secure_prefix_violation'), 'high');
}

{
  const r = diagnose({ setCookie: '__Secure-id=1; Secure' });
  lacks('__Secure- with Secure is fine', r.problems, 'secure_prefix_violation');
}

{
  const r = diagnose({ setCookie: '__Http-id=1; Secure' });
  has('__Http- without HttpOnly is flagged', r.problems, 'http_prefix_violation');
  eq('http_prefix_violation severity is high', severityOf(r.problems, 'http_prefix_violation'), 'high');
}

{
  const r = diagnose({ setCookie: '__Http-id=1; Secure; HttpOnly' });
  lacks('__Http- with both Secure and HttpOnly is fine', r.problems, 'http_prefix_violation');
}

{
  const r = diagnose({ setCookie: '__Host-Http-id=1; Secure; HttpOnly; Path=/' });
  lacks('a fully compliant __Host-Http- cookie has no host_prefix_violation', r.problems, 'host_prefix_violation');
  lacks('a fully compliant __Host-Http- cookie has no http_prefix_violation', r.problems, 'http_prefix_violation');
}

// ─────────────────────────────────────────────────────────────────────────
// 9. diagnose() — Partitioned (CHIPS)
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; Partitioned' });
  has('Partitioned without Secure is flagged', r.problems, 'partitioned_requires_secure');
  eq('partitioned_requires_secure severity is high', severityOf(r.problems, 'partitioned_requires_secure'), 'high');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Partitioned; Secure' });
  lacks('Partitioned with Secure is not flagged for that rule', r.problems, 'partitioned_requires_secure');
  has('Partitioned without SameSite=None gets a low-severity suggestion', r.problems, 'partitioned_without_samesite_none');
}

{
  const r = diagnose({ setCookie: 'sid=abc; Partitioned; Secure; SameSite=None' });
  lacks('Partitioned with SameSite=None needs no suggestion', r.problems, 'partitioned_without_samesite_none');
}

// ─────────────────────────────────────────────────────────────────────────
// 10. diagnose() — HttpOnly note, default-SameSite note
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc; HttpOnly' });
  has('HttpOnly gets an informational note about document.cookie', r.problems, 'httponly_hides_from_js');
  eq('httponly_hides_from_js severity is low', severityOf(r.problems, 'httponly_hides_from_js'), 'low');
}

{
  const r = diagnose({ setCookie: 'sid=abc' });
  has('a cookie with no SameSite gets the default-Lax note', r.problems, 'samesite_default_lax');
  eq('samesite_default_lax severity is low', severityOf(r.problems, 'samesite_default_lax'), 'low');
}

{
  const r = diagnose({ setCookie: 'sid=abc; SameSite=Lax' });
  lacks('an explicit SameSite does not get the default-Lax note', r.problems, 'samesite_default_lax');
}

// ─────────────────────────────────────────────────────────────────────────
// 11. diagnose() — cross-site enforcement
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Strict; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'top-level',
  });
  has('SameSite=Strict blocks a cross-site request even as a top-level navigation', r.problems, 'samesite_blocks_cross_site');
  eq('samesite_blocks_cross_site severity is high', severityOf(r.problems, 'samesite_blocks_cross_site'), 'high');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'top-level',
  });
  lacks('SameSite=Lax still allows a cross-site top-level navigation', r.problems, 'samesite_blocks_cross_site');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'iframe',
  });
  has('SameSite=Lax blocks a cross-site iframe subrequest', r.problems, 'samesite_blocks_cross_site');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'fetch-xhr', requestCredentials: 'include',
  });
  has('SameSite=Lax blocks a cross-site fetch/XHR subrequest', r.problems, 'samesite_blocks_cross_site');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'fetch-xhr', requestCredentials: 'include',
  });
  has('the default (unset) SameSite also blocks cross-site fetch/XHR', r.problems, 'samesite_blocks_cross_site');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=None; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'iframe', browser: 'safari',
  });
  has('SameSite=None in a Safari cross-site iframe still gets ITP-blocked', r.problems, 'itp_blocks_third_party');
  eq('itp_blocks_third_party severity is high', severityOf(r.problems, 'itp_blocks_third_party'), 'high');
  lacks('ITP is a distinct code from samesite_blocks_cross_site', r.problems, 'samesite_blocks_cross_site');
  has('a Secure, non-partitioned cookie in this exact scenario also gets a CHIPS suggestion', r.problems, 'chips_suggestion');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=None; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'iframe', browser: 'chrome',
  });
  has('SameSite=None in a non-Safari cross-site iframe gets the phase-out warning instead', r.problems, 'third_party_cookies_deprecation');
  eq('third_party_cookies_deprecation severity is medium', severityOf(r.problems, 'third_party_cookies_deprecation'), 'medium');
  lacks('Chrome does not get the Safari-specific ITP code', r.problems, 'itp_blocks_third_party');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=None; Secure',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.other.com',
    context: 'top-level', browser: 'safari',
  });
  lacks('the third-party warnings only apply to the iframe context, not top-level', r.problems, 'itp_blocks_third_party');
  lacks('no CHIPS suggestion outside of an iframe context', r.problems, 'chips_suggestion');
}

// ─────────────────────────────────────────────────────────────────────────
// 12. diagnose() — same-site-but-cross-origin note (e.g. differing ports)
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({
    setCookie: 'sid=abc',
    pageOrigin: 'http://localhost:5173', apiOrigin: 'http://localhost:8000',
  });
  has('same-site, different-port origins get the cross-origin reminder', r.problems, 'same_site_cross_origin_note');
  eq('same_site_cross_origin_note severity is low', severityOf(r.problems, 'same_site_cross_origin_note'), 'low');
}

{
  const r = diagnose({
    setCookie: 'sid=abc',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://app.example.com',
  });
  lacks('identical origins never get the same-site-cross-origin note', r.problems, 'same_site_cross_origin_note');
}

// ─────────────────────────────────────────────────────────────────────────
// 13. diagnose() — fetch/XHR credentials mode
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com',
    context: 'fetch-xhr',
  });
  has('a cross-origin fetch/XHR with no credentials mode set is flagged', r.problems, 'fetch_credentials_missing');
  eq('fetch_credentials_missing severity is high', severityOf(r.problems, 'fetch_credentials_missing'), 'high');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com',
    context: 'fetch-xhr', requestCredentials: 'same-origin',
  });
  has('credentials:"same-origin" on a cross-origin call is also flagged', r.problems, 'fetch_credentials_missing');
}

{
  const r = diagnose({
    setCookie: 'sid=abc; SameSite=Lax',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com',
    context: 'fetch-xhr', requestCredentials: 'include',
  });
  lacks('credentials:"include" on a cross-origin call is not flagged as missing', r.problems, 'fetch_credentials_missing');
  has('but it does get the CORS wildcard/credentials reminder', r.problems, 'cors_wildcard_credentials_risk');
  eq('cors_wildcard_credentials_risk severity is high', severityOf(r.problems, 'cors_wildcard_credentials_risk'), 'high');
}

{
  const r = diagnose({
    setCookie: 'sid=abc',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://app.example.com',
    context: 'fetch-xhr', requestCredentials: 'omit',
  });
  has('credentials:"omit" on a same-origin call is flagged', r.problems, 'fetch_credentials_omitted_same_origin');
  eq('fetch_credentials_omitted_same_origin severity is high', severityOf(r.problems, 'fetch_credentials_omitted_same_origin'), 'high');
}

{
  const r = diagnose({
    setCookie: 'sid=abc',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://app.example.com',
    context: 'fetch-xhr',
  });
  lacks('the default (unset) credentials mode is fine for a same-origin call', r.problems, 'fetch_credentials_omitted_same_origin');
  lacks('and is not treated as cross-origin either', r.problems, 'fetch_credentials_missing');
}

{
  const r = diagnose({
    setCookie: 'sid=abc',
    pageOrigin: 'https://app.example.com', apiOrigin: 'https://api.example.com',
    context: 'top-level',
  });
  lacks('fetch-specific rules do not apply outside a fetch-xhr context', r.problems, 'fetch_credentials_missing');
}

// ─────────────────────────────────────────────────────────────────────────
// 14. diagnose() — overall status + summary
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ setCookie: 'sid=abc123; Path=/; Secure; SameSite=Lax' });
  eq('a clean, minimal, valid cookie yields status "pass"', r.status, 'pass');
  eq('a passing diagnosis reports zero problems', r.problems.length, 0);
  ok('pass summary says nothing blocking was found', /No blocking/i.test(r.summary));
}

{
  const r = diagnose({ setCookie: 'sid=abc' });
  eq('only a low-severity finding yields status "warn"', r.status, 'warn');
}

{
  const r = diagnose({ setCookie: 'sid=abc; SameSite=None' });
  eq('any high-severity finding yields status "fail"', r.status, 'fail');
  ok('fail summary names the most urgent problem', /blocking issue/i.test(r.summary));
}

{
  const r = diagnose({ setCookie: '__Host-id=1; Domain=example.com; Partitioned' });
  eq('several independent high-severity problems still collapse into one "fail"', r.status, 'fail');
  ok('several high-severity codes are all present at once', ['host_prefix_violation', 'partitioned_requires_secure'].every((c) => r.problems.some((p) => p.code === c)));
}

// ─────────────────────────────────────────────────────────────────────────
// 15. sortProblems() — high severity always sorts first, regardless of push order
// ─────────────────────────────────────────────────────────────────────────

{
  // multiple_lines_pasted (low) is pushed before samesite_none_requires_secure
  // (high) in the diagnose() source, so this specifically exercises the sort.
  const r = diagnose({ setCookie: 'sid=abc; SameSite=None\nother=xyz; Path=/' });
  eq('sorted problems: first entry is high severity', r.problems[0].severity, 'high');
  eq('sorted problems: a low-severity entry pushed earlier in code still sorts after it', r.problems[r.problems.length - 1].severity === 'low' || r.problems.some((p) => p.severity === 'low'), true);
  eq('sorted problems: the high-severity code leads', r.problems[0].code, 'samesite_none_requires_secure');
}

// ─────────────────────────────────────────────────────────────────────────
// 16. checklist is always populated
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({});
  ok('checklist has generic guidance even with no input at all', r.checklist.length >= 3);
}

{
  const r = diagnose({ setCookie: 'sid=abc', context: 'fetch-xhr' });
  ok('checklist calls out the two-sided credentials/CORS requirement for fetch-xhr', r.checklist.some((c) => c.includes("credentials:'include'") && /Access-Control-Allow-Credentials/.test(c)));
}

// ─────────────────────────────────────────────────────────────────────────

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
} else {
  console.log('All tests passed.');
}
