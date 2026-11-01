## First time running the tool

Open PowerShell in the extracted folder and run ` .\Invoke-WebSecurityReview.ps1 ` (without the spaces around the command). The prompts help you pick a target, Standard/Deep/Full mode, and report preference. Standard is recommended for a first run. Deep is still read-only. Full requires real, approved API paths and a separate YES confirmation before any POST requests; without these, it switches to Deep. Use command-line arguments for repeatable automation or custom API contracts.

# Community guide: why these checks matter

**Scope:** Read-only-by-default verification of publicly visible website settings, not a vulnerability scan or penetration test. Assess only sites you own or have permission to test.

## A browser-friendly website isn't always a secure website

Some small sites still use `http://`, while others redirect `http://` to `https://`. The updated script understands both and reports their behavior explicitly. On an HTTP-only site, neither passwords nor form content should be submitted: traffic can be intercepted and altered. TLS, trusted certificates, HTTPS redirects and HSTS help protect the transport layer.

## Defense in depth

| Layer | Example checks | Don't overinterpret |
|---|---|---|
| Transport | HTTPS present, HTTP upgrade, optional TLS 1.3-only | TLS 1.2 may be acceptable for compatibility; this optional strict baseline is not universal |
| Browser | CSP, HSTS, nosniff, frame restrictions, COOP | Headers cannot replace secure app code or input/output validation |
| Discovery | Public pages, selected private paths | Ten blocked paths don't prove all files are private |
| DNS | CAA at Google and Cloudflare DoH resolvers | CAA isn't DNSSEC validation and can legitimately be absent |
| Operations | `security.txt`, robots metadata | These don't prove incident readiness or SEO effectiveness |
| APIs (opt in) | Invalid origin, malformed JSON, content-type rejection | Response codes are application-specific, not comprehensive security tests |

## Things we've learned building Byson Cyber

1. Cloudflare's automatic Web Analytics beacon can conflict with `script-src 'self'` if injected without changing CSP. Check DevTools, decide whether to disable injection or authorize the external source.
2. Cloudflare Managed Transforms may override headers set by a Worker; inspect **live** response headers after deploying.
3. CAA authorizes eligible certificate issuers; it does not select your CA or guarantee certificate renewal. Optional CAA `iodef` reports need a working external-receiving mailbox.
4. `HSTS ... includeSubDomains; preload` is a commitment to all browser-facing subdomains. The `preload` token in a header is **not** proof that a browser preload-list submission has been accepted.
5. An API correctly returning `405`, `403`, `400`, or `415` is only one layer. Server-side validation, logging hygiene, provider scopes, abuse controls and appropriate authentication still matter.
6. Do not paste secrets, API responses containing visitor data, or session cookies into issue reports or public Git repositories.
7. Trusted Types is a potential additional browser defense; test it before enforcing rather than breaking existing JavaScript for a score.

## References

- [OWASP Secure Headers](https://owasp.org/projects/secure-headers-project/)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [Cloudflare Workers preview URLs](https://developers.cloudflare.com/workers/previews/)
- [Google PageSpeed Insights](https://pagespeed.web.dev/)

No automated script should claim a fully secure website from its PASS count.


## v1.2.2: why Full mode is not universal

A route that returns GET 404 may be a missing page **or** an intentionally hidden POST-only API, so the tool does not send a POST by default. GET 405 can come from method-aware middleware and doesn't definitively prove a working API. Choose a verified route before running Full.

A deliberately invalid request that returns any ordinary 4xx is evidence of rejection, **not** evidence of which layer rejected it. For instance, 403 could come from authorization, the WAF, or an origin policy. 405 may mean the route simply disallows POST, so downstream JSON validation cannot be tested. 429 means back off; do not interpret it as validation. 2xx for a negative request is a reason to investigate side effects, not automatic proof of a security flaw.

The original Byson-specific policy expects GET=405, cross-origin=403, malformed JSON=400, unsupported media type=415 and `Cache-Control: no-store`. The Community defaults are intentionally less prescriptive. Full mode is opt-in, may create logs, and negative inputs can still have unexpected side effects on custom APIs.

## v1.2.4 guided Full-mode confirmation

The additional Full-mode consent prompt accepts `yes`, `Yes`, `YES`, or any other capitalization of the full word `yes`. Other responses change the run to read-only Deep; `y` remains valid at the separate general permission prompt.

## Optional files and observation-only grades (v1.2.6)

A missing default `robots.txt`, `sitemap.xml` or `/.well-known/security.txt` file is normally informational, not an exploitable security finding. An existing `security.txt` should have a valid, nonexpired `Expires`; RFC 9116 recommends less than one year in the future. A longer but still-valid date is INFO, not WARN. CAA records are also observational unless you explicitly configure the expected issuer/reporting values. Resolver record counts do not validate an issuer's authorization or certificate-renewal compatibility.
