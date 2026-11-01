## v1.2.6 - Clearer optional-file, expiry and CAA reporting (2026-11-01)

- Missing default optional robots, sitemap and security.txt files (404/410) are INFO, not WARN; real errors and non-optional missing routes retain WARN.
- `security.txt` expirations more than 365 days ahead generate INFO per RFC 9116 recommendation. Expired, missing and invalid dates remain WARN.
- Unconfigured CAA issuer/report expectations are not policy-validated; records found by both resolvers are INFO, not PASS. Explicit expectations retain strict PASS/WARN classification.
- Preserve Windows PowerShell 5.1 ASCII-safe BOM/CRLF compatibility and all v1.2.5 curl, authorization and report behavior.
- Static source/package checks completed; test the new script on Windows before publishing.

## v1.2.5 - Windows TLS probe crash fix (2026-11-01)

- Fixes Windows PowerShell 5.1 terminating on expected `curl.exe` TLS handshake errors (for example, Schannel `SEC_E_UNSUPPORTED_FUNCTION`) while `ErrorActionPreference` is Stop.
- For each curl probe, temporarily relaxes native stderr handling and uses the process exit code to classify the result, restoring the error preference afterward.
- An unsupported TLS 1.3 handshake is now reported as a compatibility WARN while the audit continues to TLS 1.2, headers, DNS, and exposure checks; no site vulnerability is assumed from the single result.
- Corrected the version metadata displayed in CSV/JSON/HTML and the console to v1.2.5.
- No changes to Full-mode API authorization, pacing, read-only behavior, or production configurations.
- Windows PowerShell 5.1 live-run confirmation is still recommended after installing this update.

## v1.2.4 - Full-mode consent usability fix (2026-11-01)

- Guided Full now accepts `yes`, `Yes`, `YES` (any capitalization, optional whitespace) for explicit API POST authorization instead of only uppercase `YES`.
- Any other confirmation still falls back to Deep with no POST requests. The separate general site-ownership prompt continues to accept `y`/`yes`.
- No changes to network checks, API pacing, report format, or non-interactive use.

## v1.2.3 - Guided setup for first-time users

- Run `Invoke-WebSecurityReview.ps1` without arguments to get a domain prompt, Standard/Deep/Full menu, authorization check and optional CSV/JSON/HTML output.
- Full mode prompts only for real API paths, warns that invalid POSTs may have side effects, and asks for an explicit YES authorization. Without a real approved path it automatically falls back to Deep, with no POSTs.
- Explicit `-SiteUrl` runs remain noninteractive; the Byson preset's behavior is unchanged.
- Adds a runnable example and first-time-user documentation; preserves Windows PowerShell 5.1 BOM/ASCII-safe source and CRLF line endings.

# Changelog

## v1.2.2 - 2026-11-01

- Full mode requires a real `-ApiPaths` path; rejects example placeholders before probing the site.
- Routes that return GET `404`/`410`, redirects, or network errors skip active POSTs (GET 404 is ambiguous for POST-only routes).
- GET 405, access-control responses, rejected invalid POSTs, missing endpoints, redirect responses, 429 rate limits, and backend failures are reported separately.
- 429 halts the rest of active POST probes; POST 405 and 404/410 stop further requests for that endpoint.
- Community mode no longer assumes universal 403/400/415 responses or `no-store`. Strict API contract expectations are optional parameters, enabled explicitly in the Byson production preset.
- Standard/Deep remains read-only, and HTTP-only sites never get API POST requests.
- Previous v1.2.1 Windows PowerShell 5.1 ASCII-safe, BOM, CRLF source behavior is preserved.


## v1.2.1 - 2026-11-01

- Fixed a Windows PowerShell 5.1 parser error triggered by UTF-8 without BOM and Unicode punctuation in HTML report strings.
- All PowerShell scripts are now ASCII-safe with UTF-8 BOM and CRLF endings for Windows compatibility.
- The HTML report remains self-contained with encoded findings and no third-party scripts.
- No changes to audit scope, Cloudflare settings, or API probe behavior.
- Validate syntax first with `Test-WebAudit-Syntax.ps1` on your Windows PowerShell session.

## v1.2.0 — 2026-11-01

- Added **Standard**, **Deep**, and **Full** modes. Deep is observational; Full adds explicit API negative POST tests only when paths are supplied.
- Deep adds HTTP/HTTPS compatibility and content metadata indicators, extra fixed configuration-file paths, additional CSP and cross-origin header details, and public email/DNSSEC resolver observations.
- Each finding includes severity, why it matters, recommended next steps, and a reference; warnings and failures get a user-facing explanation.
- Export CSV, JSON, and standalone HTML (all self-contained, escaped report content).
- COOP absence is informational, not a default vulnerability warning. CAA absence remains informational.
- Preserved bare domain / HTTP-only input support from v1.1 and existing Byson production baseline configuration.
- Added offline `Test-WebAudit-Syntax.ps1` to detect syntax errors and dangerous writes to common PowerShell automatic/read-only variables.
- No secrets, credentials, real form submissions, vulnerability exploitation, or intentionally rapid WAF probes.

## v1.1.0

- Accept bare domains, HTTP and HTTPS input; prefer HTTPS, continue safe checks against HTTP-only origins.
- Verify CAA through two public DNS resolvers; preserve website routes/headers, redirects, exposure and optional API checks.

## v1.0.x

- Initial Byson Cyber production baseline and community script.
