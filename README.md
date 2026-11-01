## v1.2.4 - Guided Full confirmation accepts yes in any case

When the wizard asks for explicit Full-mode API POST permission, type `yes`, `Yes`, or `YES` (any capitalization, optional surrounding whitespace). A response other than the full word `yes` still safely switches to Deep with no POST requests. The site ownership/permission prompt continues to accept `y` or `yes` (any case). This changes only the no-argument guided flow; script arguments and the Byson production preset are unchanged.

# Byson Cyber — Community Website Security Audit v1.2.4

A PowerShell tool that runs **low-impact, authorized website configuration checks** and explains why the results matter. Use it for your own websites, to teach good security practices, or with permission to assess a client's site.

**Compatibility:** Windows PowerShell 5.1+ or PowerShell 7, with the `curl` executable installed. It uses Google and Cloudflare public DNS-over-HTTPS for observations; no Cloudflare account, API key, or third-party PowerShell modules required. Designed to work with `http://example.com`, `https://example.com`, or `example.com` input. It prefers HTTPS, follows same-base-domain apex/www redirects, and reports missing HTTPS without refusing to continue its safe GET checks.

## New: Guided setup (no PowerShell experience needed)

For a beginner, **run this by itself**:

```powershell
.\Invoke-WebSecurityReview.ps1
```

The tool asks for the domain, scan type, and authorization to test the website. Choosing **Full** also asks whether you know your actual, authorized API paths and requires explicit approval before it submits deliberately invalid POST requests. If you do not know your API paths or decline, it falls back to **Deep**, which uses GET requests only. Finally, it asks whether to save an HTML, CSV, and JSON report (the default is yes) into a timestamped `reports/` folder.

Example prompts:

```text
1. What website/domain should we review? (example.com): deltarealtyllc.com
2. What type of review do you want?
   [1] Standard (recommended first)
   [2] Deep
   [3] Full (invalid POSTs to approved API paths)
Choose 1, 2, or 3 [default: 1]: 2
Selected: deltarealtyllc.com | Deep
Do you own or have permission to test this website? [y/N]: y
3. Save an HTML, CSV, and JSON report? [Y/n]: y
Running Deep review...
```

**Automation and advanced usage are unchanged:** passing `-SiteUrl` skips all questions. To include additional pages, hosts, and site-specific policies, use the command-line switches described below. If no website is supplied but `-Deep` or `-Mode` is supplied, the wizard asks only the missing information. The script never asks for passwords, API keys, or Cloudflare account access.

## Pick your audit mode

| Mode | Command | Behavior |
|---|---|---|
| **Standard** (default) | `./Invoke-WebSecurityReview.ps1 -SiteUrl example.com` | Basic web security headers, HTTPS redirects, common file exposure, selected public routes, CAA, security.txt, indexing hints. GET-only. |
| **Deep** | `./Invoke-WebSecurityReview.ps1 -SiteUrl example.com -Deep` | Standard plus extended response-header, TLS 1.2/1.3 compatibility, content metadata, mixed-content hints, limited extra sensitive-file paths, public SPF/DMARC/MX/DNSSEC-AD observations. GET-only. |
| **Full** (authorized APIs) | `./Invoke-WebSecurityReview.ps1 -SiteUrl example.com -Full -ApiPaths @('/api/contact')` | Deep plus *up to *three deliberately invalid* POSTs per confirmed HTTPS API path, spaced by at least 11 seconds. Missing or rate-limited endpoints stop additional requests. This test is opt-in. |

Alternatively use `-Mode Standard`, `-Mode Deep`, or `-Mode Full`.

All modes are **configuration reviews, not vulnerability scans**. The number of findings depends on website settings and expected routes. No fixed count of 75 passes is required for arbitrary websites. Byson's 75-check baseline came from a site-specific configuration (multiple aliases and APIs).

### First run: local validation, then audit

In Windows PowerShell, from the extracted toolkit folder (run the syntax check before any website requests):

```powershell
.\Test-WebAudit-Syntax.ps1
.\Invoke-WebSecurityReview.ps1 -SiteUrl deltarealtyllc.com -Deep -ExportPrefix '.\reports\delta'
```

A missing COOP header or CAA record is **not inherently a vulnerability**. The script treats those as INFO unless a site-specific policy explicitly requires them. A TLS 1.2-capable site is not automatically insecure; enforce TLS 1.3-only only if compatible and required for your deployment.

With no parameters, the new guided setup prompts for the domain, scan mode, consent, and report preference. Only use websites you own or are authorized to test.

### Byson production preset

If you downloaded the production ZIP, it adds `Audit-BysonCyber.ps1`. This preset supplies:

- `www.bysoncyber.com` as the preferred canonical site;
- the apex and four alias domains (16 additional redirect combinations);
- all eight primary pages, plus robots, sitemap, and security.txt;
- strict two-year HSTS, subdomains/preload expectations, TLS 1.3-only;
- CAA entries in five zones, including the reporting address;
- two owned API paths, GET method expectations, and authorized Full POST negatives.

```powershell
.\Audit-BysonCyber.ps1
.\Audit-BysonCyber.ps1 -Deep
.\Audit-BysonCyber.ps1 -Full
```

`-Full` runs invalid API tests only to the approved, hardcoded Byson endpoints and uses paced requests. Do not reuse the production preset against third-party sites. The other two modes do not submit POST requests.


## Full mode safety and endpoint-specific expectations (new in v1.2.3)

- **`-Full` now requires `-ApiPaths`**. A missing path, or tutorial placeholder such as `/YOUR-ACTUAL-API-ENDPOINT`, is rejected before any network requests. Use `-Deep` if you do not have an authorized API endpoint.
- Full first checks the chosen path via GET. HTTP `404`/`410`, redirects, and transport failures **do not confirm a usable endpoint**; active POST probes are skipped. A GET `404` does **not** prove there is no POST route; a POST-only route may deliberately hide GET. Use an endpoint that responds to GET with an observable method/access-control response, or review it manually. A GET `405` may also be returned by generic middleware and is not proof of a real route.
- A GET `405` is reported separately as *method rejected*. HTTP `401`/`403` are access-control observations. A negative POST returning ordinary `4xx` is classified as **rejected**, without claiming why it was rejected or assuming a specific security layer did it.
- A POST returning `405` prevents further POST tests to that path. `429` stops all remaining active tests; `5xx` and unexpected `2xx` merit review. Redirect responses are not followed.
- To enforce **your own API contract**, optionally provide `-ExpectedApiGetStatus`, `-ExpectedApiCrossOriginStatus`, `-ExpectedApiMalformedJsonStatus`, `-ExpectedApiUnsupportedMediaTypeStatus` (all use `0` as the default observational setting). Add `-RequireApiNoStore` if your API should explicitly prevent caching. Differences become WARN rather than being mislabeled as exploitable flaws.

For example, only if your owned API really specifies these responses:

```powershell
.\Invoke-WebSecurityReview.ps1 -SiteUrl example.com -Full -ApiPaths @('/api/contact') `
  -ExpectedApiGetStatus 405 -ExpectedApiCrossOriginStatus 403 `
  -ExpectedApiMalformedJsonStatus 400 -ExpectedApiUnsupportedMediaTypeStatus 415 `
  -RequireApiNoStore -ExportPrefix '.\reports\my-api'
```

`Audit-BysonCyber.ps1 -Full` preconfigures these exact expectations for Byson's own APIs. **Do not impose them on unrelated applications.**

## Report exports

Use `-ExportPrefix '.\reports\my-site'` to write **CSV, JSON, and standalone HTML** reports with all observed results, descriptions, and recommended next steps. The HTML file works offline; it has no external CSS, JS, tracking, or network connections. The production launcher exports timestamped reports by default (unless `-NoExport`).

Standard output shows PASS / WARN / FAIL / INFO / SKIP, as well as severity, observed details, and contextual guidance for warnings and failures. Use `-ShowAllGuidance` to print explanations for every result (they are always exported).

### Interpreting results

- **PASS:** One specific observation met its configured expectation. It isn't a guarantee against compromise.
- **WARN:** Unexpected or inconclusive result; review context, functionality, and implementation.
- **FAIL:** Required behavior not met, such as inaccessible HTTPS or an HTTP URL failing to upgrade to HTTPS.
- **INFO:** Optional hardening or diagnostic signal without a universal security grade (CAA/COOP/email records, for example).
- **SKIP:** The check wasn't applicable or the user didn't provide a target/path.

Severity is a **starting point for discussion**, not CVSS. A missing optional `security.txt` or COOP must not be reported as a critical vulnerability. Likewise, a `200` for `/config.json` requires reading the contents and deciding whether they're actually sensitive—it isn't definitive proof of exposure.

**Explicit limitations:** This tool does not validate DNSSEC chains, scan open ports, fuzz parameters, brute-force logins, test real credential flows, inspect the Cloudflare account, assess server-side source code, verify mail delivery, certify accessibility, or prove compliance. Browser DOM/script-execution policy and TLS posture should receive independent browser and professional scanner checks.

### Scope and request safety

- The default audit performs ordinary GETs and public DNS resolver requests. No real form submissions.
- Full mode sends deliberately invalid JSON / unsupported content-type / cross-origin test requests only to explicitly named APIs. Community mode classifies the observed response rather than assuming Byson-specific HTTP codes. Invalid POST bodies are designed to be harmless, but **cannot guarantee zero side effects** for arbitrary APIs. Review the endpoint contract and obtain authorization first.
- HTTP-only sites **never receive POST probes**, even in Full mode.
- Avoid using `-Full` unless you have explicit permission to test the specific API. Failed form requests may still generate WAF alerts or access logs.
- If a hostname's homepage redirects outside its apex/www base, the tool refuses to audit the discovered destination. The initial redirect discovery request may still contact that endpoint; review third-party redirects before testing.
- A public report includes domain names, status codes, and response metadata. Review and redact reports before publishing.

## Suggested repository layout

```
Invoke-WebSecurityReview.ps1
Test-WebAudit-Syntax.ps1
README.md
COMMUNITY-GUIDE.md
MANUAL-CHECKLIST.md
CHANGELOG.md
.gitignore
```

Keep `reports/` out of Git. Add the Byson-only launcher to a private folder or optional production distribution.

[OWASP Secure Headers](https://owasp.org/www-project-secure-headers/) · [OWASP API Security](https://owasp.org/API-Security/) · [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

*Byson Cyber — Into the Storm 🦬*

### v1.2.3 Windows PowerShell compatibility fix

The initial v1.2.0 package used Unicode punctuation without a BOM in its `.ps1` file, which Windows PowerShell 5.1 may misinterpret and reject during parsing. In v1.2.3 all PowerShell script text is ASCII-safe, and scripts are encoded UTF-8 with BOM using Windows line endings. No website deployment or Cloudflare configuration changes are required.

If replacing an earlier ZIP, overwrite **all `.ps1` files** and run `Test-WebAudit-Syntax.ps1` locally first.

### v1.2.3 - API target safety and portable Full results

Full requires explicit valid API paths and fails fast on tutorial placeholders. Unknown/missing endpoints are not sent POSTs. Results distinguish method rejection, unavailable endpoints, rate limiting, and rejected invalid payloads. Configurable strict HTTP expectations preserve the Byson production regression suite.

**For a public GitHub release:** choose and add an explicit open-source license (for example, MIT) before inviting community reuse or contributions; no license is granted implicitly by these ZIPs.

### v1.2.3 - Beginner-friendly interactive setup

Running the community tool with no parameters launches a guided questionnaire for domain, Standard/Deep/Full scan type, API path selection only when appropriate, permission confirmation, and optional report export. Choosing Full without actual API endpoints (or declining POST authorization) gracefully falls back to Deep. Supplying `-SiteUrl` continues to run without prompts for CI, scripts, or the Byson production launcher.
