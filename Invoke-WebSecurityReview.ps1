#Requires -Version 5.1
<#
.SYNOPSIS
  Read-only-by-default website configuration review for authorized sites.
.DESCRIPTION
  No parameters starts a guided, beginner-friendly questionnaire. Accepts a
  hostname, an HTTPS origin, or an HTTP origin. Standard checks
  common controls; Deep adds diagnostics; Full adds authorized, paced invalid
  API POST checks only when -ApiPaths are provided. HTTP-only sites receive
  a clear FAIL for HTTPS and never receive API POST tests.
.EXAMPLE
 .\Invoke-WebSecurityReview.ps1 -SiteUrl deltarealtyllc.com
.EXAMPLE
  .\Invoke-WebSecurityReview.ps1 -SiteUrl http://example.com -ExportPrefix .\reports\example
.EXAMPLE
  .\Invoke-WebSecurityReview.ps1 -SiteUrl https://www.example.com -Deep -ApexHost example.com
.EXAMPLE
  .\Invoke-WebSecurityReview.ps1 -SiteUrl https://www.example.com -Full -ApiPaths @('/api/contact')
.EXAMPLE
  .\Invoke-WebSecurityReview.ps1
  # Guided setup; accepts domain, scan type, API paths and report preference.
.NOTES
  v1.2.4 | Byson Cyber | Into the Storm
  NOT a penetration test. Only test domains you own or are authorized to assess.
#>
[CmdletBinding()]
param(
    [string]$SiteUrl = '',
    [string[]]$Pages = @('/', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt'),
    [string[]]$DnsDomains = @(),
    [string[]]$AliasDomains = @(),
    [string]$ApexHost = '',
    [string]$ExpectedCAAIssuer = '',
    [string]$ExpectedCAAReport = '',
    [string]$RedirectTestPath = '/?audit=1',
    [ValidateRange(0,2147483647)][int]$MinHstsSeconds = 31536000,
    [switch]$RequirePreload,
    [switch]$RequireSubdomains,
    [switch]$ExpectNoHomepageCookies,
    [switch]$ExpectTLS13Only,
    [string[]]$ApiPaths = @(),
    [switch]$IncludeApiNegativeTests,
    [ValidateRange(11,120)][int]$ApiDelaySeconds = 11,
    [string]$ExportPrefix = '',
    [ValidateSet('Standard','Deep','Full')][string]$Mode = 'Standard',
    [switch]$Deep,
    [switch]$Full,
    [switch]$ShowAllGuidance,
    # 0 means observe-and-classify (community default). Nonzero values enable
    # site-specific exact status expectations, as used by Byson Cyber.
    [ValidateRange(0,599)][int]$ExpectedApiGetStatus = 0,
    [ValidateRange(0,599)][int]$ExpectedApiCrossOriginStatus = 0,
    [ValidateRange(0,599)][int]$ExpectedApiMalformedJsonStatus = 0,
    [ValidateRange(0,599)][int]$ExpectedApiUnsupportedMediaTypeStatus = 0,
    [switch]$RequireApiNoStore
)

$ErrorActionPreference = 'Stop'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:RequestCount = 0
$script:CurlExecutable = ''
$script:AuditMode = 'Standard'

# With no target supplied, use the guided setup. Explicit -SiteUrl calls remain
# non-interactive for scripting, CI, and the separate Byson production preset.
$wizardStarted = [string]::IsNullOrWhiteSpace($SiteUrl)
if ($Deep -and $Full) { throw 'Use either -Deep or -Full, not both.' }
if ($wizardStarted) {
    Write-Host ''
    Write-Host 'BYSON CYBER - GUIDED WEBSITE SECURITY REVIEW' -ForegroundColor Cyan
    Write-Host 'Welcome! This assistant helps you run a low-impact review.'
    Write-Host 'Only assess websites you own or have permission to test.' -ForegroundColor Yellow
    Write-Host 'Press Q at the domain or scan selection prompt to cancel.'
    Write-Host ''

    # Validate basic URL syntax locally before asking permission or making any request.
    while ($true) {
        $answer = ([string](Read-Host '1. What website/domain should we review? (example.com)')).Trim()
        if ($answer -match '^(?i:q|quit|exit)$') { Write-Host 'Audit cancelled. No requests sent.'; return }
        $candidate = $answer
        if ($candidate -and $candidate -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $candidate = "https://$candidate" }
        $testUri = $null
        $valid = ($candidate -and [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$testUri))
        if ($valid) {
            $valid = $testUri.Scheme -in @('http','https') -and
                     -not [string]::IsNullOrWhiteSpace($testUri.Host) -and
                     [string]::IsNullOrEmpty($testUri.UserInfo) -and
                     $testUri.AbsolutePath -eq '/' -and
                     [string]::IsNullOrEmpty($testUri.Query) -and
                     [string]::IsNullOrEmpty($testUri.Fragment)
        }
        if ($valid) { $SiteUrl = $answer; break }
        Write-Host 'Enter a domain only (e.g. example.com, http://example.com, or https://example.com).' -ForegroundColor Yellow
        Write-Host 'Do not include a page path, query, credentials, or fragment.'
    }

    # Skip scan selection if the caller specified a mode switch but omitted SiteUrl.
    if (-not $PSBoundParameters.ContainsKey('Mode') -and -not $Deep -and -not $Full -and -not $IncludeApiNegativeTests) {
        Write-Host ''
        Write-Host '2. What type of review do you want?' -ForegroundColor Cyan
        Write-Host '  [1] Standard (recommended first) - HTTPS, headers, redirects, public files; GET only.'
        Write-Host '  [2] Deep - Standard plus more TLS, DNS, CSP, HTML, and exposure checks; GET only.'
        Write-Host '  [3] Full - Deep plus intentionally invalid POST requests to your approved APIs.'
        while ($true) {
            $selection = ([string](Read-Host 'Choose 1, 2, or 3 [default: 1]')).Trim().ToLowerInvariant()
            if ($selection -in @('','1','standard','s')) { $Mode = 'Standard'; break }
            if ($selection -in @('2','deep','d')) { $Mode = 'Deep'; break }
            if ($selection -in @('3','full','f')) { $Mode = 'Full'; break }
            if ($selection -in @('q','quit','exit')) { Write-Host 'Audit cancelled. No requests sent.'; return }
            Write-Host 'Please choose 1, 2, or 3.' -ForegroundColor Yellow
        }
    }
    # Honor -Deep/-Full aliases before checking whether Full requires API paths.
    if ($Deep) { $Mode = 'Deep' }
    if ($Full -or $IncludeApiNegativeTests) { $Mode = 'Full' }

    if ($Mode -eq 'Full') {
        Write-Host ''
        Write-Host '3. API tests (Full mode)' -ForegroundColor Cyan
        Write-Host 'Full performs a few deliberately invalid POSTs against named HTTPS API paths.'
        Write-Host 'Invalid requests can still create logs, alerts, or side effects on some systems.' -ForegroundColor Yellow
        Write-Host 'No API paths? Choose Deep instead. You can run Full later with -ApiPaths.'
        if (@($ApiPaths).Count -eq 0) {
            $knowPaths = ([string](Read-Host 'Do you know the real API paths you are approved to test? [y/N]')).Trim()
            if ($knowPaths -notmatch '^(?i:y|yes)$') {
                $Mode = 'Deep'
                Write-Host 'Switching to Deep (no POST requests).' -ForegroundColor Green
            } else {
                while ($true) {
                    $rawPaths = ([string](Read-Host 'Enter API paths separated by commas (example: /api/contact)')).Trim()
                    if ($rawPaths -match '^(?i:q|quit|exit)$') { $Mode = 'Deep'; Write-Host 'Switching to Deep.'; break }
                    $entries = @($rawPaths -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $validPaths = $entries.Count -gt 0
                    foreach ($item in $entries) {
                        if (-not $item.StartsWith('/') -or $item.StartsWith('//') -or
                            $item -match '[\<>`"''?\#\s{}]' -or
                            $item -match '(?i)(your[-_ ]|placeholder|example|replace[-_ ]|actual[-_ ]api|TODO|/test[-_ ]endpoint)' -or
                            $item -match '(?i)%(?:2f|5c|2e|00|0a|0d)' -or
                            $item -match '/\.{1,2}(?:/|$)') { $validPaths = $false; break }
                    }
                    if ($validPaths) { $ApiPaths = $entries | Select-Object -Unique; break }
                    Write-Host 'Provide one or more real same-site paths beginning with / (no placeholders, query or fragments).' -ForegroundColor Yellow
                }
            }
        }
        if ($Mode -eq 'Full') {
            $approval = ([string](Read-Host 'Type YES (any capitalization) to confirm authorization for invalid API POSTs')).Trim()
            if ($approval -notmatch '^(?i:yes)$') {
                Write-Host 'Authorization not confirmed. Switching to Deep (no POST requests).' -ForegroundColor Yellow
                $Mode = 'Deep'
                $ApiPaths = @()
            }
        }
    }

    Write-Host ''
    Write-Host "Selected: $SiteUrl | $Mode" -ForegroundColor Cyan
    $permission = ([string](Read-Host 'Do you own or have permission to test this website? [y/N]')).Trim()
    if ($permission -notmatch '^(?i:y|yes)$') {
        Write-Host 'Audit cancelled. No requests sent.' -ForegroundColor Yellow
        return
    }

    if (-not $PSBoundParameters.ContainsKey('ExportPrefix')) {
        $saveLabel = if ($Mode -eq 'Full') { '4' } else { '3' }
        $save = ([string](Read-Host "$saveLabel. Save an HTML, CSV, and JSON report? [Y/n]")).Trim()
        if (-not $save -or $save -match '^(?i:y|yes)$') {
            $safeName = ([Uri]$candidate).Host -replace '[^A-Za-z0-9.-]', '_'
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $ExportPrefix = Join-Path $PSScriptRoot "reports/$safeName-$Mode-$stamp"
            Write-Host "Reports will be saved under: $($PSScriptRoot)\reports" -ForegroundColor Green
        }
    }
    Write-Host ''
    Write-Host "Running $Mode review..." -ForegroundColor Cyan
    if ($Mode -eq 'Full') {
        $pathExample = '@(' + (($ApiPaths | ForEach-Object { "'" + $_ + "'" }) -join ',') + ')'
        Write-Host "Tip for next time: .\Invoke-WebSecurityReview.ps1 -SiteUrl '$SiteUrl' -Full -ApiPaths $pathExample"
    } else {
        Write-Host "Tip for next time: .\Invoke-WebSecurityReview.ps1 -SiteUrl '$SiteUrl' -Mode $Mode"
    }
}

# Global mode selection. -Deep/-Full are friendly alternatives to -Mode.
if (-not $wizardStarted) {
    if ($Deep) { $Mode = 'Deep' }
    if ($Full) { $Mode = 'Full' }
    if ($IncludeApiNegativeTests) { $Mode = 'Full' } # Backward-compatible v1.1 flag
}
$script:AuditMode = $Mode
$script:IsExtended = $Mode -in @('Deep','Full')
# Validate *all* API paths before any HTTP/DNS request. Full mode requires an
# explicitly named endpoint. Never probe a tutorial placeholder by mistake.
if ($Mode -eq 'Full' -and @($ApiPaths).Count -eq 0) {
    throw 'Full mode requires at least one real -ApiPaths entry. Use -Deep if you do not have an approved API endpoint.'
}
foreach ($apiPath in @($ApiPaths)) {
    if ([string]::IsNullOrWhiteSpace($apiPath) -or
        -not $apiPath.StartsWith('/') -or $apiPath.StartsWith('//') -or
        $apiPath -match '[\\<>`"''?\#\s{}]' -or
        $apiPath -match '(?i)(your[-_ ]|placeholder|example|replace[-_ ]|actual[-_ ]api|TODO|/test[-_ ]endpoint)' -or
        $apiPath -match '(?i)%(?:2f|5c|2e|00|0a|0d)' -or
        $apiPath -match '/\.{1,2}(?:/|$)') {
        throw "Invalid or placeholder API path '$apiPath'. Specify a real, same-site path such as /api/contact (no query string, fragment, traversal or example tokens)."
    }
}
foreach ($expected in @($ExpectedApiGetStatus,$ExpectedApiCrossOriginStatus,$ExpectedApiMalformedJsonStatus,$ExpectedApiUnsupportedMediaTypeStatus)) {
    if ($expected -ne 0 -and $expected -lt 100) { throw 'Expected API HTTP status must be 0 (observational) or between 100 and 599.' }
}


function Get-Guidance {
    param([string]$Area, [string]$Check, [string]$Status)
    $severity = if ($Status -eq 'FAIL') { 'High' } elseif ($Status -eq 'WARN') { 'Low' } else { 'None' }
    $why = 'Configuration observations are a snapshot; results require context.'
    $fix = 'Review whether the observed behavior matches this application''s intended design.'
    $reference = 'https://owasp.org/www-project-web-security-testing-guide/'
    switch ($Area) {
        'Transport' { $why='HTTPS protects confidentiality and transport integrity.'; $fix='Use a publicly trusted certificate, redirect HTTP to HTTPS, and test hostname/certificate coverage.'; $reference='https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Transport_Layer_Security' }
        'TLS' { $why='TLS negotiation determines which protocol versions clients can use.'; $fix='Confirm accepted TLS versions match client compatibility and risk requirements; test with another TLS scanner.'; $reference='https://www.ssllabs.com/ssltest/' }
        'Headers' { $why='Browser response headers can reduce the impact of certain web attacks.'; $fix='Review header values with the application''s integrations and browsers before changing enforcement.'; $reference='https://owasp.org/www-project-secure-headers/' }
        'Redirects' { $why='A consistent HTTPS canonical URL reduces downgrade exposure and URL duplication.'; $fix='Verify every intended hostname upgrades to HTTPS and preserves relevant paths and queries.'; $reference='https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections' }
        'Exposure' { $why='Accidentally published build and configuration files may reveal sensitive information.'; $fix='Keep internal files outside the public directory, and verify routes do not expose them.'; $reference='https://owasp.org/www-project-web-security-testing-guide/' }
        'DNS' { $why='DNS records support issuance controls, email authentication and operational visibility.'; $fix='Treat DNS results as advisory and verify with authoritative records before updating production.'; $reference='https://developer.mozilla.org/en-US/docs/Glossary/CAA' }
        'API' { $why='Server-side APIs must validate requests and protect any sensitive responses.'; $fix='Validate methods, types, origins, size limits, and cache policies for the specific API design.'; $reference='https://owasp.org/API-Security/' }
        'Browser' { $why='External scripts and browser resource choices can affect trust and CSP behavior.'; $fix='Review unexpected third-party scripts and loading sources with browser DevTools.'; $reference='https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' }
        'Disclosure' { $why='security.txt helps researchers find a responsible disclosure contact.'; $fix='Maintain a reachable contact and a current Expires date; this file is optional.'; $reference='https://www.rfc-editor.org/rfc/rfc9116' }
        'SEO' { $why='Indexing directives affect discoverability, not website security.'; $fix='Check crawler directives and Search Console for unintended indexing restrictions.'; $reference='https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag' }
        'Routes' { $why='Public routes should return the behavior the site owner intended.'; $fix='Check missing pages, redirects, WAF challenges, and intentionally absent optional pages.'; $reference='https://developer.mozilla.org/en-US/docs/Web/HTTP/Status' }
        'Content' { $why='Page markup and assets can reveal broken references, unwanted third parties or mixed content.'; $fix='Inspect identified resources manually in browser Network and Console tools.'; $reference='https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content' }
    }
    if ($Check -match 'CAA') {
        $severity='None'
        $why='CAA is an optional control restricting which certificate authorities may issue certificates.'
        $fix='Review authorized CA providers and renewal requirements before configuring CAA; absence alone is not a vulnerability.'
    }
    if ($Check -match 'opener policy|COOP') {
        $severity='None'
        $why='COOP isolates browsing contexts but may break integrations that open and communicate with popups.'
        $fix='Consider same-origin only if compatible with legitimate cross-origin windows; absence is not by itself an exploitable flaw.'
    }
    if ($Check -match 'security.txt') { $severity='None' }
    if ($Check -match 'TLS 1.2 allowed') { $severity='None' }
    if ($Check -match '^Nonpublic') { $severity = if ($Status -eq 'WARN') { 'Potentially high' } else { 'None' } }
    if ($Check -match 'HTTPS missing|Usable HTTPS missing') { $severity='High' }
    if ($Area -eq 'API' -and $Check -match 'endpoint not confirmed|API method|invalid request|rate limited') {
        $severity = if ($Status -eq 'WARN' -and $Check -match 'API invalid request') { 'Low' } else { 'None' }
        $why = 'HTTP status codes alone do not establish why an API rejected a request.'
        $fix = 'Verify the API route, application logs, WAF or authentication behavior, and the endpoint-specific contract. An unexpected status is not automatically a vulnerability.'
    }
    return [pscustomobject]@{ Severity=$severity; Why=$why; Recommendation=$fix; Reference=$reference }
}


function Add-Finding {
    param([string]$Area, [string]$Check,
          [ValidateSet('PASS','WARN','FAIL','INFO','SKIP')][string]$Status,
          [string]$Details)
    $guide=Get-Guidance -Area $Area -Check $Check -Status $Status
    $script:Findings.Add([pscustomobject]@{
        Area=$Area; Check=$Check; Result=$Status; Severity=$guide.Severity
        Details=$Details; Why=$guide.Why; Recommendation=$guide.Recommendation; Reference=$guide.Reference
    })
}

function Get-HeaderValue {
    param([object]$Response, [string]$Name)
    if ($null -eq $Response) { return '' }
    $key = $Name.ToLowerInvariant()
    if ($Response.Headers.ContainsKey($key)) { return [string]$Response.Headers[$key] }
    return ''
}

function Invoke-HttpProbe {
    param([Parameter(Mandatory=$true)][string]$Url,
          [ValidateSet('GET','POST','HEAD')][string]$Method='GET',
          [string[]]$RequestHeaders=@(),
          [AllowEmptyString()][string]$Body,
          [switch]$FollowRedirects,
          [switch]$ReadBody,
          [string[]]$ExtraCurlArgs=@())
    $headerFile = [System.IO.Path]::GetTempFileName()
    $contentFile = [System.IO.Path]::GetTempFileName()
    try {
        $curlArgs = @('-sS','--connect-timeout','6','--max-time','22','--max-filesize','4194304',
                      '--proto', '=http,https','--proto-redir','=http,https',
                      '--max-redirs','6','-D',$headerFile,'-o',$contentFile,
                      '-w','%{http_code}|%{url_effective}|%{num_redirects}')
        if ($FollowRedirects) { $curlArgs += '-L' }
        if ($Method -ne 'GET') { $curlArgs += @('-X',$Method) }
        foreach ($h in $RequestHeaders) { $curlArgs += @('-H',$h) }
        if ($PSBoundParameters.ContainsKey('Body')) { $curlArgs += @('--data-raw',$Body) }
        if ($ExtraCurlArgs.Count -gt 0) { $curlArgs += $ExtraCurlArgs }
        $curlArgs += $Url # Append ONCE. Curl should never request the same URL twice.
        $script:RequestCount++
        $raw = & $script:CurlExecutable @curlArgs 2>$null
        $curlExit = $LASTEXITCODE
        $parts = ([string]($raw -join "`n")) -split '\|', 3
        $status = 0
        if ($parts.Count -gt 0) { [void][int]::TryParse($parts[0].Trim(), [ref]$status) }
        $headers = @{}
        if (Test-Path -LiteralPath $headerFile) {
            foreach ($line in (Get-Content -LiteralPath $headerFile -ErrorAction SilentlyContinue)) {
                # Handle proxy CONNECT and redirect responses: only final block matters.
                if ($line -match '^HTTP/\S+\s+\d{3}') { $headers=@{}; continue }
                if ($line -match '^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$') {
                    $key=$Matches[1].ToLowerInvariant(); $value=$Matches[2].Trim()
                    if ($headers.ContainsKey($key)) { $headers[$key] += ", $value" }
                    else { $headers[$key] = $value }
                }
            }
        }
        $content = ''
        if ($ReadBody -and (Test-Path -LiteralPath $contentFile)) {
            $content = [string](Get-Content -LiteralPath $contentFile -Raw -ErrorAction SilentlyContinue)
        }
        return [pscustomobject]@{
            Status=$status; ExitCode=$curlExit; Headers=$headers
            FinalUrl= $(if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' })
            Hops= $(if ($parts.Count -gt 2) { $parts[2].Trim() } else { '' })
            Content=$content
        }
    } finally {
        Remove-Item -LiteralPath $headerFile,$contentFile -Force -ErrorAction SilentlyContinue
    }
}

function Get-DnsJson {
    param([string]$Domain, [string]$Type, [string]$Provider)
    $encoded = [System.Uri]::EscapeDataString($Domain)
    $url = if ($Provider -eq 'Cloudflare') {
        "https://cloudflare-dns.com/dns-query?name=$encoded&type=$Type"
    } else { "https://dns.google/resolve?name=$encoded&type=$Type" }
    Invoke-RestMethod -Uri $url -Headers @{Accept='application/dns-json'} -TimeoutSec 15 -ErrorAction Stop
}

function Test-FinalRedirect {
    param([string]$Candidate,[string]$ExpectedHost,[string]$ExpectedPath)
    $candidateUri=$null; $wanted=$null
    if (-not [Uri]::TryCreate($Candidate,[UriKind]::Absolute,[ref]$candidateUri)) { return $false }
    if (-not [Uri]::TryCreate("https://$ExpectedHost$ExpectedPath",[UriKind]::Absolute,[ref]$wanted)) { return $false }
    return ($candidateUri.Scheme -eq 'https' -and $candidateUri.Host -eq $ExpectedHost -and
            $candidateUri.PathAndQuery -eq $wanted.PathAndQuery)
}

function Get-OriginFromFinalUrl {
    param([string]$Url)
    $parsed=$null
    if (-not [Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$parsed)) { return '' }
    if ($parsed.Scheme -notin @('http','https')) { return '' }
    return $parsed.GetLeftPart([UriPartial]::Authority).TrimEnd('/')
}

$inputText=$SiteUrl.Trim()
if ($inputText -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $inputText="https://$inputText" }
$inputUri=$null
if (-not [Uri]::TryCreate($inputText,[UriKind]::Absolute,[ref]$inputUri) -or
    $null -eq $inputUri -or $inputUri.Scheme -notin @('http','https') -or
    [string]::IsNullOrWhiteSpace($inputUri.Host) -or
    -not [string]::IsNullOrEmpty($inputUri.UserInfo) -or
    $inputUri.AbsolutePath -ne '/' -or
    -not [string]::IsNullOrEmpty($inputUri.Query) -or
    -not [string]::IsNullOrEmpty($inputUri.Fragment)) {
    throw 'SiteUrl must be a bare hostname, http://hostname, or https://hostname (no path, query, or credentials).'
}
if (-not $RedirectTestPath.StartsWith('/') -or $RedirectTestPath.StartsWith('//')) {
    throw 'RedirectTestPath must be a relative path beginning with a single /.'
}
$curlCommand=Get-Command 'curl.exe' -CommandType Application -ErrorAction SilentlyContinue
if (-not $curlCommand) { $curlCommand=Get-Command 'curl' -CommandType Application -ErrorAction SilentlyContinue }
if (-not $curlCommand) { throw 'Command-line curl was not found. Install curl to run this audit.' }
$script:CurlExecutable=$curlCommand.Source

Write-Host "`nBYSON CYBER - COMMUNITY WEB SECURITY REVIEW v1.2.3" -ForegroundColor Cyan
Write-Host "Input: $SiteUrl" -ForegroundColor Cyan
Write-Host "Audit mode: $Mode" -ForegroundColor Cyan
Write-Host 'Default mode: ordinary GET requests and public DNS queries.'
if ($Mode -eq 'Full') {
    Write-Host 'FULL MODE: only approved API paths receive deliberately invalid POSTs (HTTPS only).' -ForegroundColor Yellow
    Write-Host "Requests are spaced by at least $ApiDelaySeconds seconds; no valid form data is sent." -ForegroundColor Yellow
}

# Discover actual working origin, without assuming every site supports HTTPS.
# If an apex redirects to www, use the redirect destination as the canonical
# audit origin. A homepage redirect may legitimately change hosts: only test
# sites you own or have explicit authorization to assess.
$inputHost=$inputUri.Host
$httpsProbe=Invoke-HttpProbe -Url "https://$inputHost/" -FollowRedirects
$httpsFinalOrigin=Get-OriginFromFinalUrl $httpsProbe.FinalUrl
$httpsUsable=$httpsProbe.ExitCode -eq 0 -and $httpsProbe.Status -ge 100 -and
             $httpsFinalOrigin.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)
$httpProbe=$null
$usingHttpOnly=$false
$targetOrigin=''
if ($httpsUsable) {
    $targetOrigin=$httpsFinalOrigin
    if ($inputUri.Scheme -eq 'http') {
        Add-Finding 'Transport' 'HTTP input upgraded for audit' 'INFO' "HTTPS available: $targetOrigin"
    }
} else {
    $httpProbe=Invoke-HttpProbe -Url "http://$inputHost/" -FollowRedirects
    $httpFinalOrigin=Get-OriginFromFinalUrl $httpProbe.FinalUrl
    $httpUsable=$httpProbe.ExitCode -eq 0 -and $httpProbe.Status -ge 100 -and -not [string]::IsNullOrEmpty($httpFinalOrigin)
    if ($httpUsable) {
        $targetOrigin=$httpFinalOrigin
        $usingHttpOnly=$targetOrigin.StartsWith('http://',[StringComparison]::OrdinalIgnoreCase)
    } else {
        Add-Finding 'Transport' 'Site reachable' 'FAIL' "Neither HTTPS nor HTTP connected: HTTPS curl=$($httpsProbe.ExitCode), HTTP curl=$($httpProbe.ExitCode)"
    }
}

# Do not silently start auditing an unrelated domain after a redirect. The
# input host and its www/apex counterpart are within the default scope. For
# other destinations, provide the intended canonical host explicitly.
if ($targetOrigin) {
    $discoveredHost=([Uri]$targetOrigin).Host
    $requestedBase=($inputHost -replace '^(?i)www\.','').ToLowerInvariant()
    $discoveredBase=($discoveredHost -replace '^(?i)www\.','').ToLowerInvariant()
    if ($requestedBase -ne $discoveredBase) {
        Add-Finding 'Scope' 'Redirect destination' 'FAIL' "Input $inputHost redirected to $discoveredHost. Specify the authorized destination explicitly."
        Write-Warning "Redirect to a different hostname ($discoveredHost); skipping remaining site probes."
        $targetOrigin=''
    }
}

if ($targetOrigin) {
    $canonicalUri=[Uri]$targetOrigin
    $canonicalHost=$canonicalUri.Host
    $secureSite=$canonicalUri.Scheme -eq 'https'
    Write-Host "Audit origin: $targetOrigin" -ForegroundColor $(if ($secureSite) { 'Green' } else { 'Yellow' })
    if ($secureSite) {
        Add-Finding 'Transport' 'HTTPS available' 'PASS' "TLS-connected site: $targetOrigin"
        if ($httpsProbe.Status -ge 400) {
            Add-Finding 'Transport' 'Homepage HTTPS status' 'WARN' "HTTP $($httpsProbe.Status) (could be WAF/auth/application behavior)"
        }
    } else {
        Add-Finding 'Transport' 'Usable HTTPS missing' 'FAIL' "HTTP works, but the HTTPS probe did not establish a valid secure site (curl exit $($httpsProbe.ExitCode); HTTP status $($httpsProbe.Status)). Check certificate, TLS, and redirects."
        Write-Warning 'NO VERIFIED HTTPS: continuing public read-only checks; API POSTs and TLS checks will be skipped.'
    }

    # Static/public routes.
    foreach ($p in ($Pages | Select-Object -Unique)) {
        if (-not $p.StartsWith('/') -or $p.StartsWith('//')) { throw "Invalid Pages entry: $p" }
        $route=Invoke-HttpProbe -Url "$targetOrigin$p" -FollowRedirects
        if ($route.ExitCode -ne 0) { Add-Finding 'Routes' "Public $p" 'WARN' "curl exit $($route.ExitCode); HTTP $($route.Status)" }
        elseif ($route.Status -eq 200) { Add-Finding 'Routes' "Public $p" 'PASS' 'HTTP 200' }
        elseif ($p -eq '/') { Add-Finding 'Routes' 'Homepage reachable' 'FAIL' "HTTP $($route.Status)" }
        else { Add-Finding 'Routes' "Optional page $p" 'WARN' "HTTP $($route.Status); may be intentional" }
    }

    # security.txt: optional for community sites; check RFC 9116 basics when present.
    $disclosure=Invoke-HttpProbe -Url "$targetOrigin/.well-known/security.txt" -ReadBody
    if ($disclosure.ExitCode -eq 0 -and $disclosure.Status -eq 200) {
        $hasContact=$disclosure.Content -match '(?im)^Contact:\s*(mailto:|https://)'
        Add-Finding 'Disclosure' 'security.txt contact' $(if ($hasContact) { 'PASS' } else { 'WARN' }) 'Expected contact: mailto: or https: URL'
        $expiryMatch=[regex]::Match($disclosure.Content,'(?im)^Expires:\s*(\S+)')
        $expiryDate=[DateTimeOffset]::MinValue
        $validExpiry=$expiryMatch.Success -and [DateTimeOffset]::TryParse($expiryMatch.Groups[1].Value,[ref]$expiryDate)
        $isFresh=$validExpiry -and $expiryDate -gt [DateTimeOffset]::UtcNow
        Add-Finding 'Disclosure' 'security.txt expiration' $(if ($isFresh) { 'PASS' } else { 'WARN' }) $(if ($validExpiry) { "Expires $($expiryDate.ToString('u'))" } else { 'Missing/invalid Expires' })
    } else { Add-Finding 'Disclosure' 'security.txt' 'INFO' 'Optional disclosure file not present' }

    $homepageResponse=Invoke-HttpProbe -Url "$targetOrigin/" -FollowRedirects -ReadBody
    if ($homepageResponse.ExitCode -ne 0 -or $homepageResponse.Status -ne 200) {
        Add-Finding 'Headers' 'Homepage header inspection' 'WARN' "HTTP $($homepageResponse.Status); curl=$($homepageResponse.ExitCode)"
    } else {
        $hsts=Get-HeaderValue $homepageResponse 'strict-transport-security'
        if ($secureSite) {
            $ageMatch=[regex]::Match($hsts,'(?i)(?:^|;)\s*max-age\s*=\s*(\d+)')
            $age=[long]0
            if ($ageMatch.Success) { [void][long]::TryParse($ageMatch.Groups[1].Value,[ref]$age) }
            Add-Finding 'Headers' 'HSTS minimum duration' $(if ($age -ge $MinHstsSeconds) { 'PASS' } else { 'WARN' }) "max-age=$age; target>=$MinHstsSeconds"
            if ($RequireSubdomains) { Add-Finding 'Headers' 'HSTS includeSubDomains' $(if ($hsts -match '(?i)(^|;)\s*includeSubDomains\b') { 'PASS' } else { 'WARN' }) $hsts }
            if ($RequirePreload) { Add-Finding 'Headers' 'HSTS preload directive' $(if ($hsts -match '(?i)(^|;)\s*preload\b') { 'PASS' } else { 'WARN' }) $hsts }
        } else {
            Add-Finding 'Headers' 'HSTS' 'SKIP' 'HSTS delivered on HTTP cannot be trusted; HTTPS is required.'
        }
        $csp=Get-HeaderValue $homepageResponse 'content-security-policy'
        Add-Finding 'Headers' 'CSP present' $(if ($csp) { 'PASS' } else { 'WARN' }) $(if ($csp) { 'CSP supplied' } else { 'No Content-Security-Policy header' })
        if ($csp) {
            Add-Finding 'Headers' 'CSP object-src none' $(if ($csp -match "(?i)(^|;)\s*object-src\s+'none'") { 'PASS' } else { 'WARN' }) 'Review object-src restrictions'
            Add-Finding 'Headers' 'CSP frame-ancestors' $(if ($csp -match '(?i)(^|;)\s*frame-ancestors\s+') { 'PASS' } else { 'WARN' }) 'Review framing rules'
            Add-Finding 'Headers' 'CSP base-uri' $(if ($csp -match '(?i)(^|;)\s*base-uri\s+') { 'PASS' } else { 'WARN' }) 'Review base URI restrictions'
            Add-Finding 'Headers' 'No unsafe-eval' $(if ($csp -notmatch "(?i)'unsafe-eval'") { 'PASS' } else { 'WARN' }) 'Review script-src'
        }
        $nosniff=Get-HeaderValue $homepageResponse 'x-content-type-options'
        Add-Finding 'Headers' 'MIME sniffing disabled' $(if ($nosniff -eq 'nosniff') { 'PASS' } else { 'WARN' }) "X-Content-Type-Options: $nosniff"
        $frame=Get-HeaderValue $homepageResponse 'x-frame-options'
        Add-Finding 'Headers' 'Frame protection' $(if ($frame -match '^(DENY|SAMEORIGIN)$') { 'PASS' } elseif ($csp -match '(?i)frame-ancestors') { 'INFO' } else { 'WARN' }) "X-Frame-Options: $frame"
        $referrer=Get-HeaderValue $homepageResponse 'referrer-policy'
        Add-Finding 'Headers' 'Referrer policy' $(if ($referrer -match '(?i)^(no-referrer|same-origin|strict-origin|strict-origin-when-cross-origin)$') { 'PASS' } else { 'WARN' }) "Referrer-Policy: $referrer"
        $coop=Get-HeaderValue $homepageResponse 'cross-origin-opener-policy'
        Add-Finding 'Headers' 'Cross-origin opener policy' $(if ($coop -eq 'same-origin') { 'PASS' } else { 'INFO' }) "COOP: $coop"
        $permissions=Get-HeaderValue $homepageResponse 'permissions-policy'
        Add-Finding 'Headers' 'Permissions-Policy' $(if ($permissions) { 'PASS' } else { 'INFO' }) $(if ($permissions) { 'Present' } else { 'Not defined' })
        $xss=Get-HeaderValue $homepageResponse 'x-xss-protection'
        Add-Finding 'Headers' 'Legacy XSS auditor off' $(if ($xss -eq '0' -or -not $xss) { 'PASS' } else { 'WARN' }) "X-XSS-Protection: $xss"
        $powered=Get-HeaderValue $homepageResponse 'x-powered-by'
        Add-Finding 'Headers' 'No X-Powered-By disclosure' $(if (-not $powered) { 'PASS' } else { 'INFO' }) $(if ($powered) { $powered } else { 'Absent' })
        if ($ExpectNoHomepageCookies) {
            $setCookie=Get-HeaderValue $homepageResponse 'set-cookie'
            Add-Finding 'Headers' 'No homepage Set-Cookie' $(if (-not $setCookie) { 'PASS' } else { 'WARN' }) $(if ($setCookie) { 'Cookie set; value hidden' } else { 'No Set-Cookie' })
        }
        if ($homepageResponse.Content -match '(?i)static\.cloudflareinsights\.com/beacon') {
            Add-Finding 'Browser' 'Cloudflare beacon injection' 'WARN' 'Detected; review CSP or analytics settings'
        } else { Add-Finding 'Browser' 'No injected Cloudflare analytics beacon' 'PASS' 'Not found in homepage HTML' }
        if ($homepageResponse.Content -match '(?i)<meta\s+[^>]*name\s*=\s*["'']robots["''][^>]*noindex') {
            Add-Finding 'SEO' 'Homepage noindex' 'WARN' 'Robots meta noindex detected'
        } else { Add-Finding 'SEO' 'No obvious homepage noindex' 'PASS' 'Heuristic only, not an indexing guarantee' }
    }

    if ($script:IsExtended -and $homepageResponse.ExitCode -eq 0 -and $homepageResponse.Status -eq 200) {
        $bodyText=[string]$homepageResponse.Content
        $contentType=Get-HeaderValue $homepageResponse 'content-type'
        Add-Finding 'Content' 'Homepage Content-Type HTML' $(if ($contentType -match '(?i)text/html') { 'PASS' } else { 'WARN' }) "Content-Type: $contentType"
        $langMatch=[regex]::Match($bodyText,'(?i)<html\b[^>]*\blang\s*=')
        Add-Finding 'Content' 'HTML language attribute' $(if ($langMatch.Success) { 'PASS' } else { 'INFO' }) 'Attribute presence only; not an accessibility certification'
        $hasTitle=$bodyText -match '(?is)<title\b[^>]*>\s*[^<\s][^<]*</title>'
        Add-Finding 'Content' 'HTML document title' $(if ($hasTitle) { 'PASS' } else { 'WARN' }) 'Nonempty <title> detected'
        $hasViewport=$bodyText -match '(?is)<meta\s+[^>]*name\s*=\s*["'']viewport["'']'
        Add-Finding 'Content' 'Mobile viewport metadata' $(if ($hasViewport) { 'PASS' } else { 'INFO' }) 'Heuristic; not a mobile usability test'
        $canonicalLink=[regex]::Match($bodyText,'(?is)<link\s+[^>]*rel\s*=\s*["'']canonical["''][^>]*>')
        Add-Finding 'SEO' 'Canonical link declaration' $(if ($canonicalLink.Success) { 'PASS' } else { 'INFO' }) 'Review URL when present; absence can be intentional'
        $httpSources=[regex]::Matches($bodyText,'(?i)(?:\bsrc\s*=\s*["'']http://[^"'']+["'']|<link\b[^>]*\bhref\s*=\s*["'']http://[^"'']+["''])')
        Add-Finding 'Content' 'Absolute HTTP asset references' $(if ($httpSources.Count -eq 0) { 'PASS' } else { 'WARN' }) "matches=$($httpSources.Count); heuristic src/link markup only; browser confirmation needed"
        $jsInline=[regex]::Matches($bodyText,'(?is)<script\b(?![^>]*\bsrc\s*=)[^>]*>')
        Add-Finding 'Content' 'Inline script elements' 'INFO' "count=$($jsInline.Count); ensure nonce/hash or no inline JS when enforcing CSP"
        $extScripts=[regex]::Matches($bodyText,'(?i)<script\b[^>]*\bsrc\s*=\s*["'']https?://([^/"'']+)')
        Add-Finding 'Content' 'Absolute third-party script declarations' 'INFO' "count=$($extScripts.Count); browser instrumentation may differ"
        $cspReport=Get-HeaderValue $homepageResponse 'content-security-policy-report-only'
        Add-Finding 'Headers' 'CSP report-only policy' 'INFO' $(if ($cspReport) { 'Present; compare with enforced policy' } else { 'Not configured; optional' })
        $corPolicy=Get-HeaderValue $homepageResponse 'cross-origin-resource-policy'
        Add-Finding 'Headers' 'Cross-Origin-Resource-Policy' $(if ($corPolicy) { 'PASS' } else { 'INFO' }) $(if ($corPolicy) { $corPolicy } else { 'Absent; depends on shared-resource needs' })
        $embedPolicy=Get-HeaderValue $homepageResponse 'cross-origin-embedder-policy'
        Add-Finding 'Headers' 'Cross-Origin-Embedder-Policy' 'INFO' $(if ($embedPolicy) { $embedPolicy } else { 'Absent; isolation is application-dependent' })
        $serverHeader=Get-HeaderValue $homepageResponse 'server'
        Add-Finding 'Headers' 'Server header exposure' 'INFO' $(if ($serverHeader) { "Server: $serverHeader" } else { 'Absent' })
        $cspDeep=Get-HeaderValue $homepageResponse 'content-security-policy'
        if ($cspDeep) {
            foreach ($directive in @('default-src','script-src','form-action','upgrade-insecure-requests')) {
                $present=$cspDeep -match "(?i)(^|;)\s*$directive(?:\s|;|$)"
                Add-Finding 'Headers' "CSP $directive" $(if ($present) { 'PASS' } else { 'INFO' }) 'Presence only; review exact sources and app requirements'
            }
            Add-Finding 'Headers' 'CSP inline script allowance' $(if ($cspDeep -match "(?i)'unsafe-inline'") { 'INFO' } else { 'PASS' }) 'Check whether script-src has inline allowances; directive-level interpretation required'
            Add-Finding 'Headers' 'CSP Trusted Types policy' 'INFO' $(if ($cspDeep -match '(?i)require-trusted-types-for') { 'Directive present; verify application compatibility' } else { 'Not present; optional defense-in-depth, test before enabling' })
        }
        $cacheHtml=Get-HeaderValue $homepageResponse 'cache-control'
        Add-Finding 'Headers' 'Homepage Cache-Control' 'INFO' $(if ($cacheHtml) { $cacheHtml } else { 'Absent; public pages may be cacheable' })
        if ($secureSite) {
            $tls13=Invoke-HttpProbe -Url "$targetOrigin/" -ExtraCurlArgs @('--tlsv1.3','--tls-max','1.3')
            Add-Finding 'TLS' 'TLS 1.3 handshake (compatibility)' $(if ($tls13.ExitCode -eq 0 -and $tls13.Status -gt 0) { 'PASS' } else { 'WARN' }) "curl=$($tls13.ExitCode); HTTP=$($tls13.Status)"
            if (-not $ExpectTLS13Only) {
                $tls12=Invoke-HttpProbe -Url "$targetOrigin/" -ExtraCurlArgs @('--tlsv1.2','--tls-max','1.2')
                Add-Finding 'TLS' 'TLS 1.2 allowed (compatibility)' 'INFO' "curl=$($tls12.ExitCode); HTTP=$($tls12.Status); TLS 1.2 support is not automatically a flaw"
            }
        } else {
            Add-Finding 'TLS' 'Version negotiation' 'SKIP' 'HTTPS unavailable; no TLS protocol test possible'
        }
    }

    $httpRedirect=Invoke-HttpProbe -Url "http://$canonicalHost$RedirectTestPath" -FollowRedirects
    $redirectOk=$httpRedirect.ExitCode -eq 0 -and
                (Test-FinalRedirect $httpRedirect.FinalUrl $canonicalHost $RedirectTestPath)
    Add-Finding 'Redirects' 'HTTP upgrades to canonical HTTPS' $(if ($redirectOk) { 'PASS' } else { 'FAIL' }) "HTTP $($httpRedirect.Status); redirects=$($httpRedirect.Hops); final=$($httpRedirect.FinalUrl)"

    if ($ApexHost) {
        $apexRedirect=Invoke-HttpProbe -Url "https://$ApexHost$RedirectTestPath" -FollowRedirects
        $apexOk=$apexRedirect.ExitCode -eq 0 -and [int]$apexRedirect.Hops -ge 1 -and
                (Test-FinalRedirect $apexRedirect.FinalUrl $canonicalHost $RedirectTestPath)
        Add-Finding 'Redirects' 'Apex canonical redirect' $(if ($apexOk) { 'PASS' } else { 'WARN' }) "HTTP $($apexRedirect.Status); hops=$($apexRedirect.Hops); final=$($apexRedirect.FinalUrl)"
        $apexHeaders=Invoke-HttpProbe -Url "https://$ApexHost$RedirectTestPath"
        $apexHsts=Get-HeaderValue $apexHeaders 'strict-transport-security'
        $hasApexHsts=$apexHeaders.ExitCode -eq 0 -and $apexHeaders.Status -in @(301,302,307,308) -and $apexHsts -match '(?i)max-age=\d+'
        Add-Finding 'Headers' 'HSTS on HTTPS apex redirect' $(if ($hasApexHsts) { 'PASS' } else { 'WARN' }) "HTTP $($apexHeaders.Status); HSTS present=$([bool]$apexHsts)"
    }
    foreach ($alias in ($AliasDomains | Select-Object -Unique)) {
        foreach ($aliasHost in @($alias,"www.$alias")) {
            foreach ($scheme in @('http','https')) {
                $redirect=Invoke-HttpProbe -Url "${scheme}://$aliasHost$RedirectTestPath" -FollowRedirects
                $ok=$redirect.ExitCode -eq 0 -and [int]$redirect.Hops -ge 1 -and
                    (Test-FinalRedirect $redirect.FinalUrl $canonicalHost $RedirectTestPath)
                Add-Finding 'Redirects' "Alias ${scheme}://$aliasHost" $(if ($ok) { 'PASS' } else { 'WARN' }) "HTTP $($redirect.Status); hops=$($redirect.Hops); final=$($redirect.FinalUrl)"
            }
        }
    }

    # Fixed common accidental publish paths; not a full inventory or a vulnerability scan.
    $privatePaths=@('/.env','/.dev.vars','/.git/config','/.git/HEAD','/wrangler.jsonc',
                    '/package.json','/package-lock.json','/src/index.js','/backup.zip',
                    '/assets/site-v120.js.map')
    foreach ($path in $privatePaths) {
        $response=Invoke-HttpProbe -Url "$targetOrigin$path"
        $ok=$response.ExitCode -eq 0 -and $response.Status -in @(403,404,410)
        Add-Finding 'Exposure' "Nonpublic $path" $(if ($ok) { 'PASS' } else { 'WARN' }) "HTTP $($response.Status); curl=$($response.ExitCode)"
    }

    if ($script:IsExtended) {
        foreach ($path in @('/.DS_Store','/.npmrc','/config.json','/web.config','/phpinfo.php')) {
            $response=Invoke-HttpProbe -Url "$targetOrigin$path"
            $notExposed=$response.ExitCode -eq 0 -and $response.Status -in @(403,404,410)
            Add-Finding 'Exposure' "Nonpublic $path" $(if ($notExposed) { 'PASS' } else { 'WARN' }) "HTTP $($response.Status); a generic 200 or redirect requires manual content verification"
        }
    }

    # Public CAA from two independent recursive resolvers; do not assume a
    # resolver error means records are absent.
    $zones=@($DnsDomains)
    if ($zones.Count -eq 0) { $zones=@($inputHost) }
    foreach ($zone in ($zones | Select-Object -Unique)) {
        $resolverResults=@()
        foreach ($provider in @('Google','Cloudflare')) {
            try {
                $answer=Get-DnsJson -Domain $zone -Type 'CAA' -Provider $provider
                $records=@($answer.Answer | Where-Object { $_.type -eq 257 } | ForEach-Object { [string]$_.data })
                $issuerOK=$false; $reportOK=$false
                if ($ExpectedCAAIssuer) {
                    $issuerOK=@($records | Where-Object { $_ -match '^0 issue\s+' -and $_ -like "*$ExpectedCAAIssuer*" }).Count -gt 0
                }
                if ($ExpectedCAAReport) { $reportOK=$records -contains "0 iodef `"$ExpectedCAAReport`"" }
                $resolverResults += [pscustomobject]@{Provider=$provider; Status=$answer.Status; Count=$records.Count; Issuer=$issuerOK; Report=$reportOK}
            } catch {
                $resolverResults += [pscustomobject]@{Provider=$provider; Status=-1; Count=0; Issuer=$false; Report=$false}
            }
        }
        $available=@($resolverResults | Where-Object { $_.Status -eq 0 }).Count
        $matching=@($resolverResults | Where-Object {
            $_.Status -eq 0 -and (-not $ExpectedCAAIssuer -or $_.Issuer) -and (-not $ExpectedCAAReport -or $_.Report)
        }).Count
        $graded='INFO'
        if ($available -lt 2) { $graded='WARN' }
        elseif ($ExpectedCAAIssuer -or $ExpectedCAAReport) {
            if ($matching -eq 2) { $graded='PASS' } else { $graded='WARN' }
        } elseif (@($resolverResults | Where-Object { $_.Count -gt 0 }).Count -eq 2) { $graded='PASS' }
        $details=($resolverResults | ForEach-Object { "$($_.Provider):dns=$($_.Status),count=$($_.Count),issuer=$($_.Issuer),report=$($_.Report)" }) -join '; '
        Add-Finding 'DNS' "CAA $zone" $graded $details
    }

    if ($script:IsExtended) {
        $mailDomain=($inputHost -replace '^(?i)www\.','')
        foreach ($lookup in @(@{Name=$mailDomain; Type='MX'; Label='MX records'},
                              @{Name=$mailDomain; Type='TXT'; Label='SPF record'},
                              @{Name="_dmarc.$mailDomain"; Type='TXT'; Label='DMARC policy'})) {
            $responses=@()
            foreach ($provider in @('Google','Cloudflare')) {
                try {
                    $dnsResult=Get-DnsJson -Domain $lookup.Name -Type $lookup.Type -Provider $provider
                    $selected=@($dnsResult.Answer | Where-Object {
                        ($lookup.Type -eq 'MX' -and $_.type -eq 15) -or ($lookup.Type -eq 'TXT' -and $_.type -eq 16)
                    } | ForEach-Object { [string]$_.data })
                    if ($lookup.Label -eq 'SPF record') { $selected=@($selected | Where-Object { $_ -match '(?i)v=spf1' }) }
                    if ($lookup.Label -eq 'DMARC policy') { $selected=@($selected | Where-Object { $_ -match '(?i)v=DMARC1' }) }
                    $responses+= "$provider=$($selected.Count)"
                } catch { $responses+="$provider=error" }
            }
            Add-Finding 'DNS' $lookup.Label 'INFO' "$mailDomain | $($responses -join '; '); mail policy requires separate verification"
        }
        try {
            $dnssecResult=Get-DnsJson -Domain $mailDomain -Type 'A' -Provider 'Google'
            Add-Finding 'DNS' 'DNSSEC resolver AD observation' 'INFO' "AD=$([bool]$dnssecResult.AD); this alone does not establish an independently validated DNSSEC chain"
        } catch { Add-Finding 'DNS' 'DNSSEC resolver AD observation' 'INFO' 'Resolver unavailable; do not infer DNSSEC status' }
    }

    if ($ExpectTLS13Only) {
        if ($secureSite) {
            $old=Invoke-HttpProbe -Url "$targetOrigin/" -ExtraCurlArgs @('--tlsv1.2','--tls-max','1.2')
            $oldStatus=if ($old.ExitCode -eq 35) { 'PASS' } elseif ($old.ExitCode -eq 0) { 'FAIL' } else { 'WARN' }
            Add-Finding 'TLS' 'TLS 1.2 disallowed' $oldStatus "curl exit=$($old.ExitCode); HTTP=$($old.Status)"
            $modern=Invoke-HttpProbe -Url "$targetOrigin/" -ExtraCurlArgs @('--tlsv1.3','--tls-max','1.3')
            Add-Finding 'TLS' 'TLS 1.3 usable' $(if ($modern.ExitCode -eq 0 -and $modern.Status -eq 200) { 'PASS' } else { 'WARN' }) "curl exit=$($modern.ExitCode); HTTP=$($modern.Status)"
        } else { Add-Finding 'TLS' 'TLS 1.3-only policy' 'SKIP' 'HTTPS unavailable' }
    }

    # Observe method behavior first. 404/410 cannot prove a POST route is
    # absent, but by default avoid sending POSTs to an unconfirmed endpoint.
    $readyApiPaths=New-Object System.Collections.Generic.List[string]
    $anyApiRateLimited=$false
    foreach ($apiPath in ($ApiPaths | Select-Object -Unique)) {
        if (-not $secureSite) {
            Add-Finding 'API' "API method $apiPath" 'SKIP' 'API checks require verified HTTPS; no POST attempts will be made.'
            continue
        }
        $apiGet=Invoke-HttpProbe -Url "$targetOrigin$apiPath"
        $allow=Get-HeaderValue $apiGet 'allow'
        $cache=Get-HeaderValue $apiGet 'cache-control'
        $apiGetText="HTTP $($apiGet.Status); Allow=$allow; cache=$cache"
        if ($apiGet.ExitCode -ne 0) {
            Add-Finding 'API' "API method $apiPath" 'WARN' "GET probe failed (curl=$($apiGet.ExitCode)); POSTs skipped."
            continue
        }
        if ($apiGet.Status -in @(404,410)) {
            Add-Finding 'API' "API endpoint not confirmed $apiPath" 'WARN' "$apiGetText; GET returned not found/gone. It may also be a POST-only route that hides GET. No POSTs sent by default."
            continue
        }
        if ($apiGet.Status -ge 300 -and $apiGet.Status -lt 400) {
            Add-Finding 'API' "API endpoint not confirmed $apiPath" 'WARN' "$apiGetText; GET redirects and is not followed. POSTs skipped to avoid an unexpected destination."
            continue
        }
        if ($apiGet.Status -eq 429) {
            $anyApiRateLimited=$true
            Add-Finding 'API' "API rate limited $apiPath" 'INFO' "$apiGetText; rate limited; active POSTs skipped for this audit."
            continue
        }
        $getType=Get-HeaderValue $apiGet 'content-type'
        if ($apiGet.Status -eq 200 -and $getType -match '(?i)text/html') {
            Add-Finding 'API' "API endpoint not confirmed $apiPath" 'WARN' "$apiGetText; GET returned an HTML page ($getType), not a confirmed API. POSTs skipped."
            continue
        }
        $readyApiPaths.Add($apiPath)
        if ($ExpectedApiGetStatus -gt 0) {
            $getExpectedOk=$apiGet.Status -eq $ExpectedApiGetStatus
            $cacheOK=(-not $RequireApiNoStore -or $cache -match '(?i)no-store')
            Add-Finding 'API' "API method $apiPath" $(if ($getExpectedOk -and $cacheOK) { 'PASS' } else { 'WARN' }) "$apiGetText; expected HTTP $ExpectedApiGetStatus; require no-store=$([bool]$RequireApiNoStore)"
        } elseif ($apiGet.Status -eq 405) {
            Add-Finding 'API' "API method rejected GET $apiPath" 'PASS' "$apiGetText; rejected GET. Middleware can also return 405 for unknown paths."
        } elseif ($apiGet.Status -in @(401,403)) {
            Add-Finding 'API' "API method access controlled $apiPath" 'INFO' "$apiGetText; authentication or edge policy may prevent application validation."
        } else {
            Add-Finding 'API' "API method observed $apiPath" 'INFO' "$apiGetText; GET behavior varies by application."
        }
        # Full mode is deliberately slow. Don't trigger a shared rate limiter.
        if ($Mode -eq 'Full') { Start-Sleep -Seconds $ApiDelaySeconds }
    }

    if ($Mode -eq 'Full' -and -not $secureSite) {
        Add-Finding 'API' 'Negative API POSTs' 'SKIP' 'HTTPS unavailable: refusing to submit POST requests over HTTP.'
    } elseif ($Mode -eq 'Full') {
        $limitReached=$anyApiRateLimited
        foreach ($apiPath in ($ApiPaths | Select-Object -Unique)) {
            if (-not $readyApiPaths.Contains($apiPath)) {
                Add-Finding 'API' "Negative API POSTs $apiPath" 'SKIP' 'GET did not confirm a usable endpoint. No POST requests were sent.'
                continue
            }
            if ($limitReached) {
                Add-Finding 'API' "Negative API POSTs $apiPath" 'SKIP' 'Previous endpoint returned 429: stopping active tests.'
                continue
            }
            $testCases=@(
                @{Name='Cross-origin POST'; Expected=$ExpectedApiCrossOriginStatus; Headers=@('Origin: https://audit.invalid','Sec-Fetch-Site: cross-site','Content-Type: application/json'); Payload='{}'},
                @{Name='Malformed JSON'; Expected=$ExpectedApiMalformedJsonStatus; Headers=@('Content-Type: application/json'); Payload='{'},
                @{Name='Unsupported media type'; Expected=$ExpectedApiUnsupportedMediaTypeStatus; Headers=@('Content-Type: text/plain'); Payload='not-a-form'}
            )
            $stopThisApi=$false
            foreach ($t in $testCases) {
                if ($stopThisApi -or $limitReached) {
                    Add-Finding 'API' "API invalid request $apiPath $($t.Name)" 'SKIP' 'Earlier response made further POSTs unnecessary or unsafe.'
                    continue
                }
                # This POST never follows redirects. 1 request per test case.
                $response=Invoke-HttpProbe -Url "$targetOrigin$apiPath" -Method 'POST' -RequestHeaders $t.Headers -Body $t.Payload
                $cache=Get-HeaderValue $response 'cache-control'
                $status=[int]$response.Status
                $expected=[int]$t.Expected
                $statusInfo="HTTP $status; curl=$($response.ExitCode); cache=$cache"
                $resultStatus='INFO'
                $detail='Status observed; interpretation depends on the application and WAF.'
                if ($response.ExitCode -ne 0) {
                    $resultStatus='WARN'
                    $detail='Transport error; request outcome unknown.'
                    $stopThisApi=$true
                } elseif ($status -eq 429) {
                    $resultStatus='SKIP'
                    $detail='Rate limited; this does not prove input validation. Stopping all further POST tests.'
                    $limitReached=$true
                } elseif ($status -in @(404,410)) {
                    $resultStatus='WARN'
                    $detail='Endpoint may be missing or intentionally hidden; remaining POSTs skipped.'
                    $stopThisApi=$true
                } elseif ($status -ge 300 -and $status -lt 400) {
                    $resultStatus='INFO'
                    $detail='Redirect returned; not followed. Validation not assessed.'
                    $stopThisApi=$true
                } elseif ($status -eq 405) {
                    $resultStatus='INFO'
                    $detail='POST method rejected. Could be a non-API path or middleware; validation not assessed.'
                    $stopThisApi=$true
                } elseif ($status -ge 500) {
                    $resultStatus='WARN'
                    $detail='Server error after invalid request; review logs and error handling.'
                } elseif ($status -ge 200 -and $status -lt 300) {
                    $resultStatus='WARN'
                    $detail='Invalid request received a success response; verify endpoint-specific behavior and side effects.'
                } elseif ($status -ge 400 -and $status -lt 500) {
                    $resultStatus='PASS'
                    $detail='Request rejected. This does not identify which layer rejected it or prove input-validation design.'
                } else {
                    $resultStatus='INFO'
                    $detail='Unexpected or nonstandard response; review manually.'
                }

                # Site-specific exact expectations are OPTIONAL. Community
                # defaults classify observable rejection without assuming Byson
                # status codes. Byson preset explicitly selects strict mode.
                if ($expected -gt 0 -and -not $stopThisApi -and -not $limitReached) {
                    $cacheOK=(-not $RequireApiNoStore -or $cache -match '(?i)no-store')
                    $expectedOK=$status -eq $expected
                    if ($expectedOK -and $cacheOK) { $resultStatus='PASS' }
                    else { $resultStatus='WARN' }
                    $detail+=" Configured expectation HTTP $expected; no-store required=$([bool]$RequireApiNoStore)."
                }
                Add-Finding 'API' "API invalid request $apiPath $($t.Name)" $resultStatus "$statusInfo; $detail"
                if (-not $stopThisApi -and -not $limitReached) {
                    Start-Sleep -Seconds $ApiDelaySeconds
                }
            }
        }
    }

}

$pass=@($script:Findings | Where-Object { $_.Result -eq 'PASS' }).Count
$warn=@($script:Findings | Where-Object { $_.Result -eq 'WARN' }).Count
$fail=@($script:Findings | Where-Object { $_.Result -eq 'FAIL' }).Count
$info=@($script:Findings | Where-Object { $_.Result -eq 'INFO' }).Count
$skip=@($script:Findings | Where-Object { $_.Result -eq 'SKIP' }).Count
Write-Host "`nRESULTS" -ForegroundColor Cyan
$script:Findings | Format-Table Area,Check,Result,Severity,Details -AutoSize -Wrap
Write-Host "Mode=$Mode. Checks are configuration-dependent; count is not a security score." -ForegroundColor Cyan
$actionable=@($script:Findings | Where-Object { $_.Result -in @('WARN','FAIL') })
if ($ShowAllGuidance) { $actionable=@($script:Findings.ToArray()) }
if ($actionable.Count -gt 0) {
    Write-Host "`nEXPLANATIONS AND NEXT STEPS" -ForegroundColor Cyan
    foreach ($finding in $actionable) {
        Write-Host "[$($finding.Result)] $($finding.Check)  -  $($finding.Severity)" -ForegroundColor $(if ($finding.Result -eq 'FAIL') { 'Red' } else { 'Yellow' })
        Write-Host "  Why: $($finding.Why)"
        Write-Host "  Action: $($finding.Recommendation)"
        Write-Host "  Reference: $($finding.Reference)"
    }
}
Write-Host "`nPASS=$pass  WARN=$warn  FAIL=$fail  INFO=$info  SKIP=$skip  HTTP probes=$script:RequestCount" -ForegroundColor Cyan
Write-Host 'A clean result does not certify security. WARN/INFO require judgment.'
Write-Host 'OUT OF SCOPE: full pentest, DNSSEC chain validation, account security, WAF limits, browser accessibility, credential or provider checks.'

if ($ExportPrefix) {
    $parent=Split-Path -Path $ExportPrefix -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $jsonFile="$ExportPrefix.json"; $csvFile="$ExportPrefix.csv"
    $payload=[pscustomobject]@{
        created_utc=[DateTime]::UtcNow.ToString('o')
        version='1.2.3'
        mode=$Mode
        input=$SiteUrl
        audited_origin=$targetOrigin
        findings=@($script:Findings.ToArray())
        summary=[pscustomobject]@{pass=$pass;warn=$warn;fail=$fail;info=$info;skip=$skip;http_probes=$script:RequestCount}
    }
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $jsonFile -Encoding UTF8
    $script:Findings | Export-Csv -LiteralPath $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "Saved JSON: $jsonFile" -ForegroundColor Green
    Write-Host "Saved CSV:  $csvFile" -ForegroundColor Green
    $htmlFile="$ExportPrefix.html"
    $htmlRows=New-Object System.Collections.Generic.List[string]
    foreach ($finding in $script:Findings) {
        $kind=([string]$finding.Result).ToLowerInvariant()
        $htmlRows.Add(('<tr class="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td><td>{7}</td><td><a href="{8}">Reference</a></td></tr>' -f
            $kind, [System.Net.WebUtility]::HtmlEncode($finding.Result), [System.Net.WebUtility]::HtmlEncode($finding.Area),
            [System.Net.WebUtility]::HtmlEncode($finding.Check), [System.Net.WebUtility]::HtmlEncode($finding.Severity),
            [System.Net.WebUtility]::HtmlEncode($finding.Details), [System.Net.WebUtility]::HtmlEncode($finding.Why),
            [System.Net.WebUtility]::HtmlEncode($finding.Recommendation), [System.Net.WebUtility]::HtmlEncode($finding.Reference)))
    }
    $safeSite=[System.Net.WebUtility]::HtmlEncode($targetOrigin)
    $htmlParts=@('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Byson Cyber  -  Website Audit Report</title>',
        '<style>body{font:15px system-ui,sans-serif;max-width:1500px;margin:2rem auto;padding:0 1rem;color:#11212d;background:#f8f9fb}h1{color:#081a26}small{color:#52616b}table{border-collapse:collapse;width:100%;background:white}th,td{text-align:left;vertical-align:top;padding:.6rem;border-bottom:1px solid #d7dde3;overflow-wrap:anywhere}th{background:#e7ecf0}tr.fail{background:#ffe5e5}tr.warn{background:#fff4d8}tr.skip{color:#566}a{color:#245788}footer{margin:2rem 0}code{white-space:normal}</style></head><body>',
        "<h1>Byson Cyber  -  Website Security Review</h1><p>Version 1.2.3  |  Mode: $Mode  |  Origin: <code>$safeSite</code></p>",
        "<p><strong>PASS $pass  |  WARN $warn  |  FAIL $fail  |  INFO $info  |  SKIP $skip</strong>  -  $($script:RequestCount) HTTP probes</p>",
        '<p><strong>Important:</strong> Automated checks are observational. This report is not a penetration test, security certification, or compliance attestation.</p>',
        '<table><thead><tr><th>Status</th><th>Area</th><th>Check</th><th>Severity</th><th>Observation</th><th>Why it matters</th><th>Recommended next step</th><th>Source</th></tr></thead><tbody>',
        ($htmlRows -join "`n"), '</tbody></table><footer><small>Byson Cyber | Into the Storm  |  Generated report; review before sharing publicly.</small></footer></body></html>')
    $htmlParts -join "`n" | Set-Content -LiteralPath $htmlFile -Encoding UTF8
    Write-Host "Saved HTML: $htmlFile" -ForegroundColor Green
}
