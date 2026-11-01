#Requires -Version 5.1
<#
.SYNOPSIS
  Local-only verification of the Byson Cyber audit source files.
.DESCRIPTION
  Does not make any network requests. Parses scripts using the same PowerShell
  parser that will execute them, and checks for common reserved variable writes.
#>
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$names=@('Invoke-WebSecurityReview.ps1')
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Audit-BysonCyber.ps1')) {
    $names+= 'Audit-BysonCyber.ps1'
}
$bad=0
foreach ($name in $names) {
    $path=Join-Path $PSScriptRoot $name
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
    if ($errors.Count -gt 0) {
        foreach ($err in $errors) { Write-Host "PARSE ERROR $($name): $($err.Message) line $($err.Extent.StartLineNumber)" -ForegroundColor Red }
        $bad+=$errors.Count
        continue
    }
    $reserved=@('home','host','pid','pshome','psversiontable','true','false','null','error','input','matches','args','myinvocation','psscriptroot','pscommandpath','lastexitcode')
    $writes=@($ast.FindAll({param($node)
        if ($node -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { return $false }
        if ($node.Left -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }
        $varName=$node.Left.VariablePath.UserPath.ToLowerInvariant()
        return $varName -in $reserved
    },$true))
    if ($writes.Count -gt 0) {
        foreach ($write in $writes) { Write-Host "CHECK VARIABLE: $($write.Extent.Text)" -ForegroundColor Yellow }
        $bad+=$writes.Count
    } else { Write-Host "PASS syntax and reserved-variable check: $name" -ForegroundColor Green }
}
if ($bad -gt 0) { throw "$bad syntax or reserved-variable issues found. Do not run the audit until addressed." }
Write-Host 'PASS - All source files parsed. Runtime network behavior still requires a real authorized site test.' -ForegroundColor Green
