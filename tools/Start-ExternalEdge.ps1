[CmdletBinding()]
param(
    [string]$ProxyHost = 'secure-gateway.sicredi.space',
    [ValidateRange(1024, 65535)][int]$Port = 8443,
    [ValidateSet('All','GitLab','Jira','Confluence','Lab')][string]$Application = 'All',
    [ValidateSet('Selective','All')][string]$Routing = 'Selective',
    [switch]$PrintCommand
)
$ErrorActionPreference = 'Stop'
if ($ProxyHost -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$') {
    throw 'Invalid proxy hostname'
}
$edgeCandidates = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
)
$edgePath = $edgeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $edgePath) { throw 'Microsoft Edge was not found' }
$profileName = if ($Routing -eq 'All') { 'secure-gateway\edge-external-all' } else { 'secure-gateway\edge-external' }
$profilePath = Join-Path $env:LOCALAPPDATA $profileName
$pacUrl = "https://${ProxyHost}:${Port}/proxy.pac"
# Interactive browser explicitly requested; no credentials in arguments or registry.
$urls = switch ($Application) {
    'Lab' { 'http://localhost:18765/' }
    'GitLab' { 'https://gitlab.sicredi.net/' }
    'Jira' { 'https://sicredi.atlassian.net/jira' }
    'Confluence' { 'https://sicredi.atlassian.net/wiki' }
    'All' { 'https://gitlab.sicredi.net/'; 'https://sicredi.atlassian.net/jira'; 'https://sicredi.atlassian.net/wiki' }
}
$proxyArguments = if ($Routing -eq 'All') {
    # Explicit proxy supports the lab loopback test; PAC has implicit bypasses.
    @("--proxy-server=https://${ProxyHost}:${Port}",
      "--proxy-bypass-list=`"<-loopback>;${ProxyHost}`"")
} else {
    @("--proxy-pac-url=$pacUrl")
}
$edgeArguments = @("--user-data-dir=`"$profilePath`"") + @($proxyArguments) + @($urls)
if ($PrintCommand) {
    [pscustomobject]@{ Executable = $edgePath; Arguments = $edgeArguments; Routing = $Routing } | ConvertTo-Json -Depth 3
    return
}
Start-Process -FilePath $edgePath -ArgumentList $edgeArguments
Write-Output 'Edge opened. Proxy username is the client ID; password is its current token. Application login and MFA remain separate. Close this dedicated profile before reopening to refresh PAC.'

if ($Routing -eq 'All') { Write-Output 'HTTP/HTTPS browser traffic uses the proxy; unauthorized destinations are denied. This is not a VPN and does not transport arbitrary UDP/WebRTC.' }
