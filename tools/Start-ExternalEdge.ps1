[CmdletBinding()]
param(
    [string]$ProxyHost = 'secure-gateway.sicredi.space',
    [ValidateRange(1024, 65535)][int]$Port = 8443,
    [ValidateSet('All','GitLab','Jira','Confluence')][string]$Application = 'All'
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
$profilePath = Join-Path $env:LOCALAPPDATA 'secure-gateway\edge-external'
$pacUrl = "https://${ProxyHost}:${Port}/proxy.pac"
# Interactive browser explicitly requested; no credentials in arguments or registry.
$urls = switch ($Application) {
    'GitLab' { 'https://gitlab.sicredi.net/' }
    'Jira' { 'https://sicredi.atlassian.net/jira' }
    'Confluence' { 'https://sicredi.atlassian.net/wiki' }
    'All' { 'https://gitlab.sicredi.net/'; 'https://sicredi.atlassian.net/jira'; 'https://sicredi.atlassian.net/wiki' }
}
Start-Process -FilePath $edgePath -ArgumentList (@(
    "--user-data-dir=`"$profilePath`"",
    "--proxy-pac-url=$pacUrl"
) + @($urls))
Write-Output 'Edge opened. Proxy username is the client ID; password is its current token. Application login and MFA remain separate. Close this dedicated profile before reopening to refresh PAC.'
