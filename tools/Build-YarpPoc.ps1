[CmdletBinding()]
param(
    [ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64',
    [switch]$FrameworkDependent
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repo 'yarp-poc\SecureGateway.Yarp.csproj'
$output = Join-Path $repo ("yarp-poc\publish-" + $Runtime)
$selfContained = if ($FrameworkDependent) { 'false' } else { 'true' }
& dotnet publish $project -c Release -r $Runtime --self-contained $selfContained -o $output --nologo
if ($LASTEXITCODE -ne 0) { throw 'Publicacao YARP falhou.' }
Write-Output "Artefatos em $output. Transfira a pasta completa por mecanismo autorizado; nao versione os binarios."
