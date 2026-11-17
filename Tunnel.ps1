<#
.SYNOPSIS
Manage the restricted Windows agent: up, down, status, logs, check, restart.
.EXAMPLE
.\Tunnel.ps1 up
.EXAMPLE
.\Tunnel.ps1 logs -Tail 50 -Follow
#>
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet('up','down','status','logs','check','restart','rotate-client-token')]
    [string]$Command = 'status',
    [string]$Config = '',
    [ValidateSet('lab-status','lab-catalog','lab-echo','gitlab','artifactory','atlassian','web','homologation')]
    [string]$Service = '',
    [string]$RuntimeDirectory = '',
    [ValidateRange(1,10000)][int]$Tail = 100,
    [Alias('f')][switch]$Follow,
    [string]$PolicyJson = '',
    [string]$PolicyJsonBase64 = '',
    [switch]$PolicyStdin
)
$ErrorActionPreference = 'Stop'
if (($PolicyJson -or $PolicyJsonBase64 -or $PolicyStdin) -and $Command -ne 'rotate-client-token') {
    throw 'Use os valores de politica somente com rotate-client-token.'
}
if (-not $RuntimeDirectory) {
    $RuntimeDirectory = Join-Path $env:LOCALAPPDATA 'secure-gateway\agent'
}
$runtimePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RuntimeDirectory)
$launcher = Join-Path $PSScriptRoot 'Start-RestrictedLab.ps1'
$launchArgs = @{ RuntimeDirectory=$runtimePath }
if ($Config) { $launchArgs.Config = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Config) }
if ($Service) { $launchArgs.Service = $Service }

function Show-AgentLogs {
    $metadata = $null
    foreach ($name in @('agent.json','last-run.json')) {
        $path = Join-Path $runtimePath $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $metadata = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            break
        }
    }
    $paths = @()
    if ($null -ne $metadata) {
        foreach ($field in @('stdout','stderr')) {
            if (-not $metadata.$field) { continue }
            $path = [IO.Path]::GetFullPath([string]$metadata.$field)
            if ((Split-Path -Parent $path) -ne $runtimePath.TrimEnd('\') -or
                (Split-Path -Leaf $path) -notmatch '^agent-[a-f0-9]{32}(\.stderr)?\.log$') {
                throw 'Caminho de log invalido no registro do agente.'
            }
            if (Test-Path -LiteralPath $path -PathType Leaf) { $paths += $path }
        }
    } elseif (Test-Path -LiteralPath $runtimePath -PathType Container) {
        $latest = Get-ChildItem -LiteralPath $runtimePath -File |
            Where-Object { $_.Name -match '^agent-[a-f0-9]{32}\.log$' } |
            Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
        if ($null -ne $latest) {
            $paths += $latest.FullName
            $stderrPath = $latest.FullName -replace '\.log$', '.stderr.log'
            if (Test-Path -LiteralPath $stderrPath) { $paths += $stderrPath }
        }
    }
    if (-not $paths.Count) {
        Write-Output '{"event":"agent_logs_not_found"}'
        return
    }
    $readers = @()
    try {
        foreach ($path in $paths) {
            $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
            # Seek backwards by bounded blocks; do not scan a month of logs just
            # to display the last 100 lines. UTF-8 newline bytes are unambiguous.
            $offset = $stream.Length
            $lineCount = 0
            $buffer = New-Object byte[] 65536
            while ($offset -gt 0 -and $lineCount -le $Tail) {
                $size = [int][Math]::Min($buffer.Length, $offset)
                $offset -= $size
                $null = $stream.Seek($offset, [IO.SeekOrigin]::Begin)
                $read = $stream.Read($buffer, 0, $size)
                $lineCount += ([Text.Encoding]::UTF8.GetString($buffer, 0, $read).Split("`n").Length - 1)
            }
            $null = $stream.Seek($offset, [IO.SeekOrigin]::Begin)
            $reader = New-Object IO.StreamReader($stream)
            if ($offset -gt 0) { $null = $reader.ReadLine() }
            $readers += [pscustomobject]@{ Reader=$reader; Name=(Split-Path -Leaf $path) }
            $recent = New-Object 'Collections.Generic.Queue[string]'
            while ($null -ne ($line = $reader.ReadLine())) {
                $recent.Enqueue($line)
                if ($recent.Count -gt $Tail) { $null = $recent.Dequeue() }
            }
            foreach ($line in $recent) { Write-Output "[$(Split-Path -Leaf $path)] $line" }
        }
        if ($Follow) {
            while ($true) {
                foreach ($entry in $readers) {
                    while ($null -ne ($line = $entry.Reader.ReadLine())) {
                        Write-Output "[$($entry.Name)] $line"
                    }
                }
                Start-Sleep -Milliseconds 250
            }
        }
    } finally {
        foreach ($entry in $readers) { $entry.Reader.Dispose() }
    }
}

function Invoke-AgentLauncher([string]$Mode) {
    Push-Location -LiteralPath $PSScriptRoot
    try { & $launcher -Mode $Mode @launchArgs } finally { Pop-Location }
}

function Assert-AgentPolicy($Value) {
    if ($Value -is [Array]) {
        foreach ($item in $Value) { Assert-AgentPolicy $item }
    } elseif ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '(?i)token|password|secret|private_key|signing_key') {
                throw 'A politica do agente nao pode conter token, senha ou chave privada.'
            }
            Assert-AgentPolicy $property.Value
        }
    }
}

function Update-AgentPolicy {
    $sources = 0
    if ($PolicyJson) { $sources++ }
    if ($PolicyJsonBase64) { $sources++ }
    if ($PolicyStdin) { $sources++ }
    if ($sources -ne 1) {
        throw 'Informe somente -PolicyJson, -PolicyJsonBase64 ou -PolicyStdin, gerado no aws-frp.'
    }
    $json = $PolicyJson
    if ($PolicyStdin) { $json = [Console]::In.ReadToEnd() }
    if ($PolicyJsonBase64) {
        $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PolicyJsonBase64))
    }
    if ($json.Length -gt 65536) { throw 'Politica excede o tamanho permitido.' }
    $policy = $json | ConvertFrom-Json
    if ($policy.format -ne 1 -or $policy.role -ne 'agent' -or -not $policy.patch) {
        throw 'Esperada politica format=1 e role=agent. Nao envie o token do cliente.'
    }
    Assert-AgentPolicy $policy
    $configPath = Join-Path $PSScriptRoot 'bundles-https\agent\config.json'
    if ($launchArgs.Config) { $configPath = $launchArgs.Config }
    $pythonPath = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $pythonPath)) {
        $pythonPath = (Get-Command python -ErrorAction Stop).Source
    }
    $helper = Join-Path $PSScriptRoot 'homologation.py'
    New-Item -ItemType Directory -Force -Path $runtimePath | Out-Null
    $temporary = Join-Path $runtimePath ('policy-' + [Guid]::NewGuid().ToString('N') + '.json')
    try {
        $json | Set-Content -LiteralPath $temporary -Encoding UTF8
        & $pythonPath $helper apply --config $configPath --policy $temporary --validate-only
        if ($LASTEXITCODE -ne 0) { throw 'Politica invalida; agente atual nao foi interrompido.' }
        Invoke-AgentLauncher Stop
        if ($LASTEXITCODE -ne 0) { throw 'Nao foi possivel parar com seguranca o agente gerenciado.' }
        & $pythonPath $helper apply --config $configPath --policy $temporary
        if ($LASTEXITCODE -ne 0) { throw 'Falha ao aplicar politica. Confira o backup e execute check antes de subir.' }
        $launchArgs.Config = $configPath
        Invoke-AgentLauncher Agent
        if ($LASTEXITCODE -ne 0) { throw 'Politica aplicada, mas o preflight/inicio falhou. Execute tunnel check.' }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

if ($Command -eq 'logs') { Show-AgentLogs; exit 0 }
if ($Command -eq 'status') { Invoke-AgentLauncher Status; exit $LASTEXITCODE }
if ($Command -eq 'check') { Invoke-AgentLauncher Check; exit $LASTEXITCODE }

# Serialize managed lifecycle commands for this user's runtime directory.
$hash = [Security.Cryptography.SHA256]::Create()
try {
    $digest = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($runtimePath.ToLowerInvariant()))).Replace('-','')
} finally { $hash.Dispose() }
$mutex = New-Object Threading.Mutex($false, "Local\SecureGateway-$digest")
$locked = $false
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Outra operacao up/down/restart esta em andamento neste agente.' }
    if ($Command -eq 'rotate-client-token') { Update-AgentPolicy; exit 0 }
    if ($Command -in @('down','restart')) {
        Invoke-AgentLauncher Stop
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    if ($Command -in @('up','restart')) {
        Invoke-AgentLauncher Agent
        exit $LASTEXITCODE
    }
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
