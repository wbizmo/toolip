#requires -Version 7.0
<#
Toolip Windows standalone installer candidate.
Review this locally before running. Never execute a downloaded script with
Invoke-Expression. This installer refuses to install without an exact commit
and an Ed25519 public key obtained separately from release downloads.
#>
[CmdletBinding(SupportsShouldProcess = $false)]
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [Parameter(Mandatory = $true)][string]$GitSha,
  [Parameter(Mandatory = $true)][string]$PublicKey,
  [string]$Prefix = (Join-Path $env:LOCALAPPDATA 'Programs\Toolip'),
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
  throw 'Provide a fixed X.Y.Z release version.'
}
if ($GitSha -cnotmatch '^[a-f0-9]{40}$') {
  throw 'Provide a full lowercase immutable source SHA.'
}
if (-not (Test-Path -LiteralPath $PublicKey -PathType Leaf)) {
  throw 'The separately trusted Ed25519 PEM public key is required.'
}
$publicKeyPath = (Resolve-Path -LiteralPath $PublicKey).Path
if (-not [System.IO.Path]::IsPathFullyQualified($Prefix)) {
  throw 'Installation prefix must be an absolute directory.'
}
if (-not $IsWindows) {
  throw 'This installer supports Windows only.'
}
$arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) {
  'X64' { 'x64' }
  'Arm64' { 'arm64' }
  default { throw 'Unsupported Windows architecture.' }
}
$target = "windows-$arch"
$asset = "toolip-$Version-$target.zip"
$base = "https://github.com/wbizmo/toolip/releases/download/v$Version"

if ($DryRun) {
  Write-Output "Review-only; no downloads or files changed."
  Write-Output "Immutable source: $GitSha"
  Write-Output "Target: $target"
  Write-Output "Manifest: $base/release-manifest.json"
  Write-Output "Archive: $base/$asset"
  return
}

foreach ($command in @('curl.exe', 'openssl.exe', 'tar.exe')) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "A required local verification tool is unavailable: $command"
  }
}

# Only user-private destinations. Never call elevation, edit PowerShell
# profiles, modify the machine PATH or run the downloaded executable.
$userLocal = [System.IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
$resolvedPrefix = [System.IO.Path]::GetFullPath($Prefix).TrimEnd('\')
if (-not $resolvedPrefix.StartsWith(
    "$userLocal\", [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'Installation must remain under the user LOCALAPPDATA directory.'
}

$temporary = Join-Path ([System.IO.Path]::GetTempPath()) (
  'toolip-install-' + [Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($temporary) | Out-Null

function Invoke-VerifiedDownload([string]$Uri, [string]$Output) {
  & curl.exe --fail --silent --show-error --location `
    --proto '=https' --proto-redir '=https' `
    --connect-timeout 10 --max-time 120 --retry 2 `
    --output $Output $Uri
  if ($LASTEXITCODE -ne 0) { throw 'An authenticated HTTPS download failed.' }
}

function Assert-NotReparsePoint([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'Symlink or junction encountered in installation path.'
  }
}

try {
  $manifestPath = Join-Path $temporary 'manifest.json'
  $signaturePath = Join-Path $temporary 'manifest.sig'
  $rawSignature = Join-Path $temporary 'signature.bin'
  $archivePath = Join-Path $temporary $asset
  Invoke-VerifiedDownload "$base/release-manifest.json" $manifestPath
  Invoke-VerifiedDownload "$base/release-manifest.sig" $signaturePath

  & openssl.exe base64 -d -A -in $signaturePath -out $rawSignature
  if ($LASTEXITCODE -ne 0) { throw 'Release manifest signature format is invalid.' }
  & openssl.exe pkeyutl -verify -rawin -pubin -inkey $publicKeyPath `
    -sigfile $rawSignature -in $manifestPath *> $null
  if ($LASTEXITCODE -ne 0) { throw 'Release manifest signature is not trusted.' }

  $manifestInfo = Get-Item -LiteralPath $manifestPath
  if ($manifestInfo.Length -gt 65536) {
    throw 'Release manifest exceeds the allowed byte budget.'
  }
  $manifest = Get-Content -LiteralPath $manifestPath -Raw |
    ConvertFrom-Json -Depth 16
  if ($manifest.schema -cne 'toolip.dev/distribution/v1' -or
      $manifest.repository -cne 'wbizmo/toolip' -or
      $manifest.artifactKind -cne 'standalone-runtime-bundle' -or
      $manifest.version -cne $Version -or
      $manifest.sourceGitSha -cne $GitSha) {
    throw 'Signed release identity does not match the operator expectation.'
  }
  $candidates = @($manifest.assets | Where-Object { $_.target -ceq $target })
  if ($candidates.Count -ne 1 -or $candidates[0].filename -cne $asset) {
    throw 'Expected target archive is missing or ambiguous.'
  }
  $expectedHash = [string]$candidates[0].sha256
  if ($expectedHash -cnotmatch '^[a-f0-9]{64}$') {
    throw 'Signed SHA-256 digest is malformed.'
  }
  $expectedBytes = [long]$candidates[0].size
  if ($expectedBytes -lt 1 -or $expectedBytes -gt 8589934592) {
    throw 'Signed archive size is outside the allowed budget.'
  }

  Invoke-VerifiedDownload "$base/$asset" $archivePath
  $actualBytes = (Get-Item -LiteralPath $archivePath).Length
  if ($actualBytes -ne $expectedBytes) {
    throw 'Archive size differs from the signed manifest.'
  }
  $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
  if ($actualHash -cne $expectedHash.ToUpperInvariant()) {
    throw 'Archive SHA-256 differs from the signed manifest.'
  }

  $members = @(& tar.exe -tzf $archivePath)
  if ($LASTEXITCODE -ne 0 -or $members.Count -ne 1 -or
      $members[0] -cne 'toolip.exe') {
    throw 'Release archive has an unsupported or unsafe layout.'
  }
  $extracted = Join-Path $temporary 'extracted'
  [System.IO.Directory]::CreateDirectory($extracted) | Out-Null
  & tar.exe -xzf $archivePath -C $extracted toolip.exe
  if ($LASTEXITCODE -ne 0) { throw 'Safe archive extraction failed.' }
  $binary = Join-Path $extracted 'toolip.exe'
  if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Signed archive did not include a regular executable.'
  }
  Assert-NotReparsePoint $binary

  # Refuse pre-existing junctions and symlinks in every user directory
  # component before creating a private staging file beside final target.
  $current = $userLocal
  $suffix = $resolvedPrefix.Substring($userLocal.Length).TrimStart('\')
  foreach ($part in ($suffix -split '\\')) {
    if (-not $part) { continue }
    $current = Join-Path $current $part
    Assert-NotReparsePoint $current
    if (-not (Test-Path -LiteralPath $current)) {
      [System.IO.Directory]::CreateDirectory($current) | Out-Null
    }
  }
  $destination = Join-Path $resolvedPrefix 'toolip.exe'
  if (Test-Path -LiteralPath $destination) {
    throw 'A Toolip executable already exists; no overwrite is allowed.'
  }
  $stage = Join-Path $resolvedPrefix (
    '.toolip-stage-' + [Guid]::NewGuid().ToString('N') + '.exe'
  )
  try {
    [System.IO.File]::Copy($binary, $stage, $false)
    [System.IO.File]::Move($stage, $destination, $false)
  } finally {
    if (Test-Path -LiteralPath $stage) {
      Remove-Item -LiteralPath $stage -Force
    }
  }
  Write-Output "Installed signed Toolip candidate $Version to $destination"
  Write-Output 'PATH was not modified. Configure it manually after review.'
} finally {
  if (Test-Path -LiteralPath $temporary) {
    Remove-Item -LiteralPath $temporary -Recurse -Force
  }
}
