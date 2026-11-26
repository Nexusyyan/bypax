# Downloads and verifies the official signed WinDivert 2.2.2-A binaries (LGPLv3).
# Extracts ONLY WinDivert.dll, WinDivert64.sys, WINDIVERT_LICENSE.txt, and WINDIVERT_README.txt
# into runtime/windivert/ (gitignored) with zero sample tools.

[CmdletBinding()]
param(
    [string]$Version = "2.2.2-A",
    [string]$Tag = "v2.2.2",
    [string]$ExpectedSha256 = "63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15",
    [Alias("OutDir")]
    [string]$OutputDir = (Join-Path $PSScriptRoot "..\runtime\windivert"),
    [string]$Proxy = ""
)

$ErrorActionPreference = "Stop"

$ZipName = "WinDivert-$Version.zip"
$Url = "https://github.com/basil00/WinDivert/releases/download/$Tag/$ZipName"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("bypax-windivert-" + [System.Guid]::NewGuid().ToString("N"))
$ZipPath = Join-Path $TempDir $ZipName

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$ResolvedOutDir = (Resolve-Path $OutputDir).Path

try {
    Write-Host "Downloading WinDivert $Version from $Url ..."
    if ($Proxy) {
        $CurlExe = Join-Path $env:SystemRoot "System32\curl.exe"
        if (Test-Path $CurlExe) {
            Write-Host "Using proxy $Proxy via curl.exe ..."
            & $CurlExe -fSL --max-time 60 --proxy $Proxy -o $ZipPath $Url
            if ($LASTEXITCODE -ne 0) {
                throw "curl.exe failed with exit code $LASTEXITCODE"
            }
        } else {
            Invoke-WebRequest -Uri $Url -OutFile $ZipPath -Proxy $Proxy -TimeoutSec 60 -UseBasicParsing
        }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath -TimeoutSec 60 -UseBasicParsing
    }

    $Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToUpperInvariant()
    Write-Host "Archive SHA-256: $Hash"
    if ($ExpectedSha256 -and ($Version -eq "2.2.2-A" -or $PSBoundParameters.ContainsKey("ExpectedSha256"))) {
        if ($Hash -ne $ExpectedSha256.ToUpperInvariant()) {
            throw "SHA-256 mismatch! Expected $ExpectedSha256, got $Hash"
        }
    }

    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    $RootDir = Join-Path $ExtractDir "WinDivert-$Version"
    if (-not (Test-Path $RootDir)) {
        $RootDir = (Get-ChildItem -Directory $ExtractDir | Select-Object -First 1).FullName
    }

    $X64Dir = Join-Path $RootDir "x64"
    $DllSrc = Join-Path $X64Dir "WinDivert.dll"
    $SysSrc = Join-Path $X64Dir "WinDivert64.sys"
    if (-not (Test-Path $DllSrc) -or -not (Test-Path $SysSrc)) {
        throw "Required x64 WinDivert binaries were not found inside $ZipName"
    }

    Copy-Item $DllSrc -Destination (Join-Path $ResolvedOutDir "WinDivert.dll") -Force
    Copy-Item $SysSrc -Destination (Join-Path $ResolvedOutDir "WinDivert64.sys") -Force

    foreach ($LicenseFile in @("LICENSE", "README")) {
        $Src = Join-Path $RootDir $LicenseFile
        if (-not (Test-Path $Src)) {
            throw "Required WinDivert notice '$LicenseFile' was not found inside $ZipName"
        }
        Copy-Item $Src -Destination (Join-Path $ResolvedOutDir "WINDIVERT_$LicenseFile.txt") -Force
    }

    $SysPath = Join-Path $ResolvedOutDir "WinDivert64.sys"
    $Sig = Get-AuthenticodeSignature -FilePath $SysPath
    Write-Host "WinDivert64.sys signature status: $($Sig.Status)"
    if ($Sig.SignerCertificate) {
        Write-Host "Signer: $($Sig.SignerCertificate.Subject)"
    }
    if ($Sig.Status -ne "Valid") {
        Write-Warning "WinDivert64.sys Authenticode signature is not Valid ($($Sig.Status)). Check your system certificate store or driver integrity."
    }

    Write-Host "OK: WinDivert $Version runtime installed to $ResolvedOutDir"
}
finally {
    if (Test-Path $TempDir) {
        Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
    }
}
