# Cyber Huntress: Surface Map Attack Framework Build Script
# Builds Windows + Linux binaries into:
#   ./bin/windows
#   ./bin/linux

$ErrorActionPreference = "Stop"

function Initialize-Directory($path) {
    if (!(Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

function Invoke-GoBuild($name, $sourcePath, $windowsOut, $linuxOut) {
    Write-Host "`n[*] Building $name (Go) for Windows..."
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -o $windowsOut $sourcePath
    Write-Host "[+] Binary: $windowsOut"

    Write-Host "[*] Building $name (Go) for Linux..."
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    go build -o $linuxOut $sourcePath
    Write-Host "[+] Binary: $linuxOut"

    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
}

function Invoke-RustBuild($name, $projectPath, $windowsExeName, $linuxExeName) {
    $safeName = ($name -replace '[^A-Za-z0-9_.-]', '-')
    $cargoTargetDir = Join-Path $env:LOCALAPPDATA "Akemi-Build\$safeName"
    $rustFeatures = @()
    if ($name -eq "Akemi-Spear") {
        if ($env:AKEMI_SPEAR_SYN_SCAN -eq "1") {
            $rustFeatures += "syn-scan"
        }
    }
    if (!(Test-Path $cargoTargetDir)) {
        New-Item -ItemType Directory -Path $cargoTargetDir -Force | Out-Null
    }

    Push-Location $projectPath
    try {
        $env:CARGO_TARGET_DIR = $cargoTargetDir
        Write-Host "`n[*] Building $name (Rust) for Windows..."
        if ($rustFeatures.Count -gt 0) {
            Write-Host "    Optional features: $($rustFeatures -join ', ')"
            cargo build --release --features ($rustFeatures -join ",")
        }
        else {
            cargo build --release
        }
        $windowsSource = Join-Path $cargoTargetDir "release\$windowsExeName"
        if (Test-Path $windowsSource) {
            Copy-Item $windowsSource -Destination "../bin/windows/$windowsExeName" -Force
            Write-Host "[+] Binary: bin/windows/$windowsExeName"
        }
        else {
            Write-Host "[!] Expected Windows binary not found: $windowsSource"
        }

        try {
            Write-Host "[*] Building $name (Rust) for Linux..."
            if ($rustFeatures.Count -gt 0) {
                cargo build --release --target x86_64-unknown-linux-gnu --features ($rustFeatures -join ",")
            }
            else {
                cargo build --release --target x86_64-unknown-linux-gnu
            }
            $linuxSource = Join-Path $cargoTargetDir "x86_64-unknown-linux-gnu\release\$linuxExeName"
            if (Test-Path $linuxSource) {
                Copy-Item $linuxSource -Destination "../bin/linux/$linuxExeName" -Force
                Write-Host "[+] Binary: bin/linux/$linuxExeName"
            }
            else {
                Write-Host "[!] Expected Linux binary not found: $linuxSource"
            }
        }
        catch {
            Write-Host "[!] Linux Rust build failed for $name."
            Write-Host "    You may need: rustup target add x86_64-unknown-linux-gnu"
            Write-Host "    And a working Linux linker/toolchain on Windows, or use WSL/cross."
            Write-Host "    If syn-scan is enabled, build on Linux/WSL or provide the required cross toolchain."
        }
    }
    finally {
        Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        Pop-Location
    }
}

Write-Host "[*] Creating output directories..."
Initialize-Directory "bin"
Initialize-Directory "bin/windows"
Initialize-Directory "bin/linux"

Invoke-GoBuild `
    -name "Akemi" `
    -sourcePath "./cmd/Akemi" `
    -windowsOut "bin/windows/Akemi.exe" `
    -linuxOut "bin/linux/Akemi"

Invoke-RustBuild `
    -name "Akemi-Spear" `
    -projectPath "Akemi-Spear" `
    -windowsExeName "Akemi-Spear.exe" `
    -linuxExeName "Akemi-Spear"

Invoke-RustBuild `
    -name "DotHound" `
    -projectPath "DotHound" `
    -windowsExeName "dothound.exe" `
    -linuxExeName "dothound"

Write-Host "`n[*] Akemi build complete!"
Write-Host "    Windows binaries: ./bin/windows"
Write-Host "    Linux binaries:   ./bin/linux"
