$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $Root "build"
$ArtifactDir = Join-Path $Root "artifacts\BMTX"

cmake -S $Root -B $BuildDir -G "Visual Studio 17 2022" -A x64
cmake --build $BuildDir --config Release

New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null
Copy-Item -Force (Join-Path $BuildDir "Release\BMTX.exe") $ArtifactDir
Copy-Item -Force (Join-Path $Root "README.md") $ArtifactDir

Write-Host "Artifact created: $ArtifactDir"
