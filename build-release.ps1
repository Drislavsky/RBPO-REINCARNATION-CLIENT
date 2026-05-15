$ErrorActionPreference = "Stop"

cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

$artifactDir = Join-Path $PSScriptRoot "artifacts\BMTX"
New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
Copy-Item "build\Release\BMTX.exe" $artifactDir -Force
Copy-Item "build\Release\BMTXService.exe" $artifactDir -Force
Copy-Item "assets\bmtx.ico" $artifactDir -Force

Write-Host "Artifacts copied to $artifactDir"
