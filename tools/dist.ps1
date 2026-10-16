# Release builds for Windows: the Rust example binaries (zipped) and the janus_requests wheel, into build\dist; log in build\dist.log.
$ErrorActionPreference = 'Stop'
$root = 'E:\dev\rust-dev\Janus'
$dist = "$root\build\dist"
Set-Location $root
Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$dist\rust" | Out-Null
& cargo build --release -p janus --examples *> "$root\build\dist-cargo.log"
if ($LASTEXITCODE -ne 0) { "cargo failed" | Out-File "$root\build\dist.log"; exit 1 }
Copy-Item "$root\target\release\examples\get.exe", "$root\target\release\examples\session.exe" "$dist\rust\"
Push-Location "$root\crates\janus-py"
& uvx maturin build --release -o $dist *> "$root\build\dist-wheel.log"
Pop-Location
if ($LASTEXITCODE -ne 0) { "wheel failed" | Out-File "$root\build\dist.log"; exit 1 }
Compress-Archive -Force -Path "$dist\rust\*" -DestinationPath "$dist\janus-0.2.0-rust-x86_64-pc-windows-msvc.zip"
Get-ChildItem -Recurse -File $dist | % { "{0,12:N0}  {1}" -f $_.Length, $_.FullName } | Out-File "$root\build\dist.log"
"DONE" | Out-File -Append "$root\build\dist.log"
