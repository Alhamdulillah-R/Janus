# Build the janus_requests wheel and the editable test install, start the local test servers and proxies, run the functional script; log to build\py-windows.log.
$ErrorActionPreference = 'Stop'
$root = 'E:\dev\rust-dev\Janus'
$log = "$root\build\py-windows.log"
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $root

& cargo build -p janus --examples *> "$root\build\cargo-windows.log"
if ($LASTEXITCODE -ne 0) { "cargo build failed" | Out-File $log; exit 1 }

Remove-Item -Force "$root\build\wheels\*.whl" -ErrorAction SilentlyContinue
Push-Location "$root\crates\janus-py"
& uvx maturin build --release -o "$root\build\wheels" *> "$root\build\wheel-windows.log"
Pop-Location
if ($LASTEXITCODE -ne 0) { "wheel build failed" | Out-File $log; exit 1 }

# the test environment installs the source tree editable, rebuilt on every run
$check = "$root\build\py-check"
if (-not (Test-Path "$check\pyproject.toml")) { & uv init --bare --no-workspace --python 3.12 $check *> $null }
Push-Location $check
& uv add --editable "$root\crates\janus-py" --extra capture *> "$root\build\py-check.log"
& uv sync --reinstall-package janus-requests *>> "$root\build\py-check.log"
Pop-Location
if ($LASTEXITCODE -ne 0) { "py-check install failed" | Out-File $log; exit 1 }

$servers = @(
    (Start-Process -PassThru -WindowStyle Hidden -FilePath uv -ArgumentList 'run', '--no-project', '--with', 'brotli', '--with', 'zstandard', 'python', 'tools\test_server.py', '8765'),
    (Start-Process -PassThru -WindowStyle Hidden -FilePath uvx -ArgumentList '--python', '3.12', 'pproxy', '-l', 'http://127.0.0.1:8899', '-l', 'socks5://127.0.0.1:8898'),
    (Start-Process -PassThru -WindowStyle Hidden -FilePath uv -ArgumentList 'run', '--no-project', '--with', 'h2', '--with', 'cryptography', 'python', 'tools\h2_echo_server.py', '8766')
)

$ports = 8765, 8899, 8766
foreach ($i in 1..120) {
    $up = @(Get-NetTCPConnection -State Listen -LocalPort $ports -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique)
    if ($up.Count -eq $ports.Count) { break }
    Start-Sleep 1
}

try {
    & uv run --project $check python tools\py_functional.py 8765 8899 8898 8766 *> $log
    "EXIT=$LASTEXITCODE" | Out-File -Append $log
}
finally {
    foreach ($port in $ports) {
        Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    }
    foreach ($s in $servers) { Stop-Process -Id $s.Id -Force -ErrorAction SilentlyContinue }
}
