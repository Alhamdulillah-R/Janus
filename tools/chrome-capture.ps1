# Capture the local Chrome (headless, fresh profile per run) with janus_requests.capture from the py-check install (see py-run.ps1); output in build\captured, log in build\chrome-capture.log.
$root = 'E:\dev\rust-dev\Janus'
$log = "$root\build\chrome-capture.log"
$out = "$root\build\captured"
$chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
$env:PYTHONIOENCODING = 'utf-8'
Set-Location $root

Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue
$server = Start-Process -PassThru -WindowStyle Hidden -FilePath uv -RedirectStandardError "$root\build\capture-server.log" -ArgumentList 'run', '--project', "$root\build\py-check", 'python', '-m', 'janus_requests.capture', '--port', '8443', '--out', $out, '--name', 'chrome155_live'

foreach ($i in 1..120) {
    if (Get-NetTCPConnection -State Listen -LocalPort 8443 -ErrorAction SilentlyContinue) { break }
    Start-Sleep 1
}

try {
    foreach ($run in 1..3) {
        $profileDir = "$root\build\chrome-capture-profile-$run"
        Remove-Item -Recurse -Force $profileDir -ErrorAction SilentlyContinue
        $chromeArgs = '--headless=new', '--disable-gpu', '--ignore-certificate-errors', '--no-first-run', "--user-data-dir=$profileDir", '--dump-dom', 'https://localhost:8443/'
        $p = Start-Process -PassThru -WindowStyle Hidden -FilePath $chrome -ArgumentList $chromeArgs -RedirectStandardOutput "$root\build\chrome-capture-dom-$run.html"
        $p.WaitForExit(60000) | Out-Null
        Remove-Item -Recurse -Force $profileDir -ErrorAction SilentlyContinue
    }
    Start-Sleep 2
    "runs done" | Out-File $log
}
finally {
    Get-NetTCPConnection -State Listen -LocalPort 8443 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
}
Get-Content "$root\build\capture-server.log" | Out-File -Append $log
Get-ChildItem $out | ForEach-Object { $_.Name } | Out-File -Append $log
