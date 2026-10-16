<#
.SYNOPSIS
Build static zlib/brotli/zstd and OpenSSL (VC-WIN64A) for Janus; reruns are incremental.
#>
param(
    # Wipe the OpenSSL build tree and run Configure again
    [switch]$Reconfigure
)

$ErrorActionPreference = 'Stop'

# ==========================================================================
$janus_root = Split-Path -Parent $PSScriptRoot
$third_party = Join-Path $janus_root 'third_party'
$deps_build = Join-Path $janus_root 'build\deps-msvc'
$deps_install = Join-Path $deps_build 'install'
$openssl_build = Join-Path $janus_root 'build\openssl-msvc'
$openssl_install = Join-Path $openssl_build 'install'

$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$perl_bin = 'E:\dev\tools\strawberry-perl\perl\bin'
$nasm_dir = 'C:\Program Files\NASM'
$cmake_bin = 'F:\JEtBrainsIDE\CLion\bin\cmake\win\x64\bin'
# openssl-4.0.3 release commit the patches are written against
$openssl_base = 'af1775b60dfa141a4ad762585052cabeb9f37e9e'
# ==========================================================================

<#
.SYNOPSIS
Import the vcvars64 environment into the current PowerShell process.
#>
function Import-VsEnv {
    $lines = & cmd.exe /c "`"$vcvars`" >nul && set"
    if ($LASTEXITCODE -ne 0) {
        throw "vcvars64 failed: $vcvars"
    }

    foreach ($line in $lines) {
        $eq = $line.IndexOf('=')
        if ($eq -gt 0) {
            [Environment]::SetEnvironmentVariable($line.Substring(0, $eq), $line.Substring($eq + 1), 'Process')
        }
    }

    $env:PATH = "$perl_bin;$nasm_dir;$cmake_bin;$env:PATH"
}

<#
.SYNOPSIS
Configure, build and install one CMake project as a static Release library.
#>
function Build-CMakeLib {
    param(
        [string]$Name,
        [string]$SourceDir,
        [string[]]$CMakeArgs
    )

    $build_dir = Join-Path $deps_build $Name
    $configure_args = @(
        '-S', $SourceDir,
        '-B', $build_dir,
        '-G', 'NMake Makefiles',
        '-DCMAKE_BUILD_TYPE=Release',
        "-DCMAKE_INSTALL_PREFIX=$deps_install",
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL'
    ) + $CMakeArgs

    & cmake @configure_args
    if ($LASTEXITCODE -ne 0) {
        throw "cmake configure failed: $Name"
    }

    & cmake --build $build_dir --target install
    if ($LASTEXITCODE -ne 0) {
        throw "cmake build failed: $Name"
    }
}

<#
.SYNOPSIS
Build the three compression libraries OpenSSL links for certificate compression.
#>
function Build-Deps {
    $lib_dir = Join-Path $deps_install 'lib'

    if (-not (Test-Path (Join-Path $lib_dir 'zlibstatic.lib'))) {
        Build-CMakeLib -Name 'zlib' -SourceDir (Join-Path $third_party 'zlib') -CMakeArgs @(
            '-DZLIB_BUILD_EXAMPLES=OFF'
        )
    }

    if (-not (Test-Path (Join-Path $lib_dir 'brotlicommon.lib'))) {
        Build-CMakeLib -Name 'brotli' -SourceDir (Join-Path $third_party 'brotli') -CMakeArgs @(
            '-DBUILD_SHARED_LIBS=OFF',
            '-DBROTLI_DISABLE_TESTS=ON'
        )
    }

    if (-not (Test-Path (Join-Path $lib_dir 'zstd_static.lib'))) {
        Build-CMakeLib -Name 'zstd' -SourceDir (Join-Path $third_party 'zstd\build\cmake') -CMakeArgs @(
            '-DZSTD_BUILD_SHARED=OFF',
            '-DZSTD_BUILD_STATIC=ON',
            '-DZSTD_BUILD_PROGRAMS=OFF',
            '-DZSTD_BUILD_TESTS=OFF'
        )
    }
}

<#
.SYNOPSIS
Apply patches\openssl\*.patch to the OpenSSL tree, rewriting only files whose content changed.
#>
function Sync-OpenSslPatches {
    $src = Join-Path $third_party 'openssl'
    $scratch = Join-Path $janus_root 'build\openssl-scratch'
    $patches = Get-ChildItem (Join-Path $janus_root 'patches\openssl') -Filter '*.patch' | Sort-Object Name

    if (-not (Test-Path $scratch)) {
        & git -C $src worktree add --detach $scratch $openssl_base
        if ($LASTEXITCODE -ne 0) {
            throw "git worktree add failed: $scratch"
        }
    }

    & git -C $scratch reset -q --hard $openssl_base
    & git -C $scratch clean -fdq
    foreach ($patch in $patches) {
        & git -C $scratch apply --cached $patch.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "git apply failed: $($patch.Name)"
        }
    }
    & git -C $scratch checkout -- .

    $paths = @()
    $paths += & git -C $scratch diff --cached --name-only $openssl_base
    $paths += & git -C $src diff --name-only $openssl_base
    $paths += & git -C $src ls-files --others --exclude-standard
    foreach ($rel in ($paths | Where-Object { $_ } | Sort-Object -Unique)) {
        $from = Join-Path $scratch $rel
        $to = Join-Path $src $rel

        if (-not (Test-Path $from)) {
            Remove-Item -Force $to
            Write-Host "patch sync: removed $rel"
            continue
        }
        if ((Test-Path $to) -and ((Get-FileHash $from).Hash -eq (Get-FileHash $to).Hash)) {
            continue
        }

        Copy-Item -Force $from $to
        Write-Host "patch sync: updated $rel"
    }
}

<#
.SYNOPSIS
Run OpenSSL Configure once in the out-of-tree build directory.
#>
function Initialize-OpenSsl {
    if ($Reconfigure -and (Test-Path $openssl_build)) {
        Remove-Item -Recurse -Force $openssl_build
    }

    if (Test-Path (Join-Path $openssl_build 'makefile')) {
        return
    }

    New-Item -ItemType Directory -Force $openssl_build | Out-Null
    Push-Location $openssl_build
    try {
        $include_dir = Join-Path $deps_install 'include'
        $lib_dir = Join-Path $deps_install 'lib'
        $configure_args = @(
            (Join-Path $third_party 'openssl\Configure'),
            'VC-WIN64A',
            'no-shared',
            'no-tests',
            'no-docs',
            'zlib',
            "--with-zlib-include=$include_dir",
            "--with-zlib-lib=$(Join-Path $lib_dir 'zlibstatic.lib')",
            'enable-brotli',
            "--with-brotli-include=$include_dir",
            "--with-brotli-lib=$lib_dir",
            'enable-zstd',
            "--with-zstd-include=$include_dir",
            "--with-zstd-lib=$(Join-Path $lib_dir 'zstd_static.lib')",
            "--prefix=$openssl_install",
            "--openssldir=$(Join-Path $openssl_install 'ssl')"
        )

        & perl @configure_args
        if ($LASTEXITCODE -ne 0) {
            throw 'OpenSSL Configure failed'
        }
    }
    finally {
        Pop-Location
    }
}

<#
.SYNOPSIS
Build and install OpenSSL libraries and headers; nmake only rebuilds what changed.
#>
function Build-OpenSsl {
    Push-Location $openssl_build
    try {
        # configdata.pm -r cannot replace itself on Windows (the running script holds it open), so reconfigure via Configure
        $configdata = Get-Item 'configdata.pm'
        $stale = Get-ChildItem (Join-Path $third_party 'openssl') -Recurse -Filter 'build.info' |
            Where-Object { $_.LastWriteTime -gt $configdata.LastWriteTime }
        if ($stale) {
            & perl (Join-Path $third_party 'openssl\Configure') reconf
            if ($LASTEXITCODE -ne 0) {
                throw 'OpenSSL reconfigure failed'
            }
            if (-not (Select-String -Path 'configdata.pm' -Pattern 'janus\.c' -CaseSensitive -Quiet)) {
                throw 'OpenSSL reconfigure did not pick up ssl\janus.c'
            }
            $now = Get-Date
            (Get-Item 'configdata.pm').LastWriteTime = $now
            (Get-Item 'makefile').LastWriteTime = $now
        }

        & nmake /nologo build_sw
        if ($LASTEXITCODE -ne 0) {
            throw 'nmake build_sw failed'
        }

        & nmake /nologo install_sw
        if ($LASTEXITCODE -ne 0) {
            throw 'nmake install_sw failed'
        }
    }
    finally {
        Pop-Location
    }
}

Import-VsEnv
Build-Deps
Sync-OpenSslPatches
Initialize-OpenSsl
Build-OpenSsl

Write-Host "OpenSSL installed to $openssl_install"
