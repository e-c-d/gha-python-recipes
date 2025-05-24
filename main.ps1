$ErrorActionPreference = "Stop"

# Set-PSDebug -Trace 2

$download_files = (Get-Content -Raw "downloads.json") | ConvertFrom-Json -AsHashtable

function New-TemporaryDirectory {
    param ([string]$parent)

    if ($parent -eq "") {
        $parent = [System.IO.Path]::GetTempPath()
    }
    $name = [System.IO.Path]::GetRandomFileName()
    $item = New-Item -ItemType Directory -Path (Join-Path $parent $name)
    return $item.FullName
}

function Resolve-LiteralPathForced {
    <#
    .SYNOPSIS
        Calls Resolve-Path but works for files that don't exist.
    .REMARKS
        From http://devhawk.net/blog/2010/1/22/fixing-powershells-busted-resolve-path-cmdlet
    #>
    param ([string]$FileName)

    $FileName = Resolve-Path -LiteralPath $FileName -ErrorAction SilentlyContinue `
        -ErrorVariable _frperror
    if (-not($FileName)) {
        $FileName = $_frperror[0].TargetObject
    }

    return $FileName
}

function Invoke-MkdirP {
    param ([string]$path)
    New-Item $path -ItemType Directory -ea 0
}

function Invoke-RmRecursiveForce {
    param ([string]$path)
    Remove-Item -LiteralPath "$path" -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-FileFromInternetAndCheckHash {
    param (
        $url,
        $sha512,
        $path
    )

    $temporary = New-TemporaryFile

    Invoke-MkdirP ($path | Split-Path -Parent)

    if (Test-Path $path) {
        # it's in cache
        Remove-Item $temporary -ErrorAction Ignore
        Move-Item $path $temporary
    }
    else
    {
        Invoke-WebRequest -OutFile $temporary -Uri "$url" -UserAgent "Wget/1.21.1" -MaximumRedirection 10 -AllowInsecureRedirect
    }

    # check hash
    $actual_hash = (Get-FileHash $temporary -Algorithm SHA512).Hash
    if ($actual_hash.ToUpper() -eq $sha512.ToUpper())
    {
        Move-Item $temporary $path
    }
    else
    {
        throw "Hash check failed - file $url had hash $actual_hash, should be $sha512"
    }
}

function Get-SecureDownload {
    param([string]$path, [string]$name)
    $e = $download_files[$name]
    if ($path[-1] -eq "/") {
        $path = Join-Path $path $name
    }
    Get-FileFromInternetAndCheckHash $e["url"] $e["hash_sha512"] $path
}

function Enter-CompilerEnvironment {
    Invoke-BatchFile "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
}

function Get-PythonEnvironment {
    "C:\hostedtoolcache\windows\Python\3.13.3\x64"
}

function Convert-DLLToLib {
    param([string]$dll, [string]$lib)
    $def = [System.IO.Path]::ChangeExtension($dll, '.def')
    if ($lib -eq "") {
      $lib = [System.IO.Path]::ChangeExtension($dll, '.lib')
    }
    & gendef "$dll"
    & lib "/def:$def" "/out:$lib"
}

function Prepare-FakeCompileOpenSSL {
    Enter-CompilerEnvironment

    Invoke-MkdirP openssl
    cd openssl
    & tar --strip-components=1 -xf ../dl/openssl.tar.gz

    # Configure, but don't actually build it. We will reuse the built DLLs from Python.
    perl Configure VC-WIN64A-masm no-asm no-unit-test

    # Build generated header files. For example, turn "opensslv.h.in" into "opensslv.h"
    & nmake build_generated

    Invoke-FakeCompileOpenSSL "$(Get-PythonEnvironment)/DLLs"
    cd ..
}

function Prepare-CompileSQLCipher {
    param([string]$root)
    $parent = Resolve-LiteralPathForced $root

    $vopts = @(
        "-DSQLITE_TEMP_STORE=2",
        "-DSQLITE_HAS_CODEC=1",
        "-DSQLITE_EXTRA_INIT=sqlcipher_extra_init",
        "-DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown",

        "-DSQLITE_ENABLE_COLUMN_METADATA=1",
        "-DSQLITE_ENABLE_DBSTAT_VTAB=1",
        "-DSQLITE_ENABLE_FTS3=1",
        "-DSQLITE_ENABLE_FTS3_PARENTHESIS=1",
        "-DSQLITE_ENABLE_FTS3_TOKENIZER=1",
        "-DSQLITE_ENABLE_FTS4=1",
        "-DSQLITE_ENABLE_FTS5=1",
        "-DSQLITE_ENABLE_JSON1=1",
        "-DSQLITE_ENABLE_GEOPOLY=1",
        "-DSQLITE_ENABLE_LOAD_EXTENSION=1",
        "-DSQLITE_ENABLE_PREUPDATE_HOOK=1",
        "-DSQLITE_ENABLE_RTREE=1",
        "-DSQLITE_ENABLE_SESSION=1",
        "-DSQLITE_ENABLE_STAT4=1",
        "-DSQLITE_ENABLE_STMTVTAB=1",
        "-DSQLITE_ENABLE_UNLOCK_NOTIFY=1",
        "-DSQLITE_ENABLE_UPDATE_DELETE_LIMIT=1",
        "-DSQLITE_ENABLE_SERIALIZE=1",
        "-DSQLITE_ENABLE_MATH_FUNCTIONS=1",
        "-DSQLITE_HAVE_ISNAN=1",
        "-DSQLITE_LIKE_DOESNT_MATCH_BLOBS=1",
        "-DSQLITE_MAX_SCHEMA_RETRY=50",
        "-DSQLITE_MAX_VARIABLE_NUMBER=250000",
        "-DSQLITE_OMIT_LOOKASIDE=1",
        "-DSQLITE_SECURE_DELETE=1",
        "-DSQLITE_SOUNDEX=1",
        "-DSQLITE_THREADSAFE=1",
        "-DSQLITE_USE_URI=1",

        "-DHAVE_STDINT_H=1",

        "-I`"$parent\openssl\include`""
    )

    $opts = @(
        "USE_CRT_DLL=1", "WIN32HEAP=1",
        "LTLIBPATHS=`"/LIBPATH:$parent\openssl`"",
        "LTLIBS=libcrypto.lib libssl.lib"
    )

    $Env:CC = "cl.exe"
    $Env:CXX = "cl.exe"
    $Env:OPTS = $vopts -join " "

    return $opts
}

function Prepare-FakeCompileZlib {
    Enter-CompilerEnvironment

    Invoke-MkdirP zlib
    & tar -C zlib --strip-components=1 -xf dl/zlib.tar.gz

    # cmake -GNinja `
    #     -B zlib-build `
    #     -S zlib `
    #     "-DCMAKE_INSTALL_PREFIX=$inst" `
    #     -DCMAKE_BUILD_TYPE=Release `
    #     -DCMAKE_SKIP_INSTALL_ALL_DEPENDENCY=ON
    # cmake --build zlib-build
    # cmake --install zlib-build

    cd zlib
    Invoke-FakeCompileZlib "$(Get-PythonEnvironment)/DLLs"
    cd ..
}

function Invoke-FakeCompileOpenSSL {
    param([string]$source)

    Remove-Item -LiteralPath @("demos", "doc", "fuzz", "test") -Recurse
    foreach ($x in @("libcrypto-3", "libssl-3")) {
        Copy-Item -LiteralPath "$source/$x.dll" -Destination .
    }
    Convert-DLLToLib "libcrypto-3.dll" "libcrypto.lib"
    Convert-DLLToLib "libssl-3.dll" "libssl.lib"
}

function Invoke-FakeCompileZlib {
    param([string]$source)

    Copy-Item -LiteralPath "$source/zlib1.dll" -Destination .
    Convert-DLLToLib "zlib1.dll"
}

function Invoke-BatchFile {
    param([string]$Path, [string]$Parameters)

    try {
        $tmp = New-TemporaryDirectory
        $p = "$tmp/a.bat"
        "@echo off`r`ncall `"$Path`" %*`r`nset`r`n" | Out-File -FilePath $p -Encoding ascii
        $output = & $p
    } finally {
        Invoke-RmRecursiveForce $tmp
    }

    ## Go through the environment variables in the temp file.
    ## For each of them, set the variable in our local environment.
    $output -split "`n" | Foreach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            Set-Content "env:\$($matches[1])" $matches[2]
        }
    }
}
