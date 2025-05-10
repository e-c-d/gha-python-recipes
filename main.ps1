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
        Invoke-WebRequest -OutFile $temporary -Uri "$url"
    }

    # check hash
    $actual_hash = (Get-FileHash $temporary -Algorithm SHA512).Hash
    if ($actual_hash.ToUpper() -eq $sha512.ToUpper())
    {
        Move-Item $temporary $path
    }
    else
    {
        "Hash check failed - file $url had hash $sha512, should be $actual_hash" | Write-Debug
        throw "Hash check failed"
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
