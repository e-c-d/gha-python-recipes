#!/usr/bin/env python3

from __future__ import annotations

import contextlib
import tarfile
import zipfile
import dataclasses
from pathlib import Path, PurePosixPath
import json
from urllib import request as _ur
import hashlib
import tempfile
import shutil
import subprocess as sbp
import os
import re
import sys

from .dirhash import DirectoryHash
from .pypi_simple import pypi_resolve_url


here = Path(__file__).resolve().parent
metadata_json = json.loads((here / "metadata.json").read_bytes())


PathLike = str | Path


def run(args, **kwargs):
    print(args)
    return sbp.run(args, **kwargs)


def cmd_hash():
    hash_name = sys.argv[2]
    hash_function = lambda: hashlib.new(hash_name)
    dih = DirectoryHash(hash_function)
    for path in sys.argv[3:]:
        print(dih(path).hex())


def _prepare_for_extract(p: str | PurePosixPath, n: int, out: Path) -> PurePosixPath | None:
    parts = PurePosixPath(p).parts[n:]
    if not parts:
        return None
    else:
        rp = PurePosixPath(*parts)
        p = out / rp
        p.parent.mkdir(exist_ok=True, parents=True)
        return p


def unpack_zip(path_source: Path, path_target: Path, strip_components: int = 0) -> None:
    path_target.mkdir(exist_ok=True, parents=True)
    with path_source.open("rb") as f:
        zf = zipfile.ZipFile(f)
        for info in zf.infolist():
            if info.is_dir():
                continue
            p = _prepare_for_extract(info.filename, strip_components, path_target)
            if p is None:
                continue
            with zf.open(info) as f_r, p.open("wb") as f_w:
                shutil.copyfileobj(f_r, f_w)


def unpack_tar(path_source: Path, path_target: Path, strip_components: int = 0) -> None:
    path_target.mkdir(exist_ok=True, parents=True)
    with tarfile.open(str(path_source), "r") as zf:
        while (info := zf.next()) is not None:
            if not info.isfile():
                continue
            p = _prepare_for_extract(info.name, strip_components, path_target)
            if p is None:
                continue
            zf.makefile(info, str(p))


@contextlib.contextmanager
def verifying_dir_hash(target: Path, hash_function, hash_value: str):
    target.parent.mkdir(exist_ok=True, parents=True)
    if target.exists():
        raise ValueError("already exists: {target!s}")
    with tempfile.TemporaryDirectory(dir=target.parent, prefix="unverified.") as tmpdir:
        (tmp_location := Path(tmpdir) / "p").mkdir()
        yield tmp_location
        if DirectoryHash(hash_function)(tmp_location).hex().lower() != hash_value.lower():
            raise ValueError("directory content hash does not match")
        tmp_location.rename(target)


@dataclasses.dataclass(eq=False)
class StreamProcessorHash:
    hash_function: object

    def __call__(self, block: bytes):
        self.hash_function.update(block)

    def assert_hex_digest(self, value: str):
        if (a := self.hash_function.hexdigest().lower()) != (b := value.lower()):
            raise ValueError(f"hash {a} did not match expected value {b}")


@dataclasses.dataclass(eq=False)
class StreamProcessorSizeLimiter:
    limit: int
    size_so_far = 0

    def __call__(self, block: bytes):
        self.size_so_far += len(block)
        if self.size_so_far > self.limit:
            raise ValueError(f"read size exceeded limit {self.size_so_far}")


@dataclasses.dataclass(eq=False)
class Downloader:
    data: dict = dataclasses.field(default=None)

    def __post_init__(self):
        if self.data is None:
            self.data = metadata_json["downloads"]

    def download(self, name: str, target: PathLike) -> None:
        if isinstance(target, str) and target.endswith("/"):
            target = Path(target) / name
        else:
            target = Path(target)

        meta = self.data[name]
        target.parent.mkdir(exist_ok=True, parents=True)

        url = meta["url"]
        if url.endswith("#"):
            url = f"{url}/{name}"
        url = pypi_resolve_url(url)

        req = _ur.Request(url, headers={"User-Agent": "Wget/1.21.3"})
        size_buf = 65536
        processors = [StreamProcessorSizeLimiter(10**8)]
        processors.append(hasher := StreamProcessorHash(hashlib.sha512()))
        with tempfile.TemporaryDirectory(dir=str(target.parent)) as tmpdir:
            tmpdir = Path(tmpdir)
            if target.exists():
                # File already exists, so let's check the hash.
                target.rename(existing := tmpdir / "f.tmp")
                reader = existing.open("rb")
            else:
                # File does not exist, we must download it.
                reader = _ur.urlopen(req)

            with reader as fr, (path_tmp := Path(tmpdir) / "dl.tmp").open("wb") as fw:
                while True:
                    block = fr.read(size_buf)
                    if not block:
                        break
                    for processor in processors:
                        processor(block)
                    fw.write(block)

            if h := meta.get("hash_sha512"):
                hasher.assert_hex_digest(h)
            else:
                if not target.name.startswith("unverified-"):
                    raise AssertionError('filename must start with "unverified-" when no hash')
            path_tmp.rename(target)


def get_vs_env() -> dict[str, str]:
    vs_bat = Path(
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "e.bat"
        with path.open("wt", newline="\r\n") as f:
            f.write(
                f"""@echo off
call "{vs_bat}" %*
set
"""
            )
        ret = run([str(path)], check=True, capture_output=True)
        output = ret.stdout.decode("utf-8")
        return {
            k: v for k, _, v in (line.partition("=") for line in output.splitlines(keepends=False))
        }


def fix_env(env) -> None:
    sep = os.pathsep

    # Enter the compiler environment.
    for k, v in get_vs_env().items():
        env[k] = v

    paths = env["PATH"].split(sep)

    # Make Strawberry Perl come before anything else such as the mingw Perl.
    paths.sort(key=lambda x: 0 if ("Strawberry" in x) else 1)

    env["PATH"] = sep.join(paths)


def get_python_dlls_path():
    return Path(sys.executable).parent / "DLLs"


def convert_dll_to_def_to_lib(path_dll: Path, path_lib: Path, run_kw) -> None:
    path_def = path_dll.with_suffix(".def")
    run(["gendef", path_dll.name], check=True, cwd=str(path_dll.resolve().parent), **run_kw)
    assert path_def.exists(), f"file not found {path_def!r}"
    run(["lib", f"/def:{path_def!s}", f"/out:{path_lib!s}"], check=True, **run_kw)
    assert path_lib.exists(), f"file not found {path_lib!r}"


def cmd_download_sqlcipher():
    dl = Downloader()
    dl.download("sqlcipher-4.9.0.zip", "dl/sqlcipher.zip")
    dl.download("openssl-3.4.1.tar.gz", "dl/openssl.tar.gz")
    # dl.download("tcl-9.0.1.tar.gz", "dl/tcl.tar.gz")  # tests don't work yet


def cmd_download_stoken_bfasst():
    dl = Downloader()
    dl.download("setuptools-80.1.0-py3-none-any.whl", "dl/")
    dl.download("stoken_bfasst-1.1.0.tar.gz", "dl/")
    dl.download("openssl-3.4.1.tar.gz", "dl/openssl.tar.gz")


def cmd_download_freerdp():
    dl = Downloader()
    dl.download("openssl-3.4.1.tar.gz", "dl/openssl.tar.gz")
    dl.download("freerdp-3.15.0.tar.gz", "dl/freerdp.tar.gz")
    dl.download("zlib-1.3.1.tar.gz", "dl/zlib.tar.gz")


def cmd_fake_compile_openssl(target="openssl", source="dl/openssl.tar.gz"):
    target = _Path(target)
    source = _Path(source)

    unpack_tar(source, target, strip_components=1)

    kw = dict(check=True, cwd=str(target))
    run("perl Configure VC-WIN64A-masm no-asm no-unit-test".split(), **kw)
    run("nmake build_generated".split(), **kw)

    for name in ("demos", "doc", "fuzz", "test"):
        shutil.rmtree(str(target / name))

    dlls_path = get_python_dlls_path()
    rx = re.compile(r"^(libcrypto|libssl)-\d+(\.dll)$")
    dlls = [(p, m.group(1) + ".lib") for p in dlls_path.iterdir() if (m := rx.search(p.name))]
    if len(dlls) != 2:
        raise AssertionError(f"expected 2 dlls, found: {dlls!r}")

    for p, name_lib in dlls:
        shutil.copyfile(str(p), str(dll_path := target / p.name))
        convert_dll_to_def_to_lib(dll_path, target / name_lib, run_kw={})


def cmd_fake_compile_zlib(target="zlib", source="dl/zlib.tar.gz"):
    target = _Path(target)
    source = _Path(source)

    unpack_tar(source, target, strip_components=1)

    dlls_path = get_python_dlls_path()
    rx = re.compile(r"^(zlib\d*)(\.dll)$")
    dlls = [(p, m.group(1) + ".lib") for p in dlls_path.iterdir() if (m := rx.search(p.name))]
    if len(dlls) != 1:
        raise AssertionError(f"expected 2 dlls, found: {dlls!r}")

    for p, name_lib in dlls:
        shutil.copyfile(str(p), str(dll_path := target / p.name))
        convert_dll_to_def_to_lib(dll_path, target / name_lib, run_kw={})


def cmd_build_sqlcipher(
    path_openssl: PathLike = "openssl",
    path_sqlcipher: PathLike = "sqlcipher",
    path_sqlcipher_dl="dl/sqlcipher.zip",
):
    path_openssl = _Path(path_openssl)
    path_sqlcipher = _Path(path_sqlcipher)
    path_sqlcipher_dl = _Path(path_sqlcipher_dl)

    unpack_zip(path_sqlcipher_dl, path_sqlcipher, strip_components=1)

    env_opts = [f'-I"{path_openssl}/include"']
    env_opts += """
-DSQLITE_TEMP_STORE=2
-DSQLITE_HAS_CODEC=1
-DSQLITE_EXTRA_INIT=sqlcipher_extra_init
-DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown
-DSQLITE_ENABLE_COLUMN_METADATA=1
-DSQLITE_ENABLE_DBSTAT_VTAB=1
-DSQLITE_ENABLE_FTS3=1
-DSQLITE_ENABLE_FTS3_PARENTHESIS=1
-DSQLITE_ENABLE_FTS3_TOKENIZER=1
-DSQLITE_ENABLE_FTS4=1
-DSQLITE_ENABLE_FTS5=1
-DSQLITE_ENABLE_JSON1=1
-DSQLITE_ENABLE_GEOPOLY=1
-DSQLITE_ENABLE_LOAD_EXTENSION=1
-DSQLITE_ENABLE_PREUPDATE_HOOK=1
-DSQLITE_ENABLE_RTREE=1
-DSQLITE_ENABLE_SESSION=1
-DSQLITE_ENABLE_STAT4=1
-DSQLITE_ENABLE_STMTVTAB=1
-DSQLITE_ENABLE_UNLOCK_NOTIFY=1
-DSQLITE_ENABLE_UPDATE_DELETE_LIMIT=1
-DSQLITE_ENABLE_SERIALIZE=1
-DSQLITE_ENABLE_MATH_FUNCTIONS=1
-DSQLITE_HAVE_ISNAN=1
-DSQLITE_LIKE_DOESNT_MATCH_BLOBS=1
-DSQLITE_MAX_SCHEMA_RETRY=50
-DSQLITE_MAX_VARIABLE_NUMBER=250000
-DSQLITE_OMIT_LOOKASIDE=1
-DSQLITE_SECURE_DELETE=1
-DSQLITE_SOUNDEX=1
-DSQLITE_THREADSAFE=1
-DSQLITE_USE_URI=1
-DHAVE_STDINT_H=1
""".split()
    env_opts = " ".join(env_opts)

    opts = (
        "USE_CRT_DLL=1",
        "WIN32HEAP=1",
        f'LTLIBPATHS="/LIBPATH:{path_openssl}"',
        "LTLIBS=libcrypto.lib libssl.lib",
    )

    def _make_command(args):
        xs = ["nmake", "/f", "makefile.msc"]
        xs += args
        xs.append("NO_TCL=1")
        xs += opts
        return xs

    env = os.environ | {"OPTS": env_opts}
    env["CC"] = env["CXX"] = "cl.exe"
    kw = dict(check=True, cwd=str(path_sqlcipher), env=env)

    for x in ("sqlite3.c", "sqlite3.dll", "sqlite3.exe"):
        run(_make_command([x]), **kw)


def pipi(paths):
    cmd = [sys.executable]
    cmd += "-m pip install --no-index --no-build-isolation --break-system-packages".split()
    cmd += (str(Path(p).resolve()) for p in paths)
    run(cmd, check=True)


def cmd_install_setuptools():
    pipi(Path("dl").glob("setuptools-*.whl"))


def cmd_build_stoken_bfasst():
    path_openssl = _Path("openssl")
    path_sb = _Path("stoken_bfasst")

    # with verifying_dir_hash(
    #     path_sb,
    #     lambda: hashlib.new("sha512"),
    #     metadata_json["dir_hash_sha512"]["stoken_bfasst-1.1.0"],
    # ) as d:
    #     unpack_tar("dl/unverified-stoken_bfasst.tar.gz", d, strip_components=1)

    [archive] = _Path("dl").glob("stoken_bfasst*.tar.gz")
    unpack_tar(archive, path_sb, strip_components=1)

    env = os.environ.copy()
    opts = ["-GNinja", f"-DOPENSSL_ROOT_DIR={path_openssl!s}"]
    env["STOKEN_BFASST_CMAKE_OPTS"] = json.dumps(opts)
    run([sys.executable, "setup.py", "bdist_wheel"], cwd=str(path_sb), env=env, check=True)


def _assemble(source, target, rx):
    target.mkdir(parents=True, exist_ok=True)
    for p in source.glob("**/*"):
        if p.is_file() and rx.search(p.name):
            shutil.copyfile(str(p), str(target / p.name))


def cmd_assemble_sqlcipher():
    target = Path("sqlcipher-final")
    source = Path("sqlcipher")
    rx = re.compile(r"^(lib)?sqlite.*\.(dll|lib|exe)$")
    _assemble(source, target, rx)


def cmd_assemble_freerdp():
    target = Path("freerdp-final")
    source = Path("freerdp-build")
    rx = re.compile(r"(w?freerdp|winpr).*\.(dll|lib|exe|pdb)$")
    _assemble(source, target, rx)


def cmd_assemble_stoken_bfasst():
    target = _Path("stoken_bfasst-final")
    source = _Path("stoken_bfasst") / "dist"
    rx = re.compile(r"\.whl$")
    _assemble(source, target, rx)


def _Path(p):
    return Path(p).resolve()


def cmd_build_freerdp(
    path_openssl: PathLike = "openssl",
    path_zlib: PathLike = "zlib",
    path_freerdp: PathLike = "freerdp",
    path_freerdp_build: PathLike = "freerdp-build",
    path_freerdp_dl: PathLike = "dl/freerdp.tar.gz",
):
    path_openssl = _Path(path_openssl)
    path_zlib = _Path(path_zlib)
    path_freerdp = _Path(path_freerdp)
    path_freerdp_build = _Path(path_freerdp_build)
    path_freerdp_dl = _Path(path_freerdp_dl)

    unpack_tar(path_freerdp_dl, path_freerdp, strip_components=1)

    os.environ["CC"] = os.environ["CXX"] = "cl.exe"

    # -DZLIB_ROOT_DIR=$parent/zlib-build
    # "-DCMAKE_INSTALL_PREFIX=$inst" `

    # "-DOPENSSL_INCLUDE_DIR=$parent/openssl/include" `
    # "-DOPENSSL_CRYPTO_LIBRARY=$parent/openssl/libcrypto-3.dll" `
    # "-DOPENSSL_SSL_LIBRARY=$parent/openssl/libssl-3.dll" `

    kw = dict(check=True)

    opts = ["cmake", "-GNinja", "-S", str(path_freerdp), "-B", str(path_freerdp_build)]
    opts += """
-DCMAKE_BUILD_TYPE=Release -DCHANNEL_URBDRC=OFF -DMONOLITHIC_BUILD=ON -DWITH_JPEG=OFF
-DWITH_SERVER=OFF -DWITH_SAMPLE=OFF -DWITH_PLATFORM_SERVER=OFF -DUSE_UNWIND=OFF -DWITH_WEBVIEW=OFF
-DWITH_DSP_FFMPEG=OFF -DWITH_VIDEO_FFMPEG=OFF -DWITH_FFMPEG=OFF
-DWITH_SWSCALE=OFF -DWITH_OPUS=OFF
""".split()
    [zlib_lib] = path_zlib.glob("*.lib")
    opts += (
        f"-DOPENSSL_ROOT_DIR={path_openssl!s}",
        f"-DZLIB_INCLUDE_DIR={path_zlib!s}",
        f"-DZLIB_LIBRARY={zlib_lib!s}",
    )

    run(opts, **kw)
    run(["cmake", "--build", str(path_freerdp_build)], **kw)


def main():
    name = sys.argv[1]
    if name != "hash":
        fix_env(os.environ)
    globals()["cmd_" + name]()


if __name__ == "__main__":
    main()
