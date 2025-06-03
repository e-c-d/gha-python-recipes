from __future__ import annotations

import dataclasses
from pathlib import Path
import typing as ty


@dataclasses.dataclass(eq=False)
class DirectoryHash:
    """Simple recursive directory hasher"""

    hash_function: callable
    _buf_size = 65536

    def __call__(self, path: Path | str) -> bytes:
        path = Path(path)
        if path.is_symlink():
            meth = self._get_data_for_symlink
        elif path.is_dir():
            meth = self._get_data_for_directory
        elif path.is_file():
            meth = self._get_data_for_file
        else:
            raise AssertionError("invalid file type: {path!r}")

        h = self.hash_function()
        for data in meth(path):
            h.update(data)
        return h.digest()

    @staticmethod
    def _lencode(s: bytes) -> ty.Iterable[bytes]:
        """prefix the string with its length"""
        return str(len(s)).encode("ascii"), b",", s

    @staticmethod
    def _fs_encode(s: str | Path) -> bytes:
        return str(s).encode("utf-8")

    def _get_data_for_file(self, path: Path):
        yield b"f"
        with path.open("rb") as f:
            while block := f.read(self._buf_size):
                yield block

    def _get_data_for_symlink(self, path: Path):
        target = self._fs_encode(path.readlink())
        yield b"l"
        yield from self._lencode(target)

    def _get_data_for_directory(self, path: Path):
        yield b"d"

        # encode child names as utf-8, then sort lexicographically
        enc = self._fs_encode
        items = [(enc(p.name), p) for p in path.iterdir()]
        items.sort()

        for p_name, p in items:
            yield from self._lencode(p_name)
            yield self(p)  # recurse into child
