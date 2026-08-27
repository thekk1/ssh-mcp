"""TOFU (trust-on-first-use) host key store.

First contact with a given host:port pins its SSH host key fingerprint to
a JSON file on disk; every later connection to the same host:port must
match that fingerprint exactly, or the connection is refused. That's the
difference between this and "never check a host key": it can't stop a
MITM on the very first contact, but it does stop one appearing later, and
it turns an unannounced host key rotation into a loud failure instead of a
silent MITM-shaped hole.

Reads/writes happen synchronously from asyncssh's SSHClient callback,
which is itself synchronous (no `await` points in its body) -- so plain
dict + file writes are safe here without any locking: nothing else runs on
the event loop mid-callback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


class HostKeyStore:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True))
        os.replace(tmp, self._path)

    @staticmethod
    def _key(host: str, port: int) -> str:
        return f"{host}:{port}"

    def get(self, host: str, port: int) -> Optional[str]:
        return self._data.get(self._key(host, port))

    def put(self, host: str, port: int, fingerprint: str) -> None:
        self._data[self._key(host, port)] = fingerprint
        self._save()
