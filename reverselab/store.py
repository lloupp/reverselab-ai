"""Opt-in local investigation history. Never persist API keys or original binaries."""
from __future__ import annotations

import json
from contextlib import closing
import os
import sqlite3
from pathlib import Path
from typing import Any
from uuid import uuid4


SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    file_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    goal TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    trace_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_sha
    ON investigations(file_sha256, created_at DESC);
"""


def database_path() -> Path:
    configured = os.environ.get('REVERSELAB_DB_PATH', '').strip()
    if configured:
        return Path(configured).expanduser()
    root = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local' / 'state')))
    return root / 'reverselab-ai' / 'investigations.sqlite3'


def _connect() -> sqlite3.Connection:
    db = database_path()
    db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    con = sqlite3.connect(db, timeout=4)
    con.executescript(SCHEMA)
    return con


def save_investigation(file_sha256: str, goal: str, provider: str, model: str,
                       status: str, summary: str, trace: list[dict[str, Any]]) -> str:
    """The caller passes a redacted bounded trace, *never* raw provider requests."""
    ident = uuid4().hex
    if len(file_sha256) != 64 or any(c not in '0123456789abcdef' for c in file_sha256):
        raise ValueError('SHA-256 inválido para histórico.')
    payload = json.dumps(trace, ensure_ascii=False)
    if len(payload) > 120_000:
        raise ValueError('Histórico excede o limite permitido.')
    with closing(_connect()) as con, con:
        con.execute('INSERT INTO investigations (id,file_sha256,goal,provider,model,status,summary,trace_json) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (ident, file_sha256, goal[:1200], provider[:30], model[:160], status[:30], summary[:3000], payload))
    return ident


def list_investigations(file_sha256: str, limit: int = 10) -> list[dict[str, Any]]:
    if len(file_sha256) != 64 or any(c not in '0123456789abcdef' for c in file_sha256):
        raise ValueError('SHA-256 inválido.')
    with closing(_connect()) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute('SELECT id,created_at,goal,provider,model,status,summary '
                           'FROM investigations WHERE file_sha256=? ORDER BY created_at DESC, rowid DESC LIMIT ?',
                           (file_sha256, min(20, max(1, limit)))).fetchall()
    return [dict(row) for row in rows]


def read_investigation(ident: str) -> dict[str, Any] | None:
    if len(ident) != 32 or any(c not in '0123456789abcdef' for c in ident):
        raise ValueError('Identificador de investigação inválido.')
    with closing(_connect()) as con:
        con.row_factory = sqlite3.Row
        row = con.execute('SELECT * FROM investigations WHERE id=?', (ident,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result['trace'] = json.loads(result.pop('trace_json'))
    return result
