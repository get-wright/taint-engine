"""SQLite-backed index store for symbols, references, and imports.

Provides incremental indexing — only re-indexes files whose mtime or
content hash has changed since the last index run.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from .base import ImportEntry, ResolvedSymbol, SymbolInfo

if TYPE_CHECKING:
    from .symbol_extractor import ReferenceInfo

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    path TEXT UNIQUE NOT NULL,
    mtime REAL NOT NULL,
    content_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    line INTEGER NOT NULL,
    col INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_col INTEGER NOT NULL,
    scope TEXT,
    UNIQUE(file_id, name, line)
);

CREATE TABLE IF NOT EXISTS refs (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    symbol_name TEXT NOT NULL,
    line INTEGER NOT NULL,
    col INTEGER NOT NULL,
    kind TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    local_name TEXT NOT NULL,
    source_module TEXT NOT NULL,
    imported_name TEXT,
    line INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_refs_name ON refs(symbol_name);
CREATE INDEX IF NOT EXISTS idx_imports_local ON imports(local_name);
CREATE INDEX IF NOT EXISTS idx_imports_source ON imports(source_module);
"""


class IndexStore:
    """SQLite index for files, symbols, references, and imports."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def upsert_file(self, path: str, *, mtime: float, content_hash: str) -> int:
        """Insert or update a file record. Returns the file ID."""
        self._conn.execute(
            """INSERT INTO files (path, mtime, content_hash)
               VALUES (?, ?, ?)
               ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime, content_hash=excluded.content_hash""",
            (path, mtime, content_hash),
        )
        self._conn.commit()
        row = self._conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()
        return row[0]

    def is_file_current(self, path: str, *, mtime: float, content_hash: str) -> bool:
        """Check if a file's index is up to date."""
        row = self._conn.execute(
            "SELECT mtime, content_hash FROM files WHERE path=?", (path,)
        ).fetchone()
        if row is None:
            return False
        return row[0] == mtime and row[1] == content_hash

    def _file_id(self, path: str) -> int | None:
        row = self._conn.execute("SELECT id FROM files WHERE path=?", (path,)).fetchone()
        return row[0] if row else None

    def replace_symbols(self, path: str, symbols: list[SymbolInfo]) -> None:
        """Replace all symbols for a file."""
        fid = self._file_id(path)
        if fid is None:
            return
        self._conn.execute("DELETE FROM symbols WHERE file_id=?", (fid,))
        self._conn.executemany(
            "INSERT INTO symbols (file_id, name, kind, line, col, end_line, end_col, scope) VALUES (?,?,?,?,?,?,?,?)",
            [(fid, s.name, s.kind, s.line, s.col, s.end_line, s.end_col, s.scope) for s in symbols],
        )
        self._conn.commit()

    def lookup_symbol(self, name: str) -> list[SymbolInfo]:
        """Find all symbols with a given name across all files."""
        rows = self._conn.execute(
            "SELECT s.name, s.kind, s.line, s.col, s.end_line, s.end_col, s.scope FROM symbols s WHERE s.name=?",
            (name,),
        ).fetchall()
        return [SymbolInfo(name=r[0], kind=r[1], line=r[2], col=r[3], end_line=r[4], end_col=r[5], scope=r[6]) for r in rows]

    def lookup_symbol_in_file(self, path: str, name: str) -> SymbolInfo | None:
        """Find a symbol by name in a specific file."""
        fid = self._file_id(path)
        if fid is None:
            return None
        row = self._conn.execute(
            "SELECT name, kind, line, col, end_line, end_col, scope FROM symbols WHERE file_id=? AND name=?",
            (fid, name),
        ).fetchone()
        if row is None:
            return None
        return SymbolInfo(name=row[0], kind=row[1], line=row[2], col=row[3], end_line=row[4], end_col=row[5], scope=row[6])

    def get_symbols_for_file(self, path: str) -> list[SymbolInfo]:
        """Get all symbols in a file, sorted by line."""
        fid = self._file_id(path)
        if fid is None:
            return []
        rows = self._conn.execute(
            "SELECT name, kind, line, col, end_line, end_col, scope FROM symbols WHERE file_id=? ORDER BY line",
            (fid,),
        ).fetchall()
        return [SymbolInfo(name=r[0], kind=r[1], line=r[2], col=r[3], end_line=r[4], end_col=r[5], scope=r[6]) for r in rows]

    def replace_references(self, path: str, refs: list[ReferenceInfo]) -> None:
        """Replace all references for a file."""
        fid = self._file_id(path)
        if fid is None:
            return
        self._conn.execute("DELETE FROM refs WHERE file_id=?", (fid,))
        self._conn.executemany(
            "INSERT INTO refs (file_id, symbol_name, line, col, kind) VALUES (?,?,?,?,?)",
            [(fid, r.symbol_name, r.line, r.col, r.kind) for r in refs],
        )
        self._conn.commit()

    def count_references(self, path: str, symbol_name: str) -> int:
        """Count references to a symbol within a specific file."""
        fid = self._file_id(path)
        if fid is None:
            return 0
        row = self._conn.execute(
            "SELECT COUNT(*) FROM refs WHERE file_id=? AND symbol_name=?",
            (fid, symbol_name),
        ).fetchone()
        return row[0]

    def replace_imports(self, path: str, imports: list[ImportEntry]) -> None:
        """Replace all imports for a file."""
        fid = self._file_id(path)
        if fid is None:
            return
        self._conn.execute("DELETE FROM imports WHERE file_id=?", (fid,))
        self._conn.executemany(
            "INSERT INTO imports (file_id, local_name, source_module, imported_name, line) VALUES (?,?,?,?,?)",
            [(fid, i.local_name, i.source_module, i.imported_name, i.line) for i in imports],
        )
        self._conn.commit()

    def lookup_imports_by_file(self, path: str) -> list[ImportEntry]:
        """Get all imports in a file."""
        fid = self._file_id(path)
        if fid is None:
            return []
        rows = self._conn.execute(
            "SELECT local_name, source_module, imported_name, line FROM imports WHERE file_id=? ORDER BY line",
            (fid,),
        ).fetchall()
        return [ImportEntry(local_name=r[0], source_module=r[1], imported_name=r[2], line=r[3]) for r in rows]

    def lookup_import(self, path: str, local_name: str) -> ImportEntry | None:
        """Find a specific import by its local name in a file."""
        fid = self._file_id(path)
        if fid is None:
            return None
        row = self._conn.execute(
            "SELECT local_name, source_module, imported_name, line FROM imports WHERE file_id=? AND local_name=?",
            (fid, local_name),
        ).fetchone()
        if row is None:
            return None
        return ImportEntry(local_name=row[0], source_module=row[1], imported_name=row[2], line=row[3])

    def resolve_symbol(self, name: str) -> list[ResolvedSymbol]:
        """Find all definitions of a symbol name across indexed files."""
        rows = self._conn.execute(
            """SELECT f.path, s.name, s.kind, s.line, s.col, s.end_line, s.end_col, s.scope
               FROM symbols s JOIN files f ON s.file_id=f.id
               WHERE s.name=?""",
            (name,),
        ).fetchall()
        return [
            ResolvedSymbol(
                file_path=r[0],
                name=r[1],
                kind=r[2],
                line=r[3],
                col=r[4],
                end_line=r[5],
                end_col=r[6],
                scope=r[7],
            )
            for r in rows
        ]
