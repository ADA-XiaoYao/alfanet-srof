"""
SROF · Core Database Layer
SQLite-backed, swap to PostgreSQL via env var

Fix: unixepoch() requires SQLite >= 3.38.
     Use strftime('%s','now') for compatibility with SQLite 3.37+.
"""
import sqlite3, json, os, time
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from typing import Optional, List
from datetime import datetime

DB_PATH = Path(os.getenv("SROF_DB", str(Path(__file__).parent.parent / "data" / "srof.db")))


# ─── SCHEMA ──────────────────────────────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS workspaces (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at  INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS targets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER,
    protocol     TEXT DEFAULT 'tcp',
    scheme       TEXT,
    status       TEXT DEFAULT 'pending',   -- pending|active|done|error
    tags         TEXT DEFAULT '[]',        -- JSON array
    created_at   INTEGER DEFAULT (strftime('%s', 'now')),
    UNIQUE(workspace_id, host, port)
);

CREATE TABLE IF NOT EXISTS assets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,            -- subdomain|url|service|endpoint
    value        TEXT NOT NULL,
    metadata     TEXT DEFAULT '{}',        -- JSON: title, tech, status_code, cdn, ...
    discovered_at INTEGER DEFAULT (strftime('%s', 'now')),
    source       TEXT                      -- tool that found it
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id    INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    asset_id     INTEGER REFERENCES assets(id),
    plugin_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    severity     TEXT NOT NULL,            -- critical|high|medium|low|info
    cvss         REAL,
    cve          TEXT,
    description  TEXT,
    evidence     TEXT DEFAULT '{}',        -- JSON: request, response, payload
    status       TEXT DEFAULT 'open',      -- open|confirmed|false_positive|fixed
    found_at     INTEGER DEFAULT (strftime('%s', 'now')),
    confirmed_at INTEGER
);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE,
    type         TEXT NOT NULL,            -- recon|scan|exploit|ctf
    status       TEXT DEFAULT 'queued',    -- queued|running|done|error|cancelled
    config       TEXT DEFAULT '{}',        -- JSON
    result_count INTEGER DEFAULT 0,
    started_at   INTEGER,
    finished_at  INTEGER,
    error_msg    TEXT,
    created_at   INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS plugin_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id     INTEGER REFERENCES scan_jobs(id) ON DELETE CASCADE,
    plugin_id  TEXT,
    level      TEXT DEFAULT 'info',        -- debug|info|warn|error
    message    TEXT,
    data       TEXT DEFAULT '{}',
    ts         INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE,
    name         TEXT,
    steps        TEXT DEFAULT '[]',        -- JSON array of step objects
    created_at   INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_targets_workspace ON targets(workspace_id);
CREATE INDEX IF NOT EXISTS idx_assets_target     ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_vulns_target      ON vulnerabilities(target_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity    ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_jobs_workspace    ON scan_jobs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status       ON scan_jobs(status);
"""


# ─── CONNECTION ──────────────────────────────────────────────────────────────
def get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─── DATACLASSES ─────────────────────────────────────────────────────────────
@dataclass
class Target:
    host: str
    workspace_id: int
    port: Optional[int] = None
    protocol: str = "tcp"
    scheme: str = "https"
    status: str = "pending"
    tags: List[str] = None
    id: Optional[int] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

    @property
    def url(self) -> str:
        if self.port and self.port not in (80, 443):
            return f"{self.scheme}://{self.host}:{self.port}"
        return f"{self.scheme}://{self.host}"


@dataclass
class Asset:
    target_id: int
    type: str
    value: str
    source: str = ""
    metadata: dict = None
    id: Optional[int] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class Vulnerability:
    target_id: int
    plugin_id: str
    name: str
    severity: str
    description: str = ""
    evidence: dict = None
    cve: str = ""
    cvss: float = 0.0
    asset_id: Optional[int] = None
    id: Optional[int] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = {}


# ─── REPOSITORY ──────────────────────────────────────────────────────────────
class WorkspaceRepo:
    @staticmethod
    def create(name: str, description: str = "") -> int:
        with get_db() as db:
            cur = db.execute(
                "INSERT OR IGNORE INTO workspaces(name, description) VALUES(?,?)",
                (name, description)
            )
            if cur.lastrowid:
                return cur.lastrowid
            row = db.execute("SELECT id FROM workspaces WHERE name=?", (name,)).fetchone()
            return row["id"]

    @staticmethod
    def list_all() -> list:
        with get_db() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM workspaces ORDER BY updated_at DESC"
            ).fetchall()]

    @staticmethod
    def get(workspace_id: int) -> Optional[dict]:
        with get_db() as db:
            row = db.execute("SELECT * FROM workspaces WHERE id=?",
                             (workspace_id,)).fetchone()
            return dict(row) if row else None


class TargetRepo:
    @staticmethod
    def add(t: Target) -> int:
        with get_db() as db:
            tags_json = json.dumps(t.tags or [])
            cur = db.execute(
                """INSERT OR IGNORE INTO targets
                   (workspace_id, host, port, protocol, scheme, tags)
                   VALUES(?,?,?,?,?,?)""",
                (t.workspace_id, t.host, t.port, t.protocol, t.scheme, tags_json)
            )
            if cur.lastrowid:
                return cur.lastrowid
            row = db.execute(
                "SELECT id FROM targets WHERE workspace_id=? AND host=? AND port IS ?",
                (t.workspace_id, t.host, t.port)
            ).fetchone()
            return row["id"]

    @staticmethod
    def list_by_workspace(workspace_id: int) -> list:
        with get_db() as db:
            rows = db.execute(
                "SELECT * FROM targets WHERE workspace_id=? ORDER BY created_at DESC",
                (workspace_id,)
            ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["tags"] = json.loads(d.get("tags") or "[]")
                result.append(d)
            return result

    @staticmethod
    def update_status(target_id: int, status: str):
        with get_db() as db:
            db.execute("UPDATE targets SET status=? WHERE id=?", (status, target_id))


class AssetRepo:
    @staticmethod
    def add(a: Asset) -> int:
        with get_db() as db:
            cur = db.execute(
                """INSERT INTO assets(target_id, type, value, source, metadata)
                   VALUES(?,?,?,?,?)""",
                (a.target_id, a.type, a.value, a.source, json.dumps(a.metadata or {}))
            )
            return cur.lastrowid

    @staticmethod
    def bulk_add(assets: List[Asset]):
        with get_db() as db:
            db.executemany(
                """INSERT OR IGNORE INTO assets(target_id, type, value, source, metadata)
                   VALUES(?,?,?,?,?)""",
                [(a.target_id, a.type, a.value, a.source, json.dumps(a.metadata or {}))
                 for a in assets]
            )

    @staticmethod
    def list_by_target(target_id: int, asset_type: str = None) -> list:
        with get_db() as db:
            if asset_type:
                rows = db.execute(
                    "SELECT * FROM assets WHERE target_id=? AND type=? ORDER BY discovered_at DESC",
                    (target_id, asset_type)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM assets WHERE target_id=? ORDER BY discovered_at DESC",
                    (target_id,)
                ).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["metadata"] = json.loads(d.get("metadata") or "{}")
                result.append(d)
            return result


class VulnRepo:
    @staticmethod
    def add(v: Vulnerability) -> int:
        with get_db() as db:
            cur = db.execute(
                """INSERT INTO vulnerabilities
                   (target_id, asset_id, plugin_id, name, severity, cvss, cve,
                    description, evidence)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (v.target_id, v.asset_id, v.plugin_id, v.name, v.severity,
                 v.cvss, v.cve, v.description, json.dumps(v.evidence or {}))
            )
            return cur.lastrowid

    @staticmethod
    def list_by_workspace(workspace_id: int, severity: str = None) -> list:
        with get_db() as db:
            q = """SELECT v.*, t.host, t.port FROM vulnerabilities v
                   JOIN targets t ON v.target_id = t.id
                   WHERE t.workspace_id=?"""
            params = [workspace_id]
            if severity:
                q += " AND v.severity=?"
                params.append(severity)
            q += (" ORDER BY CASE v.severity"
                  " WHEN 'critical' THEN 1 WHEN 'high' THEN 2"
                  " WHEN 'medium' THEN 3 ELSE 4 END")
            rows = db.execute(q, params).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["evidence"] = json.loads(d.get("evidence") or "{}")
                result.append(d)
            return result

    @staticmethod
    def stats_by_workspace(workspace_id: int) -> dict:
        with get_db() as db:
            rows = db.execute(
                """SELECT v.severity, COUNT(*) as cnt
                   FROM vulnerabilities v JOIN targets t ON v.target_id=t.id
                   WHERE t.workspace_id=? GROUP BY v.severity""",
                (workspace_id,)
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}


class JobRepo:
    @staticmethod
    def create(workspace_id: int, job_type: str, config: dict = None) -> int:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO scan_jobs(workspace_id, type, config) VALUES(?,?,?)",
                (workspace_id, job_type, json.dumps(config or {}))
            )
            return cur.lastrowid

    @staticmethod
    def start(job_id: int):
        with get_db() as db:
            db.execute(
                "UPDATE scan_jobs SET status='running',"
                " started_at=strftime('%s','now') WHERE id=?",
                (job_id,)
            )

    @staticmethod
    def finish(job_id: int, result_count: int = 0):
        with get_db() as db:
            db.execute(
                "UPDATE scan_jobs SET status='done',"
                " finished_at=strftime('%s','now'),"
                " result_count=? WHERE id=?",
                (result_count, job_id)
            )

    @staticmethod
    def fail(job_id: int, error_msg: str):
        with get_db() as db:
            db.execute(
                "UPDATE scan_jobs SET status='error',"
                " finished_at=strftime('%s','now'),"
                " error_msg=? WHERE id=?",
                (error_msg, job_id)
            )

    @staticmethod
    def log(job_id: int, plugin_id: str, message: str,
            level: str = "info", data: dict = None):
        with get_db() as db:
            db.execute(
                "INSERT INTO plugin_logs"
                "(job_id, plugin_id, level, message, data) VALUES(?,?,?,?,?)",
                (job_id, plugin_id, level, message, json.dumps(data or {}))
            )


# ─── QUICK INIT ──────────────────────────────────────────────────────────────
def init_db():
    """Create DB schema and default workspace."""
    with get_db() as db:
        db.execute(
            "INSERT OR IGNORE INTO workspaces(name, description) VALUES(?,?)",
            ("default", "Default workspace")
        )
    return True
