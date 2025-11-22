#!/usr/bin/env python3
"""
Santamon Backend - Minimal FastAPI receiver for Raspberry Pi

Installation:
    pip install fastapi uvicorn

Run:
    uvicorn backend:app --host 0.0.0.0 --port 8443
"""

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from contextlib import asynccontextmanager
import sqlite3
from datetime import datetime, timedelta
import json
from typing import Optional, List
import os
import secrets
from pathlib import Path

# Configuration
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.getenv("SANTAMON_DB_PATH", "signals.db")
API_KEY = os.getenv("SANTAMON_API_KEY")
MIN_API_KEY_LENGTH = 16
ALLOWED_STATUSES = {"open", "acknowledged", "resolved"}

# Enforce API key presence and minimum length at startup
if not API_KEY:
    raise RuntimeError("SANTAMON_API_KEY environment variable is required")
if len(API_KEY) < MIN_API_KEY_LENGTH:
    raise RuntimeError(
        f"SANTAMON_API_KEY must be at least {MIN_API_KEY_LENGTH} characters long"
    )

# Connection pool (simple approach for SQLite)
_db_lock = None
try:
    import threading
    _db_lock = threading.Lock()
except ImportError:
    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS signals (
            signal_id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            host_id TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_description TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            tags TEXT,
            context TEXT,
            received_at TEXT NOT NULL
        )
        """
    )
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ts
        ON signals(ts DESC)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_host_id
        ON signals(host_id)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_severity
        ON signals(severity)
    """)
    # Ensure new columns exist for older databases
    cursor = conn.execute("PRAGMA table_info(signals)")
    cols = [row[1] for row in cursor.fetchall()]
    if "rule_description" not in cols:
        conn.execute("ALTER TABLE signals ADD COLUMN rule_description TEXT")
    if "status" not in cols:
        conn.execute("ALTER TABLE signals ADD COLUMN status TEXT DEFAULT 'open'")
    conn.execute("UPDATE signals SET status = 'open' WHERE status IS NULL OR status = ''")
    # Create heartbeats table for agent health monitoring
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS heartbeats (
            agent_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            version TEXT,
            os_version TEXT,
            uptime_seconds REAL,
            received_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, timestamp)
        )
        """
    )
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_heartbeat_agent
        ON heartbeats(agent_id, received_at DESC)
    """)
    conn.commit()
    conn.close()
    print(f"Database initialized: {DB_PATH}")
    yield
    # Cleanup on shutdown (if needed)


app = FastAPI(title="Santamon Backend", version="v0.1", lifespan=lifespan)

# Serve the web UI when the static assets are available
STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(STATIC_DIR), html=True), name="ui")
else:
    print(f"Static UI directory not found at {STATIC_DIR}, skipping /ui mount")


class Signal(BaseModel):
    signal_id: str = Field(..., max_length=256)
    ts: str = Field(..., max_length=64)
    host_id: str = Field(..., max_length=255)
    rule_id: str = Field(..., max_length=64)
    rule_description: Optional[str] = Field(default=None, max_length=2000)
    status: str = Field(default="open", max_length=32)
    severity: str = Field(..., max_length=32)
    title: str = Field(..., max_length=512)
    tags: List[str] = Field(default_factory=list, max_length=50)
    context: dict

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        allowed = ['low', 'medium', 'high', 'critical']
        if v not in allowed:
            raise ValueError(f'severity must be one of {allowed}')
        return v

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        if v not in ALLOWED_STATUSES:
            raise ValueError(f'status must be one of {sorted(ALLOWED_STATUSES)}')
        return v

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        for tag in v:
            if len(tag) > 64:
                raise ValueError('tag too long (max 64 characters)')
        return v


class Heartbeat(BaseModel):
    agent_id: str = Field(..., max_length=255)
    timestamp: str = Field(..., max_length=64)
    version: str = Field(..., max_length=32)
    os_version: str = Field(..., max_length=32)
    uptime_seconds: Optional[float] = None


@app.post("/agents/heartbeat")
async def heartbeat(
    hb: Heartbeat,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Receive agent heartbeat for health monitoring

    Authentication via X-API-Key header
    """
    # Use constant-time comparison to prevent timing attacks
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO heartbeats VALUES
            (?, ?, ?, ?, ?, ?)
            """,
            (
                hb.agent_id,
                hb.timestamp,
                hb.version,
                hb.os_version,
                hb.uptime_seconds,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()

        return {
            "status": "ok",
            "agent_id": hb.agent_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


class StatusUpdate(BaseModel):
    status: str

    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        if v not in ALLOWED_STATUSES:
            raise ValueError(f'status must be one of {sorted(ALLOWED_STATUSES)}')
        return v


@app.patch("/signals/{signal_id}/status")
async def update_signal_status(signal_id: str, update: StatusUpdate):
    """Update status of a signal (open, acknowledged, resolved)."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        cursor = conn.execute(
            "UPDATE signals SET status = ? WHERE signal_id = ?",
            (update.status, signal_id),
        )
        conn.commit()
        updated_rows = cursor.rowcount
        if updated_rows == 0:
            raise HTTPException(status_code=404, detail="Signal not found")
        return {"signal_id": signal_id, "status": update.status}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.post("/ingest")
async def ingest(
    signal: Signal,
    x_api_key: str = Header(None, alias="X-API-Key")
):
    """
    Ingest a security signal from santamon agent

    Authentication via X-API-Key header
    """
    # Use constant-time comparison to prevent timing attacks
    if not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Use connection with timeout
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    try:
        # Limit context size to prevent DoS
        context_json = json.dumps(signal.context)
        if len(context_json) > 100000:  # 100KB limit
            raise HTTPException(status_code=413, detail="Context too large")

        before_changes = conn.total_changes
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO signals (
                signal_id, ts, host_id, rule_id, rule_description, status,
                severity, title, tags, context, received_at
            ) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                signal.signal_id,
                signal.ts,
                signal.host_id,
                signal.rule_id,
                signal.rule_description,
                signal.status or "open",
                signal.severity,
                signal.title,
                json.dumps(signal.tags),
                json.dumps(signal.context or {}),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()

        # Determine if the insert succeeded using SQLite change count
        inserted_rows = cursor.rowcount
        if inserted_rows == -1:  # Fallback for drivers that do not support rowcount
            inserted_rows = conn.total_changes - before_changes

        return {
            "status": "ok",
            "id": signal.signal_id,
            "duplicate": inserted_rows == 0
        }
    except HTTPException:
        raise
    except Exception as e:
        # Don't expose internal errors
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.get("/signals")
async def list_signals(
    since: Optional[str] = Query(None, description="ISO timestamp to filter signals after"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    host_id: Optional[str] = Query(None, description="Filter by host"),
    status: Optional[str] = Query("open", description="Filter by status: open, acknowledged, resolved, or 'all'"),
    search: Optional[str] = Query(None, description="Search by detection title or rule id"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results")
):
    """
    List signals with optional filtering

    Returns signals in reverse chronological order
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM signals WHERE 1=1"
    params = []

    if since:
        query += " AND ts > ?"
        params.append(since)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if host_id:
        query += " AND host_id = ?"
        params.append(host_id)
    if status and status != "all":
        if status not in ALLOWED_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status '{status}'. Allowed: {sorted(ALLOWED_STATUSES)} or 'all'")
        query += " AND status = ?"
        params.append(status)
    search_term = search.strip().lower() if search else None
    if search_term:
        query += " AND (LOWER(title) LIKE ? OR LOWER(rule_id) LIKE ?)"
        like = f"%{search_term}%"
        params.extend([like, like])

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    try:
        cursor = conn.execute(query, params)
        signals = []
        for row in cursor:
            signal = dict(row)
            # Parse JSON fields
            signal['tags'] = json.loads(signal['tags']) if signal['tags'] else []
            signal['context'] = json.loads(signal['context']) if signal['context'] else {}
            if not signal.get("status"):
                signal["status"] = "open"
            signals.append(signal)

        return {
            "count": len(signals),
            "signals": signals
        }
    finally:
        conn.close()


@app.get("/stats")
async def stats():
    """
    Get database statistics

    Returns counts by severity, host, and recent activity
    """
    conn = sqlite3.connect(DB_PATH)

    try:
        # Total count
        cursor = conn.execute("SELECT COUNT(*) FROM signals")
        total = cursor.fetchone()[0]

        # By severity
        cursor = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM signals
            GROUP BY severity
            ORDER BY count DESC
        """)
        by_severity = {row[0]: row[1] for row in cursor}

        # By host
        cursor = conn.execute("""
            SELECT host_id, COUNT(*) as count
            FROM signals
            GROUP BY host_id
            ORDER BY count DESC
        """)
        by_host = {row[0]: row[1] for row in cursor}

        # Recent activity (last 24h)
        cursor = conn.execute("""
            SELECT COUNT(*) FROM signals
            WHERE ts > datetime('now', '-1 day')
        """)
        last_24h = cursor.fetchone()[0]

        # Most common rules
        cursor = conn.execute("""
            SELECT rule_id, COUNT(*) as count
            FROM signals
            GROUP BY rule_id
            ORDER BY count DESC
            LIMIT 10
        """)
        top_rules = [{"rule_id": row[0], "count": row[1]} for row in cursor]

        return {
            "total_signals": total,
            "last_24h": last_24h,
            "by_severity": by_severity,
            "by_host": by_host,
            "top_rules": top_rules
        }
    finally:
        conn.close()


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/agents")
async def list_agents(
    since: Optional[str] = Query(None, description="ISO timestamp to filter heartbeats after"),
    limit: int = Query(200, ge=1, le=2000, description="Maximum number of results")
):
    """
    List agents with their latest heartbeats
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # Default to last 10 minutes if not provided
    default_since = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
    window = since or default_since

    cursor = conn.execute(
        """
        SELECT agent_id, timestamp, version, os_version, uptime_seconds, received_at
        FROM heartbeats
        WHERE received_at > ?
        ORDER BY received_at DESC
        LIMIT ?
        """,
        (window, limit),
    )

    seen = set()
    heartbeats = []
    for row in cursor:
        agent = row["agent_id"]
        if agent in seen:
            continue
        seen.add(agent)
        heartbeats.append(dict(row))

    conn.close()
    return {"count": len(heartbeats), "heartbeats": heartbeats}


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Santamon Backend",
        "version": "v0.1",
        "endpoints": {
            "POST /ingest": "Receive signals from agents",
            "GET /signals": "List and filter signals",
            "PATCH /signals/{id}/status": "Update signal status",
            "POST /agents/heartbeat": "Receive agent heartbeat",
            "GET /agents": "List agents with latest heartbeats",
            "GET /stats": "Get statistics",
            "GET /health": "Health check",
            "GET /ui": "Web UI (if static/ directory exists)"
        }
    }


if __name__ == "__main__":
    import uvicorn
    import os

    # Get certificate paths
    cert_file = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_file = os.path.join(os.path.dirname(__file__), "key.pem")

    # Check if certificates exist
    try:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            print(f"Running with HTTPS (cert: {cert_file})")
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=8443,
                ssl_certfile=cert_file,
                ssl_keyfile=key_file,
            )
        else:
            print("WARNING: No SSL certificates found, running HTTP only")
            print(
                f"Generate with: openssl req -x509 -newkey rsa:4096 -nodes -out {cert_file} -keyout {key_file} -days 365 -subj '/CN=localhost'"
            )
            uvicorn.run(app, host="0.0.0.0", port=8443)
    except KeyboardInterrupt:
        # Allow clean exit on Ctrl+C without noisy traceback
        pass
