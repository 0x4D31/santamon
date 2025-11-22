# Santamon Backend

Minimal FastAPI backend for receiving and storing security signals from Santamon agents.

## Features

- **FastAPI** REST API with automatic OpenAPI docs
- **SQLite** database for signal and agent heartbeat storage
- **Signal deduplication** via INSERT OR IGNORE
- **Signal lifecycle management** (open, acknowledged, resolved)
- **Agent health monitoring** via heartbeats
- **Web UI** for signal management and agent status
- **Query/filter endpoints** for signal retrieval and agent listing
- **Statistics** and monitoring endpoints
- **API key authentication** with constant-time comparison

## Requirements

```bash
pip install fastapi uvicorn
```

Or use the requirements file:

```bash
pip install -r backend-requirements.txt
```

## Running

### Development (local testing - HTTP only)

```bash
# Set API key (required, min 16 chars)
export SANTAMON_API_KEY="test-key-1234567890"

# Run with uvicorn (HTTP for testing only)
uvicorn backend:app --host 0.0.0.0 --port 8443
```

### Production (HTTPS with TLS)

**Option 1: Using python backend.py (recommended)**

This automatically uses cert.pem and key.pem if they exist:

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj '/CN=localhost'

# Set API key
export SANTAMON_API_KEY="$(openssl rand -hex 32)"

# Run (automatically uses HTTPS if cert.pem exists)
python backend.py
```

**Option 2: Using uvicorn with explicit TLS**

```bash
# Generate certificate (if not already done)
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365 \
  -subj '/CN=localhost'

# Set API key
export SANTAMON_API_KEY="$(openssl rand -hex 32)"

# Run with TLS
uvicorn backend:app --host 0.0.0.0 --port 8443 \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
```

### Using systemd (Linux)

Create `/etc/systemd/system/santamon-backend.service`:

```ini
[Unit]
Description=Santamon Backend
After=network.target

[Service]
Type=simple
User=santamon
WorkingDirectory=/opt/santamon/backend
Environment="SANTAMON_API_KEY=your-secret-key"
Environment="SANTAMON_DB_PATH=/var/lib/santamon/signals.db"
ExecStart=/opt/santamon/backend/venv/bin/python backend.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

**Note:** Ensure `cert.pem` and `key.pem` exist in `/opt/santamon/backend/` for HTTPS.

## Configuration

Environment variables:

- `SANTAMON_API_KEY` - API key for authentication (required, min 16 chars)
- `SANTAMON_DB_PATH` - SQLite database path (default: `signals.db`)

## API Endpoints

### Signal Management

**POST /ingest** - Receive signals from agents
- Authentication: `X-API-Key` header (required)
- Body: Signal JSON payload
- Response: `{"status": "received", "signal_id": "<id>"}`

**GET /signals** - List and filter signals
- Query parameters:
  - `severity`: Filter by severity (critical, high, medium, low, info)
  - `status`: Filter by status (open, acknowledged, resolved, or 'all'; default: 'open')
  - `search`: Search in detection title or rule ID
  - `since`: ISO timestamp to filter signals after
  - `limit`: Maximum results (default: 100, max: 1000)
- Response: `{"count": N, "signals": [...]}`

**PATCH /signals/{signal_id}/status** - Update signal status
- Body: `{"status": "open" | "acknowledged" | "resolved"}`
- Response: `{"signal_id": "<id>", "status": "<status>"}`

### Agent Management

**POST /agents/heartbeat** - Receive agent heartbeat
- Authentication: `X-API-Key` header (required)
- Body:
  ```json
  {
    "agent_id": "hostname",
    "timestamp": "2025-01-15T10:30:00Z",
    "version": "0.1.0",
    "os_version": "15.2",
    "uptime_seconds": 3600.5
  }
  ```
- Response: `{"status": "ok", "agent_id": "<id>"}`

**GET /agents** - List agents with latest heartbeats
- Query parameters:
  - `since`: ISO timestamp to filter after (default: last 10 minutes)
  - `limit`: Maximum results (default: 200, max: 2000)
- Response: `{"count": N, "heartbeats": [...]}`

### Monitoring

**GET /stats** - Get signal statistics
- Response: Counts by severity, host, and rule

**GET /health** - Health check endpoint
- Response: `{"status": "healthy", "timestamp": "<iso>"}`

**GET /ui** - Web interface (if static/ directory exists)
- Interactive signal management and agent monitoring dashboard

**GET /** - API information and available endpoints

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8443/docs
- ReDoc: http://localhost:8443/redoc

## Security

- API key authentication with constant-time comparison (prevents timing attacks)
- Minimum API key length: 16 characters
- Context size limit: 100KB per signal
- Connection timeout: 5 seconds
- Input validation via Pydantic models
- No internal error disclosure

## Database Schema

### Signals Table
```sql
CREATE TABLE signals (
    signal_id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    host_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    tags TEXT,
    context TEXT,
    received_at TEXT NOT NULL,
    status TEXT DEFAULT 'open',              -- Signal lifecycle status
    rule_description TEXT                     -- Rule description for context
);

CREATE INDEX idx_ts ON signals(ts DESC);
CREATE INDEX idx_host_id ON signals(host_id);
CREATE INDEX idx_severity ON signals(severity);
CREATE INDEX idx_status ON signals(status);   -- For status filtering
```

### Heartbeats Table
```sql
CREATE TABLE heartbeats (
    agent_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    version TEXT,
    os_version TEXT,
    uptime_seconds REAL,
    received_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, timestamp)
);

CREATE INDEX idx_heartbeat_agent ON heartbeats(agent_id, received_at DESC);
```

### Shipped Table (Internal)
```sql
CREATE TABLE shipped (
    signal_id TEXT PRIMARY KEY,
    shipped_at TEXT NOT NULL
);
```
