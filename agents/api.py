#!/usr/bin/env python3
"""
SecOS v6.0 — API Gateway
FastAPI server: REST + WebSocket + AEGIS orchestration
"""

import asyncio, json, logging, os, time, uuid
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import Request, FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import hashlib
def _hash(p): return hashlib.sha256(p.encode()).hexdigest()
def _verify(p, h): return _hash(p) == h
from jose import JWTError, jwt
import redis.asyncio as aioredis
import asyncpg
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")

# ── CONFIG ─────────────────────────────────────────────────────────────────────
SECRET_KEY   = os.getenv("SECOS_SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM    = "HS256"
TOKEN_EXPIRE = 480  # minutes
DB_URL       = os.getenv("DATABASE_URL", "postgresql://secos:password@localhost/secosdb")
REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_PORT     = int(os.getenv("API_PORT", 8000))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/secos/api.log"),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("secos.api")

# ── AUTH ───────────────────────────────────────────────────────────────────────
DEFAULT_USERS = {
    "admin":   {"hash": _hash("Admin1234"),  "role": "admin"},
    "analyst": {"hash": _hash("Analyst123"), "role": "analyst"},
    "soc":     {"hash": _hash("SOCteam123"), "role": "soc_lead"},
}

def create_token(data: dict) -> str:
    exp = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    return jwt.encode({**data, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)

class LoginRequest(BaseModel):
    username: str
    password: str

# ── MODELS ─────────────────────────────────────────────────────────────────────
class AlertCreate(BaseModel):
    rule:       str
    severity:   str
    host:       Optional[str] = None
    src_ip:     Optional[str] = None
    user_name:  Optional[str] = None
    mitre_id:   Optional[str] = None
    tactic:     Optional[str] = None
    score:      int = 0
    raw:        Optional[dict] = None
    source:     str = "unknown"

class AlertUpdate(BaseModel):
    status:   Optional[str] = None
    decision: Optional[str] = None

class IOCCreate(BaseModel):
    value:      str
    ioc_type:   str
    verdict:    str = "UNKNOWN"
    confidence: int = 0
    source:     str = "manual"
    tags:       List[str] = []
    apt:        Optional[str] = None

# ── WEBSOCKET MANAGER ──────────────────────────────────────────────────────────
class WSManager:
    def __init__(self):
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        log.info(f"WS connected: {ws.client}")

    def disconnect(self, ws: WebSocket):
        self.connections.remove(ws) if ws in self.connections else None

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = WSManager()

# ── DB POOL ────────────────────────────────────────────────────────────────────
db_pool: Optional[asyncpg.Pool] = None
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, redis_client
    log.info("Starting SecOS API...")
    try:
        db_pool = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
        log.info("PostgreSQL connected")
    except Exception as e:
        log.error(f"DB connection failed: {e} — running in degraded mode")
        db_pool = None

    try:
        redis_client = aioredis.from_url(REDIS_URL)
        await redis_client.ping()
        log.info("Redis connected")
    except Exception as e:
        log.error(f"Redis connection failed: {e}")
        redis_client = None

    # Background: relay Redis events to WebSocket clients
    asyncio.create_task(redis_relay())

    yield

    if db_pool: await db_pool.close()
    if redis_client: await redis_client.close()
    log.info("SecOS API shutdown")

async def redis_relay():
    """Forward Redis pub/sub alerts to WebSocket clients."""
    if not redis_client:
        return
    try:
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("secos:alerts", "secos:aegis", "secos:actions")
        async for msg in pubsub.listen():
            if msg["type"] == "message":
                try:
                    data = json.loads(msg["data"])
                    await ws_manager.broadcast({"channel": msg["channel"].decode(), "data": data})
                    # Persist alert to PostgreSQL
                    if pool and msg["channel"].decode() == "secos:alerts":
                        try:
                            async with db_pool.acquire() as conn:
                                await conn.execute("""
                                    INSERT INTO events (event_id,rule_name,severity,host,src_ip,
                                        user_name,mitre_id,tactic,score,status,source,raw)
                                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                                    ON CONFLICT DO NOTHING
                                """,
                                str(data.get("id","")),
                                data.get("rule") or data.get("rule_name","Unknown"),
                                data.get("severity","LOW"),
                                data.get("host",""),
                                data.get("src_ip",""),
                                data.get("user") or data.get("user_name",""),
                                data.get("mitre_id") or data.get("mitre",""),
                                data.get("tactic",""),
                                int(data.get("score",0)),
                                data.get("status","NEW"),
                                data.get("source","SIEM"),
                                json.dumps(data)
                                )
                        except Exception as db_err:
                            log.debug(f"DB write: {db_err}")
                except Exception as e:
                    log.debug(f"Relay error: {e}")
    except Exception as e:
        log.error(f"Redis relay error: {e}")

# ── APP ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecOS API",
    version="6.0.0",
    description="SecOS Autonomous Security Operating System — REST API",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

# ── AUTH ENDPOINTS ─────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(req: LoginRequest):
    user = DEFAULT_USERS.get(req.username.lower())
    if not user or not _verify(req.password, user["hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": req.username, "role": user["role"]})
    log.info(f"Login: {req.username} [{user['role']}]")
    return {"access_token": token, "token_type": "bearer",
            "user": req.username, "role": user["role"]}

# ── HEALTH ─────────────────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {
        "status": "online",
        "version": "6.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "db": "connected" if db_pool else "unavailable",
        "redis": "connected" if redis_client else "unavailable",
        "ws_clients": len(ws_manager.connections),
    }

# ── ALERTS ─────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def get_alerts(limit: int = 500, severity: Optional[str] = None, status: Optional[str] = None):
    if not db_pool:
        return {"alerts": [], "total": 0}
    async with db_pool.acquire() as conn:
        q = "SELECT * FROM events WHERE 1=1"
        args = []
        if severity:
            args.append(severity); q += f" AND severity=${ len(args)}"
        if status:
            args.append(status); q += f" AND status=${ len(args)}"
        q += f" ORDER BY id DESC LIMIT ${len(args)+1}"
        args.append(limit)
        rows = await conn.fetch(q, *args)
        return {"alerts": [dict(r) for r in rows], "total": len(rows)}

@app.post("/api/alerts", status_code=201)
async def create_alert(alert: AlertCreate):
    if not db_pool:
        return {"id": str(uuid.uuid4()), "status": "queued"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO events (rule, severity, host, src_ip, user_name, mitre_id, tactic, score, raw, source)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, event_id
        """, alert.rule, alert.severity, alert.host, alert.src_ip,
            alert.user_name, alert.mitre_id, alert.tactic, alert.score,
            json.dumps(alert.raw or {}), alert.source)

    # Push to Redis for live feed
    if redis_client:
        await redis_client.publish("secos:alerts", json.dumps({
            "id": str(row["event_id"]), "rule": alert.rule,
            "severity": alert.severity, "host": alert.host,
            "timestamp": datetime.utcnow().isoformat(),
        }))
    return {"id": row["id"], "event_id": str(row["event_id"])}

@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: int, update: AlertUpdate):
    if not db_pool:
        raise HTTPException(status_code=503, detail="DB unavailable")
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE events SET status=COALESCE($1,status), decision=COALESCE($2,decision)
            WHERE id=$3
        """, update.status, update.decision, alert_id)
    return {"updated": True}

# ── IOCs ───────────────────────────────────────────────────────────────────────
@app.get("/api/iocs")
async def get_iocs(limit: int = 200):
    if not db_pool:
        return {"iocs": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM iocs ORDER BY last_seen DESC LIMIT $1", limit)
        return {"iocs": [dict(r) for r in rows]}

@app.post("/api/iocs/lookup")
async def lookup_ioc(req: dict):
    value = req.get("value", "")
    if not db_pool:
        return {"value": value, "verdict": "UNKNOWN", "source": "offline"}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM iocs WHERE value=$1", value)
        if row:
            return dict(row)
        return {"value": value, "verdict": "NOT_FOUND", "confidence": 0}

@app.post("/api/iocs", status_code=201)
async def create_ioc(ioc: IOCCreate):
    if not db_pool:
        return {"status": "queued"}
    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO iocs (value, ioc_type, verdict, confidence, source, tags, apt)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (value) DO UPDATE
            SET verdict=EXCLUDED.verdict, confidence=EXCLUDED.confidence,
                last_seen=NOW(), source=EXCLUDED.source
        """, ioc.value, ioc.ioc_type, ioc.verdict, ioc.confidence,
            ioc.source, ioc.tags, ioc.apt)
    return {"status": "stored"}

# ── ASSETS ─────────────────────────────────────────────────────────────────────
@app.get("/api/assets")
async def get_assets():
    if not db_pool:
        return {"assets": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM assets ORDER BY risk_score DESC")
        return {"assets": [dict(r) for r in rows]}

# ── CASES ──────────────────────────────────────────────────────────────────────
@app.get("/api/cases")
async def get_cases(status: Optional[str] = None):
    if not db_pool:
        return {"cases": []}
    async with db_pool.acquire() as conn:
        q = "SELECT * FROM cases"
        if status: q += f" WHERE status='{status}'"
        q += " ORDER BY created_at DESC"
        rows = await conn.fetch(q)
        return {"cases": [dict(r) for r in rows]}

@app.post("/api/cases", status_code=201)
async def create_case(req: dict):
    if not db_pool:
        return {"id": str(uuid.uuid4())}
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO cases (title, severity, description, tags)
            VALUES ($1,$2,$3,$4) RETURNING id, case_id
        """, req.get("title","Untitled"), req.get("severity","MEDIUM"),
            req.get("description",""), req.get("tags",[]))
    return {"id": row["id"], "case_id": str(row["case_id"])}

# ── WEBSOCKET ──────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        await ws.send_json({"type": "connected", "msg": "SecOS live feed active"})
        while True:
            data = await ws.receive_json()
            if data.get("type") == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception as e:
        log.error(f"WS error: {e}")
        ws_manager.disconnect(ws)

# ── AEGIS PROXY ────────────────────────────────────────────────────────────────
@app.post("/api/aegis/analyze")
async def aegis_analyze(req: dict):
    """Proxy to Anthropic API — keeps API key server-side."""
    import httpx
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or api_key == "your-api-key-here":
        return {"error": "ANTHROPIC_API_KEY not configured", "chain": []}

    alert = req.get("alert", {})
    prompt = f"""You are AEGIS, the autonomous AI engine of SecOS.
Analyze this security alert and provide a structured incident response decision.

Alert: {json.dumps(alert, indent=2)}

Respond with:
1. SEVERITY ASSESSMENT (confirm or adjust)
2. THREAT CONTEXT (what this attack pattern means)
3. RECOMMENDED ACTIONS (specific, ordered)
4. MITRE ATT&CK mapping
5. VERDICT: CONTAIN | INVESTIGATE | MONITOR | CLOSE

Be concise, specific, actionable."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": os.getenv("AEGIS_MODEL", "claude-sonnet-4-20250514"),
                      "max_tokens": 1000,
                      "messages": [{"role": "user", "content": prompt}]}
            )
            data = resp.json()
            analysis = data.get("content", [{}])[0].get("text", "")
            return {"analysis": analysis, "model": os.getenv("AEGIS_MODEL"), "alert_id": alert.get("id")}
    except Exception as e:
        log.error(f"AEGIS API error: {e}")
        return {"error": str(e)}

# ── STATS ──────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    if not db_pool:
        return {"total_alerts": 0}
    async with db_pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM events")
        critical = await conn.fetchval("SELECT COUNT(*) FROM events WHERE severity='CRITICAL'")
        open_c = await conn.fetchval("SELECT COUNT(*) FROM events WHERE status='NEW'")
        resolved = await conn.fetchval("SELECT COUNT(*) FROM events WHERE status='RESOLVED'")
        ioc_count = await conn.fetchval("SELECT COUNT(*) FROM iocs")
        return {
            "total_alerts": total, "critical": critical,
            "open": open_c, "resolved": resolved,
            "iocs": ioc_count,
            "uptime": time.time(),
        }

# ── MAIN ───────────────────────────────────────────────────────────────────────

@app.get("/api/aegis/history")
async def aegis_history():
    try:
        raw = r.lrange("secos:aegis:history", 0, 49)
        chains = [json.loads(x) for x in raw if x]
    except:
        chains = []
    return {"chains": chains}

@app.get("/api/ueba/profiles")
async def ueba_profiles():
    try:
        raw = r.get("secos:ueba:profiles")
        profiles = json.loads(raw) if raw else []
    except:
        profiles = []
    return {"profiles": profiles}

@app.get("/api/vuln/findings")
async def vuln_findings():
    try:
        raw = r.lrange("secos:vuln:findings", 0, 99)
        findings = [json.loads(x) for x in raw if x]
    except:
        findings = []
    return {"findings": findings}

@app.post("/api/hunt/run")
async def hunt_run(req: Request):
    try:
        body = await req.json()
        r.publish("secos:hunt:queries", json.dumps(body))
        return {"status": "queued", "query": body}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.post("/api/ingest")
async def ingest_alert(req: Request):
    """Direct alert ingest — used by remote agents."""
    try:
        data = await req.json()
        import uuid
        event_id = data.get("id") or str(uuid.uuid4())[:12].upper()
        async with db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO events (event_id,rule_name,severity,host,src_ip,
                    user_name,mitre_id,tactic,score,status,source,raw)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                ON CONFLICT DO NOTHING
            """,
            event_id,
            data.get("rule") or data.get("rule_name","Unknown"),
            data.get("severity","LOW"),
            data.get("host",""),
            data.get("src_ip",""),
            data.get("user") or data.get("user_name",""),
            data.get("mitre_id") or data.get("mitre",""),
            data.get("tactic",""),
            int(data.get("score",0)),
            data.get("status","NEW"),
            data.get("source","AGENT"),
            json.dumps(data)
            )
        # Also broadcast to WebSocket
        await ws_manager.broadcast({"channel":"secos:alerts","data":data})
        if redis_client:
            redis_client.publish("secos:alerts", json.dumps(data))
        return {"status":"ok","id":event_id}
    except Exception as e:
        log.error(f"Ingest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=API_PORT,
                reload=False, log_level="info",
                access_log=True)

@app.get("/agent/linux")
async def download_linux_agent():
    from fastapi.responses import PlainTextResponse
    script = """#!/usr/bin/env python3
import os, time, json, socket, hashlib, subprocess, requests
from datetime import datetime, timezone

SERVER  = os.getenv("SECOS_SERVER", "http://localhost:8000")
HOST    = os.getenv("AGENT_HOST", socket.gethostname())

def send_alert(rule, severity, score, mitre, tactic, raw=""):
    try:
        payload = {
            "id": hashlib.md5(f"{rule}{HOST}{time.time()}".encode()).hexdigest()[:12].upper(),
            "rule": rule, "rule_name": rule, "severity": severity,
            "host": HOST, "src_ip": "", "user_name": "root",
            "mitre_id": mitre, "tactic": tactic, "score": score,
            "source": "LINUX_AGENT", "status": "NEW",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        r = requests.post(f"{SERVER}/api/ingest", json=payload, timeout=5)
        print(f"[ALERT] {severity} {rule} -> {r.status_code}")
    except Exception as e:
        print(f"[ERROR] {e}")

def check_auth_log():
    fail_counts = {}
    try:
        with open("/var/log/auth.log") as f:
            for line in f.readlines()[-200:]:
                if "Failed password" in line:
                    parts = line.split()
                    ip = parts[-4] if len(parts) > 4 else "unknown"
                    fail_counts[ip] = fail_counts.get(ip, 0) + 1
        for ip, count in fail_counts.items():
            if count >= 3:
                send_alert("SSH Brute Force", "HIGH", 85, "T1110.001", "Credential Access", f"{count} fails from {ip}")
    except: pass

def check_processes():
    suspicious = ["mimikatz","meterpreter","netcat","ncat","mshta","certutil","empire","covenant"]
    try:
        out = subprocess.check_output(["ps","aux"], text=True).lower()
        for proc in suspicious:
            if proc in out:
                send_alert(f"Suspicious Process: {proc}", "CRITICAL", 95, "T1059", "Execution")
    except: pass

def check_root_logins():
    try:
        out = subprocess.check_output(["last","-n","20"], text=True)
        for line in out.splitlines():
            if line.startswith("root") and "pts" in line:
                send_alert("Root Remote Login", "HIGH", 80, "T1078.001", "Privilege Escalation", line)
                break
    except: pass

print(f"SecOS Linux Agent — server: {SERVER}, host: {HOST}")
last_check = time.time()
while True:
    try:
        check_auth_log()
        check_processes()
        check_root_logins()
        send_alert("Linux Heartbeat", "LOW", 10, "T1082", "Discovery")
    except Exception as e:
        print(f"[ERROR] {e}")
    time.sleep(30)
"""
    return PlainTextResponse(script, media_type="text/plain")
