import asyncio
import base64
import json
import secrets
import time
import uuid
from contextlib import asynccontextmanager

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.websockets import WebSocketDisconnect, WebSocketState

from .database import connect, digest, initialize


@asynccontextmanager
async def lifespan(app):
    try:
        initialize()
    except Exception:
        raise RuntimeError("database_initialization_failed") from None
    yield


app = FastAPI(title="RMM enrollment and reachability", lifespan=lifespan)


@app.middleware("http")
async def bounded_http(request: Request, call_next):
    # Reject streaming bodies before FastAPI's JSON parser allocates them.
    length = request.headers.get("content-length")
    if request.headers.get("transfer-encoding") or (request.method == "POST" and length is None):
        return JSONResponse(status_code=411, content={"detail": "content_length_required"})
    if length is not None and (not length.isdecimal() or int(length) > 2048):
        return JSONResponse(status_code=413, content={"detail": "request_too_large"})
    try:
        return await call_next(request)
    except Exception:
        # Database and framework exceptions may contain input/configuration values.
        return JSONResponse(status_code=503, content={"detail": "temporarily_unavailable"})


@app.exception_handler(RequestValidationError)
async def invalid_input(request: Request, error: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "invalid_request"})


def budget(name, limit):
    """Fixed, globally bounded buckets survive restarts; never keyed by untrusted IP."""
    with connect() as db:
        row = db.execute("""
            INSERT INTO request_budget VALUES (%s, now(), 1)
            ON CONFLICT (name) DO UPDATE SET
                window_start = CASE WHEN request_budget.window_start <= now() - interval '1 minute' THEN now() ELSE request_budget.window_start END,
                attempts = CASE WHEN request_budget.window_start <= now() - interval '1 minute' THEN 1 ELSE LEAST(request_budget.attempts + 1, 100000) END
            RETURNING attempts
        """, (name,)).fetchone()
    if row["attempts"] > limit:
        raise HTTPException(429, "rate_limited", headers={"Retry-After": "60"})


def admin_workspace(authorization):
    """Resolve the initial admin credential to its authorized workspace."""
    budget("http_auth", 600)
    if not authorization or not authorization.startswith("Bearer ") or len(authorization) > 100:
        raise HTTPException(401, "unauthorized")
    with connect() as db:
        workspace = db.execute(
            "SELECT id FROM workspaces WHERE admin_hash = %s",
            (digest(authorization[7:]),),
        ).fetchone()
    if not workspace:
        raise HTTPException(401, "unauthorized")
    return workspace["id"]


@app.get("/devices")
def list_devices(authorization: str | None = Header(default=None), after: uuid.UUID | None = None,
                 limit: int = Query(default=100, ge=1, le=100)):
    workspace = admin_workspace(authorization)
    with connect() as db:
        devices = db.execute("""
            SELECT id, approved_at, last_seen,
                CASE WHEN last_seen > now() - interval '45 seconds' THEN 'online'
                     WHEN last_seen IS NOT NULL THEN 'stale'
                     WHEN activate_before <= now() THEN 'approval_expired'
                     ELSE 'approved' END AS reachability
            FROM devices WHERE workspace_id = %s AND (%s::uuid IS NULL OR id > %s)
            ORDER BY id LIMIT %s
        """, (workspace, after, after, limit + 1)).fetchall()
    return {"devices": devices[:limit], "next_cursor": str(devices[limit - 1]["id"]) if len(devices) > limit else None}


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[A-Z2-7]{12}$")


@app.post("/pairings/approve")
def approve(body: Approval, authorization: str | None = Header(default=None)):
    workspace = admin_workspace(authorization)
    budget("approval:" + str(workspace), 10)
    with connect() as db:
        pending = db.execute("""
            DELETE FROM pairings WHERE code_hash = %s AND expires_at > now()
            RETURNING public_key, expires_at
        """, (digest(body.code),)).fetchone()
        if not pending:
            raise HTTPException(409, "invalid_or_consumed_code")
        device = uuid.uuid4()
        db.execute("""
            INSERT INTO devices (id, workspace_id, public_key, activate_before)
            VALUES (%s, %s, %s, %s)
        """, (device, workspace, pending["public_key"], pending["expires_at"]))
    return {"device_id": str(device), "state": "approved"}


def verify_proof(message, nonce):
    if set(message) != {"public_key", "signature"}:
        raise ValueError()
    encoded = message["public_key"]
    key = serialization.load_der_public_key(base64.b64decode(encoded, validate=True))
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError()
    canonical = base64.b64encode(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    if canonical != encoded:
        raise ValueError()
    key.verify(base64.b64decode(message["signature"], validate=True),
               ("rmm-reachability-v1\n" + nonce).encode(), ec.ECDSA(hashes.SHA256()))
    return encoded


def authenticate_key(public_key):
    with connect() as db:
        db.execute("SELECT pg_advisory_xact_lock(4004)")
        device = db.execute("SELECT * FROM devices WHERE public_key = %s FOR UPDATE", (public_key,)).fetchone()
        if device:
            activated = db.execute("""
                UPDATE devices SET last_seen = now() WHERE id = %s
                AND (last_seen IS NOT NULL OR activate_before > now()) RETURNING id
            """, (device["id"],)).fetchone()
            if not activated:
                return {"state": "denied"}
            return {"state": "online", "device_id": str(device["id"]), "heartbeat_seconds": 15, "stale_seconds": 45}
        db.execute("DELETE FROM pairings WHERE expires_at <= now()")
        if db.execute("SELECT 1 FROM pairings WHERE public_key = %s", (public_key,)).fetchone():
            return {"state": "pending"}
        if db.execute("SELECT count(*) AS count FROM pairings").fetchone()["count"] >= 1000:
            return {"state": "rate_limited"}
        code = base64.b32encode(secrets.token_bytes(8)).decode()[:12]
        db.execute("INSERT INTO pairings VALUES (%s, %s, now() + interval '10 minutes')", (public_key, digest(code)))
        return {"state": "pending", "code": code, "expires_in_seconds": 600}


async def receive(socket):
    raw = await asyncio.wait_for(socket.receive_text(), 45)
    if len(raw) > 2048:
        raise ValueError()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError()
    return value


@app.websocket("/agent")
async def agent(socket: WebSocket):
    try:
        await asyncio.to_thread(budget, "agent_connections", 120)
    except HTTPException:
        await socket.close(code=1008)
        return
    await socket.accept()
    try:
        nonce = secrets.token_urlsafe(32)
        await socket.send_json({"type": "challenge", "nonce": nonce})
        proof = await asyncio.wait_for(receive(socket), 10)
        public_key = verify_proof(proof, nonce)
        status = await asyncio.to_thread(authenticate_key, public_key)
        await socket.send_json(status)
        if status["state"] != "online":
            await socket.close()
            return
        last_heartbeat = 0.0
        while True:
            if await receive(socket) != {"type": "heartbeat"}:
                raise ValueError()
            if time.monotonic() - last_heartbeat < 1:
                raise ValueError()
            last_heartbeat = time.monotonic()
            await asyncio.to_thread(heartbeat, status["device_id"])
            await socket.send_json({"type": "heartbeat_ack"})
    except (InvalidSignature, ValueError, TypeError, KeyError):
        await socket.send_json({"state": "denied"})
        await socket.close(code=1008)
    except (WebSocketDisconnect, TimeoutError):
        pass
    except Exception:
        await socket.close(code=1011)
    finally:
        if socket.application_state == WebSocketState.CONNECTED:
            await socket.close(code=1000)


def heartbeat(device_id):
    with connect() as db:
        db.execute("UPDATE devices SET last_seen = now() WHERE id = %s", (device_id,))
