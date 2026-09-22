import asyncio
import base64
import json
import secrets
import time
import uuid
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.websockets import WebSocketDisconnect, WebSocketState

from .connections import endpoint_agents
from .database import (
    approve_pairing, authenticate_credential, authenticate_device, begin_session_close,
    claim_execution, create_caller, create_or_get_execution, create_starting_session,
    digest, fail_device_investigations, finish_execution, get_workspace_execution, get_workspace_session, increment_rate_limit,
    initialize, list_workspace_devices, mark_execution_unknown, mark_session_closed,
    mark_session_failed, mark_session_ready, record_heartbeat, recover_interrupted_work,
)
from .reachability import classify_reachability


@asynccontextmanager
async def lifespan(app):
    try:
        initialize()
        recover_interrupted_work()
    except Exception:
        raise RuntimeError("database_initialization_failed") from None
    yield


app = FastAPI(title="RMM investigation control plane", lifespan=lifespan)


@app.middleware("http")
async def enforce_request_body_limit(request: Request, call_next):
    # Reject streaming bodies before FastAPI's JSON parser allocates them.
    length = request.headers.get("content-length")
    if request.headers.get("transfer-encoding") or (request.method == "POST" and length is None):
        return JSONResponse(status_code=411, content={"detail": "content_length_required"})
    if length is not None and (not length.isdecimal() or int(length) > 1_048_576):
        return JSONResponse(status_code=413, content={"detail": "request_too_large"})
    return await call_next(request)


@app.middleware("http")
async def sanitize_unexpected_http_errors(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:
        # Database and framework exceptions may contain input/configuration values.
        return JSONResponse(status_code=503, content={"detail": "temporarily_unavailable"})


@app.exception_handler(RequestValidationError)
async def invalid_input(request: Request, error: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "invalid_request"})


def enforce_rate_limit(scope: str, limit: int) -> None:
    """Fixed, globally bounded buckets survive restarts; never keyed by untrusted IP."""
    if increment_rate_limit(scope) > limit:
        raise HTTPException(429, "rate_limited", headers={"Retry-After": "60"})


def authenticated_caller(authorization, required_role: str | None = None):
    """Resolve a revocable credential to a stable caller identity."""
    enforce_rate_limit("http_auth", 600)
    if not authorization or not authorization.startswith("Bearer ") or len(authorization) > 100:
        raise HTTPException(401, "unauthorized")
    caller = authenticate_credential(digest(authorization[7:]))
    if not caller:
        raise HTTPException(401, "unauthorized")
    if required_role is not None and caller["role"] != required_role:
        raise HTTPException(403, "forbidden")
    return caller


@app.get("/devices")
def list_devices(authorization: str | None = Header(default=None), after: uuid.UUID | None = None,
                 limit: int = Query(default=100, ge=1, le=100)):
    caller = authenticated_caller(authorization, "admin")
    observed_at = datetime.now(timezone.utc)
    devices = list_workspace_devices(caller["workspace_id"], after, limit + 1)
    page = [
        {"id": device["id"], "approved_at": device["approved_at"], "last_seen": device["last_seen"],
         "reachability": classify_reachability(device["last_seen"], device["activate_before"], observed_at)}
        for device in devices[:limit]
    ]
    return {"devices": page, "next_cursor": str(devices[limit - 1]["id"]) if len(devices) > limit else None}


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^[A-Z2-7]{12}$")


class CallerCreation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    role: str = Field(pattern=r"^(admin|operator)$")


@app.post("/callers", status_code=201)
def register_caller(body: CallerCreation, authorization: str | None = Header(default=None)):
    admin = authenticated_caller(authorization, "admin")
    credential = "rmm_" + secrets.token_urlsafe(32)
    try:
        caller_id, _ = create_caller(admin["workspace_id"], admin["id"], body.name, body.role, digest(credential))
    except Exception as error:
        if "callers_workspace_name_key" in str(error):
            raise HTTPException(409, "caller_name_conflict") from None
        raise
    return {"caller_id": str(caller_id), "role": body.role, "api_key": credential}


@app.post("/pairings/approve")
def approve(body: Approval, authorization: str | None = Header(default=None)):
    caller = authenticated_caller(authorization, "admin")
    workspace = caller["workspace_id"]
    enforce_rate_limit("approval:" + str(workspace), 10)
    device = approve_pairing(digest(body.code), workspace)
    if device is None:
        raise HTTPException(409, "invalid_or_consumed_code")
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
    code = base64.b32encode(secrets.token_bytes(8)).decode()[:12]
    return authenticate_device(public_key, code)


async def receive(socket):
    raw = await asyncio.wait_for(socket.receive_text(), 45)
    if len(raw) > 300_000:
        raise ValueError()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError()
    return value


async def close(socket, code=1000):
    if socket.application_state != WebSocketState.DISCONNECTED:
        with suppress(WebSocketDisconnect, RuntimeError):
            await socket.close(code=code)


def validate_endpoint_agent_message(message: dict) -> None:
    kind = message.get("type")
    common = {"type", "deviceId", "sessionId"}
    expected = {
        "session_ready": common,
        "session_closed": common,
        "running": common | {"executionId"},
        "result": common | {"executionId", "state", "invocationOutcome", "exitCode",
                            "exitCodeSource", "hadErrors", "stdout", "stderr", "durationMs",
                            "captureTruncated", "lastNativeExitCode"},
    }
    if kind not in expected or set(message) != expected[kind]:
        raise ValueError()
    if kind != "result":
        return
    if message["state"] not in {"completed", "timed_out", "outcome_unknown"}:
        raise ValueError()
    if not isinstance(message["stdout"], str) or not isinstance(message["stderr"], str):
        raise ValueError()
    if len(message["stdout"]) > 32768 or len(message["stderr"]) > 32768:
        raise ValueError()
    if not isinstance(message["hadErrors"], bool) or not isinstance(message["captureTruncated"], bool):
        raise ValueError()
    if message["state"] == "completed":
        if message["invocationOutcome"] not in {"completed_normally", "terminating_error", "explicit_exit"}:
            raise ValueError()
        if not isinstance(message["exitCode"], int) or message["exitCodeSource"] not in {
            "normalized_invocation", "explicit_script_exit",
        }:
            raise ValueError()
    elif message["exitCode"] is not None or message["exitCodeSource"] is not None:
        raise ValueError()
    elif message["state"] == "timed_out" and message["invocationOutcome"] != "stopped":
        raise ValueError()
    elif message["state"] == "outcome_unknown" and message["invocationOutcome"] is not None:
        raise ValueError()


class SessionCreation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_id: uuid.UUID


class ExecutionCreation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    script: str = Field(min_length=1, max_length=32768)
    timeout_ms: int = Field(default=30000, ge=100, le=30000)


def session_view(row):
    return {"session_id": str(row["id"]), "device_id": str(row["device_id"]),
            "caller_id": str(row["caller_id"]), "status": row["state"],
            "created_at": row["created_at"], "ready_at": row["ready_at"],
            "closed_at": row["closed_at"]}


def execution_view(row):
    return {"execution_id": str(row["id"]), "session_id": str(row["session_id"]),
            "caller_id": str(row["caller_id"]), "status": row["status"],
            "script_sha256": row["script_sha256"], "invocation_outcome": row["invocation_outcome"],
            "outcome_reason": row["outcome_reason"],
            "last_confirmed_status": row["last_confirmed_status"],
            "exit_code": row["exit_code"], "exit_code_source": row["exit_code_source"],
            "had_errors": row["had_errors"], "stdout": row["stdout"], "stderr": row["stderr"],
            "duration_ms": row["duration_ms"], "capture_truncated": row["capture_truncated"],
            "last_native_exit_code": row["last_native_exit_code"],
            "created_at": row["created_at"], "started_at": row["started_at"],
            "finished_at": row["finished_at"]}


@app.post("/sessions", status_code=201)
async def create_session(body: SessionCreation, authorization: str | None = Header(default=None)):
    caller = authenticated_caller(authorization, "operator")
    channel = await endpoint_agents.get_connected_channel(str(body.device_id))
    if channel is None:
        raise HTTPException(409, "device_offline")
    try:
        row = await asyncio.to_thread(create_starting_session, caller["workspace_id"], caller["id"], body.device_id)
    except RuntimeError as error:
        if str(error) == "device_busy":
            raise HTTPException(409, "device_busy") from None
        raise
    if row is None:
        raise HTTPException(404, "device_not_found")
    session_id = str(row["id"])
    ready = channel.expect("session_ready", session_id)
    try:
        await channel.send({"type": "open_session", "deviceId": str(body.device_id), "sessionId": session_id})
        await asyncio.wait_for(ready, 20)
        await asyncio.to_thread(mark_session_ready, row["id"])
    except Exception:
        await asyncio.to_thread(mark_session_failed, row["id"])
        raise HTTPException(503, "session_start_failed") from None
    return session_view(await asyncio.to_thread(get_workspace_session, caller["workspace_id"], row["id"]))


@app.get("/sessions/{session_id}")
async def get_session(session_id: uuid.UUID, authorization: str | None = Header(default=None)):
    caller = authenticated_caller(authorization, "operator")
    row = await asyncio.to_thread(get_workspace_session, caller["workspace_id"], session_id)
    if row is None:
        raise HTTPException(404, "session_not_found")
    return session_view(row)


async def dispatch_execution(execution_id: uuid.UUID, channel, device_id: str) -> None:
    row = await asyncio.to_thread(claim_execution, execution_id)
    if row is None:
        return
    running = channel.expect("running", str(execution_id))
    result = channel.expect("result", str(execution_id))
    last_confirmed_status = "queued"
    try:
        await channel.send({
            "type": "execute", "deviceId": device_id, "sessionId": str(row["session_id"]),
            "executionId": str(execution_id), "script": row["script"],
            "scriptSha256": row["script_sha256"], "timeoutMs": row["timeout_ms"],
        })
        running_message = await asyncio.wait_for(running, 10)
        expected = {"deviceId": device_id, "sessionId": str(row["session_id"]),
                    "executionId": str(execution_id)}
        if any(running_message.get(key) != value for key, value in expected.items()):
            raise ValueError("mismatched_running_binding")
        last_confirmed_status = "running"
        evidence = await asyncio.wait_for(result, row["timeout_ms"] / 1000 + 15)
        if any(evidence.get(key) != value for key, value in expected.items()):
            raise ValueError("mismatched_result_binding")
        await asyncio.to_thread(finish_execution, execution_id, evidence)
    except Exception:
        await asyncio.to_thread(mark_execution_unknown, execution_id,
                                "dispatch_confirmation_lost", last_confirmed_status)


@app.post("/sessions/{session_id}/executions", status_code=202)
async def submit_execution(body: ExecutionCreation, session_id: uuid.UUID,
                           authorization: str | None = Header(default=None),
                           idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")):
    caller = authenticated_caller(authorization, "operator")
    if idempotency_key is None or not 1 <= len(idempotency_key) <= 200:
        raise HTTPException(422, "idempotency_key_required")
    script_hash = __import__("hashlib").sha256(body.script.encode()).hexdigest()
    try:
        row, created = await asyncio.to_thread(
            create_or_get_execution, caller["workspace_id"], caller["id"], session_id,
            idempotency_key, body.script, script_hash, body.timeout_ms)
    except LookupError:
        raise HTTPException(404, "active_session_not_found") from None
    except RuntimeError as error:
        code = "idempotency_conflict" if str(error) == "idempotency_conflict" else "session_busy"
        raise HTTPException(409, code) from None
    if created:
        session = await asyncio.to_thread(get_workspace_session, caller["workspace_id"], session_id)
        channel = await endpoint_agents.get_connected_channel(str(session["device_id"]))
        if channel is None:
            await asyncio.to_thread(mark_execution_unknown, row["id"],
                                    "device_offline_before_dispatch", "queued")
        else:
            asyncio.create_task(dispatch_execution(row["id"], channel, str(session["device_id"])))
    return {"execution_id": str(row["id"]), "status": row["status"],
            "script_sha256": row["script_sha256"]}


@app.get("/executions/{execution_id}")
async def get_execution(execution_id: uuid.UUID, authorization: str | None = Header(default=None)):
    caller = authenticated_caller(authorization, "operator")
    row = await asyncio.to_thread(get_workspace_execution, caller["workspace_id"], execution_id)
    if row is None:
        raise HTTPException(404, "execution_not_found")
    return execution_view(row)


@app.post("/sessions/{session_id}/close")
async def close_session(session_id: uuid.UUID, authorization: str | None = Header(default=None)):
    caller = authenticated_caller(authorization, "operator")
    row = await asyncio.to_thread(begin_session_close, caller["workspace_id"], session_id)
    if row is None:
        raise HTTPException(409, "session_not_active")
    channel = await endpoint_agents.get_connected_channel(str(row["device_id"]))
    if channel is None:
        await asyncio.to_thread(mark_session_failed, session_id)
        raise HTTPException(503, "session_close_unconfirmed")
    closed = channel.expect("session_closed", str(session_id))
    try:
        await channel.send({"type": "close_session", "deviceId": str(row["device_id"]),
                            "sessionId": str(session_id)})
        await asyncio.wait_for(closed, 20)
        await asyncio.to_thread(mark_session_closed, session_id)
    except Exception:
        await asyncio.to_thread(mark_session_failed, session_id)
        raise HTTPException(503, "session_close_unconfirmed") from None
    return session_view(await asyncio.to_thread(get_workspace_session, caller["workspace_id"], session_id))


@app.websocket("/agent")
async def endpoint_agent(socket: WebSocket):
    try:
        await asyncio.to_thread(enforce_rate_limit, "agent_connections", 120)
    except HTTPException:
        await close(socket, 1008)
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
            await close(socket)
            return
        channel = await endpoint_agents.register(status["device_id"], socket)
        last_heartbeat = 0.0
        try:
            while True:
                message = await receive(socket)
                if message == {"type": "heartbeat"}:
                    if time.monotonic() - last_heartbeat < 1:
                        raise ValueError()
                    last_heartbeat = time.monotonic()
                    await asyncio.to_thread(record_heartbeat, status["device_id"])
                    await channel.send({"type": "heartbeat_ack"})
                    continue
                validate_endpoint_agent_message(message)
                if message.get("deviceId") != status["device_id"]:
                    raise ValueError()
                if not channel.deliver(message):
                    # Late or unsolicited evidence is never attached to another claim.
                    continue
        finally:
            if await endpoint_agents.unregister(channel):
                await asyncio.to_thread(fail_device_investigations, status["device_id"])
    except (InvalidSignature, ValueError, TypeError, KeyError):
        with suppress(WebSocketDisconnect, RuntimeError):
            await socket.send_json({"state": "denied"})
        await close(socket, 1008)
    except (WebSocketDisconnect, TimeoutError):
        pass
    except Exception:
        await close(socket, 1011)
    finally:
        await close(socket)
