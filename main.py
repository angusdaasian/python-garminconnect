from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)
import uvicorn
import os
import sys
import json
import base64
import traceback
from datetime import datetime, timedelta
import polyline
import xml.etree.ElementTree as ET

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def log(msg: str):
    """Force-flush print so Railway shows logs immediately."""
    print(msg, flush=True)
    sys.stdout.flush()


# ─── Token serialization ──────────────────────────────────────────────────────
def dump_session(client: Garmin) -> str:
    return client.garth.dumps()


def restore_client(token_blob: str) -> Garmin:
    garmin = Garmin()
    garmin.login(token_blob)
    return garmin


# ─── MFA state serialization (stateless) ──────────────────────────────────────
def encode_mfa_state(client_state) -> str:
    # client_state from garminconnect may be a dict OR an object — coerce to JSON-safe.
    if hasattr(client_state, "__dict__") and not isinstance(client_state, dict):
        try:
            client_state = client_state.__dict__
        except Exception:
            pass
    return base64.b64encode(json.dumps(client_state, default=str).encode()).decode()


def decode_mfa_state(blob: str) -> dict:
    return json.loads(base64.b64decode(blob.encode()).decode())


def parse_gpx_to_polyline(gpx_bytes: bytes) -> str | None:
    try:
        root = ET.fromstring(gpx_bytes)
        ns = {"gpx": "http://www.topografix.com/GPX/1/1"}
        coords = []
        for trkpt in root.findall(".//gpx:trkpt", ns):
            lat = float(trkpt.get("lat"))
            lon = float(trkpt.get("lon"))
            coords.append((lat, lon))
        if len(coords) < 2:
            return None
        if len(coords) > 200:
            step = len(coords) // 200
            coords = coords[::step]
        return polyline.encode(coords)
    except Exception as e:
        log(f"GPX parse error: {e}")
        return None


@app.get("/")
async def root():
    try:
        import garminconnect as gc
        version = getattr(gc, "__version__", "unknown")
    except Exception:
        version = "unknown"
    return {"status": "ok", "garminconnect_version": version}


# ─── /garmin-login (step 1) ───────────────────────────────────────────────────
@app.post("/garmin-login")
async def garmin_login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password required")

    log(f"[LOGIN] start for {email}")

    try:
        garmin = Garmin(email=email, password=password, return_on_mfa=True)
        result = garmin.login()
        log(f"[LOGIN] login() returned type={type(result).__name__}, value={result if not isinstance(result, tuple) else 'tuple(len=' + str(len(result)) + ')'}")

        # garminconnect returns a tuple ("needs_mfa", client_state) when MFA is required.
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
            _, client_state = result
            log(f"[LOGIN] MFA required, client_state type={type(client_state).__name__}")
            try:
                state_blob = encode_mfa_state(client_state)
                log(f"[LOGIN] encoded client_state, length={len(state_blob)}")
            except Exception as e:
                log(f"[LOGIN] FAILED to encode client_state: {e}")
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"Cannot serialize MFA state: {e}")

            return {
                "success": True,
                "needs_mfa": True,
                "mfa_state": state_blob,
            }

        # No MFA — login completed
        blob = dump_session(garmin)
        log(f"[LOGIN] no MFA, login complete")
        return {
            "success": True,
            "needs_mfa": False,
            "oauth1_token": blob,
            "oauth2_token": blob,
        }

    except GarminConnectAuthenticationError as e:
        log(f"[LOGIN] auth error: {e}")
        raise HTTPException(status_code=401, detail=f"Garmin auth failed: {e}")
    except GarminConnectTooManyRequestsError as e:
        log(f"[LOGIN] rate limit: {e}")
        raise HTTPException(status_code=429, detail=f"Garmin rate limit: {e}")
    except HTTPException:
        raise
    except Exception as e:
        log(f"[LOGIN] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-login-mfa (step 2) ───────────────────────────────────────────────
@app.post("/garmin-login-mfa")
async def garmin_login_mfa(request: Request):
    log("[MFA] ===== /garmin-login-mfa called =====")
    try:
        body = await request.json()
    except Exception as e:
        log(f"[MFA] failed to parse body: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")

    mfa_state_blob = body.get("mfa_state")
    mfa_code = body.get("mfa_code")
    email = body.get("email")
    password = body.get("password")

    log(f"[MFA] received: has_state={bool(mfa_state_blob)}, has_code={bool(mfa_code)}, has_email={bool(email)}, has_password={bool(password)}")

    if not mfa_state_blob or not mfa_code:
        raise HTTPException(status_code=400, detail="mfa_state and mfa_code required")

    if not email or not password:
        log("[MFA] missing email/password — resume_login may need them")
        raise HTTPException(status_code=400, detail="email and password required for resume")

    try:
        client_state = decode_mfa_state(mfa_state_blob)
        log(f"[MFA] decoded client_state, type={type(client_state).__name__}, keys={list(client_state.keys()) if isinstance(client_state, dict) else 'n/a'}")
    except Exception as e:
        log(f"[MFA] decode error: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid mfa_state: {e}")

    try:
        log("[MFA] constructing Garmin client with return_on_mfa=True")
        garmin = Garmin(email=email, password=password, return_on_mfa=True)

        log("[MFA] calling resume_login...")
        result = garmin.resume_login(client_state, str(mfa_code).strip())
        log(f"[MFA] resume_login returned type={type(result).__name__}")

        log("[MFA] dumping session tokens")
        blob = dump_session(garmin)
