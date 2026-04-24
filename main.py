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
import hashlib
import threading
import queue
import uuid
import time
from datetime import datetime, timedelta
from pathlib import Path
import polyline
import xml.etree.ElementTree as ET

BASE_TOKEN_PATH = os.environ.get("GARMIN_TOKEN_PATH", "/tmp/garmin_tokens")
MFA_SESSION_TTL_SECONDS = 300  # 5 min for the user to enter the code

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory MFA session store ──────────────────────────────────────────────
# session_id -> {"code_q", "result_q", "thread", "created"}
_mfa_sessions: dict[str, dict] = {}
_mfa_lock = threading.Lock()


def _cleanup_mfa_sessions():
    now = time.time()
    with _mfa_lock:
        stale = [sid for sid, s in _mfa_sessions.items() if now - s["created"] > MFA_SESSION_TTL_SECONDS]
        for sid in stale:
            _mfa_sessions.pop(sid, None)


# ─── Helpers ──────────────────────────────────────────────────────────────────
def get_user_token_path(email: str) -> str:
    user_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    path = os.path.join(BASE_TOKEN_PATH, user_hash)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def has_stored_tokens(token_path: str) -> bool:
    return (
        Path(token_path, "oauth1_token.json").exists()
        and Path(token_path, "oauth2_token.json").exists()
    )


def login_with_tokens(email: str) -> Garmin:
    """Login using stored tokens only. Raises if tokens missing/expired."""
    token_path = get_user_token_path(email)
    if not has_stored_tokens(token_path):
        raise GarminConnectAuthenticationError("No stored tokens for user")
    client = Garmin()
    client.login(token_path)  # loads tokens from disk and refreshes
    return client


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
        print(f"GPX parse error: {e}")
        return None


# ─── /garmin-login (step 1) ───────────────────────────────
