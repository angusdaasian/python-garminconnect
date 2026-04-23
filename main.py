from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)
import garth
import uvicorn
import os
import hashlib
import threading
import uuid
import time
from datetime import datetime, timedelta
from pathlib import Path
import polyline
import xml.etree.ElementTree as ET

BASE_TOKEN_PATH = os.environ.get("GARMIN_TOKEN_PATH", "/tmp/garmin_tokens")
MFA_SESSION_TTL_SECONDS = 300  # 5 min to enter the code

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory MFA session store ──────────────────────────────────────────────
# session_id -> {"client_state": dict, "signin_params": dict, "email": str,
#                 "token_path": str, "created": float}
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
    # garth writes oauth1_token.json + oauth2_token.json
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


# ─── /garmin-login (step 1) ───────────────────────────────────────────────────
@app.post("/garmin-login")
async def garmin_login(request: Request):
    """
    Step 1 of login.
    Body: { email, password }
    Response (no MFA): { success: true, needs_mfa: false }
    Response (MFA):    { success: true, needs_mfa: true, session_id }
    """
    _cleanup_mfa_sessions()
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password required")

    token_path = get_user_token_path(email)
    garth_client = garth.Client()

    try:
        # garth supports return_on_mfa=True since 0.4.x — returns
        # ("needs_mfa", {"client_state": ..., "signin_params": ...}) when MFA is required.
        result = garth_client.login(email, password, return_on_mfa=True)
    except Exception as e:
        msg = str(e).lower()
        if "rate" in msg or "429" in msg:
            raise HTTPException(status_code=429, detail="Garmin rate limit")
        raise HTTPException(status_code=401, detail=f"Garmin auth failed: {e}")

    needs_mfa = isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa"

    if needs_mfa:
        mfa_state = result[1]  # contains client_state + signin_params
        session_id = str(uuid.uuid4())
        with _mfa_lock:
            _mfa_sessions[session_id] = {
                "garth_client": garth_client,
                "mfa_state": mfa_state,
                "email": email,
                "token_path": token_path,
                "created": time.time(),
            }
        return {"success": True, "needs_mfa": True, "session_id": session_id}

    # No MFA — already logged in, persist tokens
    garth_client.dump(token_path)
    return {"success": True, "needs_mfa": False}


# ─── /garmin-login-mfa (step 2) ───────────────────────────────────────────────
@app.post("/garmin-login-mfa")
async def garmin_login_mfa(request: Request):
    """
    Step 2 of login (only if step 1 returned needs_mfa).
    Body: { session_id, mfa_code }
    Response: { success: true } on success
    """
    body = await request.json()
    session_id = body.get("session_id")
    mfa_code = body.get("mfa_code")
    if not session_id or not mfa_code:
        raise HTTPException(status_code=400, detail="session_id and mfa_code required")

    with _mfa_lock:
        session = _mfa_sessions.pop(session_id, None)
    if not session:
        raise HTTPException(status_code=404, detail="MFA session not found or expired")

    garth_client: garth.Client = session["garth_client"]
    mfa_state = session["mfa_state"]
    token_path = session["token_path"]

    try:
        garth_client.resume_login(mfa_state, str(mfa_code).strip())
        garth_client.dump(token_path)
    except Exception as e:
        # Re-store session so user can retry once if it was a typo? No — Garmin
        # invalidates the SSO state after a failed attempt. They must restart.
        raise HTTPException(status_code=401, detail=f"MFA verification failed: {e}")

    return {"success": True}


# ─── /garmin-activities (token-based) ─────────────────────────────────────────
@app.post("/garmin-activities")
async def post_activities(request: Request):
    """
    Body: { email, days?, detail_limit?, password? }
    Uses stored tokens. If tokens missing/expired and no password provided → 401.
    If password provided as fallback, performs a fresh login (will fail if MFA required).
    """
    body = await request.json()
    email = body.get("email")
    password = body.get("password")  # optional fallback
    days = body.get("days", 30)

    if not email:
        raise HTTPException(status_code=400, detail="email required")

    try:
        try:
            client = login_with_tokens(email)
        except GarminConnectAuthenticationError:
            if not password:
                raise HTTPException(
                    status_code=401,
                    detail="No valid Garmin session — please re-login",
                )
            # Fallback: fresh password login (no MFA support here)
            token_path = get_user_token_path(email)
            client = Garmin(email=email, password=password)
            client.login(token_path)

        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        activities = client.get_activities_by_date(
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )

        results = []
        for a in activities:
            sport = a.get("activityType", {}).get("typeKey", "unknown")
            duration = a.get("duration", 0) or 0
            distance = a.get("distance", 0) or 0
            avg_speed = (distance / duration) if duration > 0 else 0
            avg_pace = (duration / 60 / (distance / 1000)) if distance > 0 else None

            results.append({
                "garmin_activity_id": str(a.get("activityId", "")),
                "activity_name": a.get("activityName", "Garmin Activity"),
                "activity_type": sport,
                "start_time": a.get("startTimeLocal", a.get("startTimeGMT")),
                "duration_seconds": round(duration),
                "distance_meters": round(distance, 2),
                "calories": a.get("calories"),
                "average_hr": a.get("averageHR"),
                "max_hr": a.get("maxHR"),
                "elevation_gain": a.get("elevationGain"),
                "average_speed": round(avg_speed, 4),
                "average_pace": round(avg_pace, 2) if avg_pace else None,
                "avg_cadence": a.get("averageRunningCadenceInStepsPerMinute"),
                "aerobic_te": a.get("aerobicTrainingEffect"),
                "anaerobic_te": a.get("anaerobicTrainingEffect"),
                "vo2max": a.get("vO2MaxValue"),
                "training_load": a.get("activityTrainingLoad"),
                "has_gps": a.get("hasPolyline", False),
            })

        return results

    except HTTPException:
        raise
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        raise HTTPException(status_code=401, detail=f"Garmin login failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── /garmin-activity-details (token-based) ───────────────────────────────────
@app.post("/garmin-activity-details")
async def post_activity_details(request: Request):
    """
    Body: { email, activity_ids, password? }
    Same auth model as /garmin-activities.
    """
    body = await request.json()
    email = body.get("email")
    password = body.get("password")  # optional fallback
    activity_ids = body.get("activity_ids", "")

    if not email:
        raise HTTPException(status_code=400, detail="email required")

    try:
        try:
            client = login_with_tokens(email)
        except GarminConnectAuthenticationError:
            if not password:
                raise HTTPException(
                    status_code=401,
                    detail="No valid Garmin session — please re-login",
                )
            token_path = get_user_token_path(email)
            client = Garmin(email=email, password=password)
            client.login(token_path)

        ids = [aid.strip() for aid in activity_ids.split(",") if aid.strip()]
        result = {}

        for activity_id in ids:
            try:
                item = {"laps": [], "weather": None, "map_polyline": None}

                splits_data = client.get_activity_splits(activity_id)
                for lap in splits_data.get("lapDTOs", []):
                    item["laps"].append({
                        "split_number": lap.get("lapIndex"),
                        "distance": lap.get("distance"),
                        "elapsed_time": lap.get("elapsedDuration"),
                        "avg_hr": lap.get("averageHeartRate"),
                        "avg_speed": lap.get("averageSpeed"),
                        "elevation_gain": int(lap.get("elevationGain", 0)) if lap.get("elevationGain") else 0,
                    })

                try:
                    weather = client.get_activity_weather(activity_id)
                    if weather:
                        item["weather"] = {
                            "temp": weather.get("temp"),
                            "apparent_temp": weather.get("apparentTemp"),
                            "humidity": weather.get("relativeHumidity"),
                            "wind_speed": weather.get("windSpeed"),
                            "wind_direction": weather.get("windDirection"),
                            "weather_type": weather.get("weatherTypeName"),
                            "condition": weather.get("weatherTypeDTO", {}).get("desc") if weather.get("weatherTypeDTO") else None,
                        }
                except Exception:
                    pass

                try:
                    gpx_data = client.download_activity(
                        activity_id,
                        dl_fmt=client.ActivityDownloadFormat.GPX
                    )
                    if gpx_data:
                        item["map_polyline"] = parse_gpx_to_polyline(gpx_data)
                except Exception as gpx_err:
                    print(f"GPX download failed for {activity_id}: {gpx_err}")

                result[str(activity_id)] = item
            except Exception as e:
                print(f"Skipping details for {activity_id}: {e}")
                result[str(activity_id)] = None

        return result

    except HTTPException:
        raise
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # IMPORTANT: keep workers=1 so the in-memory _mfa_sessions dict is shared
    # between /garmin-login and /garmin-login-mfa requests.
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
