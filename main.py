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
import json
import base64
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


# ─── Token serialization ──────────────────────────────────────────────────────
# After login, garmin.garth.dumps() returns a base64 string holding both
# OAuth1 + OAuth2 tokens. Restore by passing it to garmin.login(blob).

def dump_session(client: Garmin) -> str:
    return client.garth.dumps()


def restore_client(token_blob: str) -> Garmin:
    garmin = Garmin()
    garmin.login(token_blob)
    return garmin


# ─── MFA state serialization (stateless) ──────────────────────────────────────
# garmin.login(return_on_mfa=True) returns (result, client_state) where
# client_state is a small JSON-serializable dict. We base64-encode it so the
# frontend can hold it between login + MFA submit. No server-side session.

def encode_mfa_state(client_state: dict) -> str:
    return base64.b64encode(json.dumps(client_state).encode()).decode()


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
        print(f"GPX parse error: {e}")
        return None


@app.get("/")
async def root():
    return {"status": "ok"}


# ─── /garmin-login (step 1) ───────────────────────────────────────────────────
@app.post("/garmin-login")
async def garmin_login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password required")

    try:
        garmin = Garmin(email=email, password=password, return_on_mfa=True)
        result = garmin.login()

        # Official garminconnect MFA pattern: result is a tuple
        # (status, client_state) when MFA is required.
        if isinstance(result, tuple) and len(result) == 2 and result[0] == "needs_mfa":
            _, client_state = result
            print(f"MFA required for {email}")
            return {
                "success": True,
                "needs_mfa": True,
                "mfa_state": encode_mfa_state(client_state),
            }

        # No MFA — login completed
        blob = dump_session(garmin)
        return {
            "success": True,
            "needs_mfa": False,
            "oauth1_token": blob,
            "oauth2_token": blob,
        }

    except GarminConnectAuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"Garmin auth failed: {e}")
    except GarminConnectTooManyRequestsError as e:
        raise HTTPException(status_code=429, detail=f"Garmin rate limit: {e}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-login-mfa (step 2) ───────────────────────────────────────────────
@app.post("/garmin-login-mfa")
async def garmin_login_mfa(request: Request):
    body = await request.json()
    mfa_state_blob = body.get("mfa_state")
    mfa_code = body.get("mfa_code")
    email = body.get("email")
    password = body.get("password")

    if not mfa_state_blob or not mfa_code:
        raise HTTPException(status_code=400, detail="mfa_state and mfa_code required")

    try:
        client_state = decode_mfa_state(mfa_state_blob)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid mfa_state: {e}")

    try:
        # Recreate the client with same credentials, then resume with the code.
        garmin = Garmin(email=email or "", password=password or "", return_on_mfa=True)
        garmin.resume_login(client_state, str(mfa_code).strip())

        blob = dump_session(garmin)
        return {
            "success": True,
            "oauth1_token": blob,
            "oauth2_token": blob,
        }

    except GarminConnectAuthenticationError as e:
        raise HTTPException(status_code=401, detail=f"MFA verification failed: {e}")
    except GarminConnectTooManyRequestsError as e:
        raise HTTPException(status_code=429, detail=f"Garmin rate limit: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-activities ───────────────────────────────────────────────────────
@app.post("/garmin-activities")
async def post_activities(request: Request):
    body = await request.json()
    email = body.get("email")
    oauth1_token = body.get("oauth1_token")
    days = body.get("days", 30)

    if not email or not oauth1_token:
        raise HTTPException(status_code=400, detail="email and oauth1_token required")

    try:
        try:
            client = restore_client(oauth1_token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid Garmin tokens: {type(e).__name__}: {e}")

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
        raise HTTPException(status_code=401, detail=f"Garmin session expired: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-activity-details ─────────────────────────────────────────────────
@app.post("/garmin-activity-details")
async def post_activity_details(request: Request):
    body = await request.json()
    email = body.get("email")
    oauth1_token = body.get("oauth1_token")
    activity_ids = body.get("activity_ids", "")

    if not email or not oaut
