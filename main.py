from fastapi import FastAPI, HTTPException, Request, Header
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
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
import polyline
import xml.etree.ElementTree as ET

BASE_TOKEN_PATH = os.environ.get("GARMIN_TOKEN_PATH", "/tmp/garmin_tokens")
SESSION_TTL_DAYS = 365

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store: {token: {"email","password","expires_at"}}
# NOTE: resets on every Railway redeploy/restart — users will need to reconnect.
SESSIONS: dict = {}


def get_user_token_path(email: str) -> str:
    user_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    path = os.path.join(BASE_TOKEN_PATH, user_hash)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def cleanup_expired_sessions():
    now = datetime.utcnow()
    expired = [t for t, s in SESSIONS.items() if s["expires_at"] < now]
    for t in expired:
        SESSIONS.pop(t, None)


def get_session(authorization: Optional[str]) -> dict:
    cleanup_expired_sessions()
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if session["expires_at"] < datetime.utcnow():
        SESSIONS.pop(token, None)
        raise HTTPException(status_code=401, detail="Session expired")
    return session


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


def parse_tcx_laps(tcx_bytes: bytes) -> list:
    """Parse TCX file and extract per-lap data including HR. Most reliable HR source."""
    try:
        root = ET.fromstring(tcx_bytes)
        # TCX uses a namespace
        ns = {"tcx": "http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2"}
        laps = []
        for idx, lap_el in enumerate(root.findall(".//tcx:Lap", ns), start=1):
            def _find_float(tag):
                el = lap_el.find(f"tcx:{tag}", ns)
                return float(el.text) if el is not None and el.text else None

            def _find_int_in(parent_tag, child_tag):
                parent = lap_el.find(f"tcx:{parent_tag}", ns)
                if parent is None:
                    return None
                child = parent.find(f"tcx:{child_tag}", ns)
                return int(child.text) if child is not None and child.text else None

            total_time = _find_float("TotalTimeSeconds") or 0
            distance = _find_float("DistanceMeters") or 0
            max_speed = _find_float("MaximumSpeed")
            calories_el = lap_el.find("tcx:Calories", ns)
            calories = int(calories_el.text) if calories_el is not None and calories_el.text else None

            avg_hr = _find_int_in("AverageHeartRateBpm", "Value")
            max_hr = _find_int_in("MaximumHeartRateBpm", "Value")

            avg_speed = (distance / total_time) if total_time > 0 else None
            pace_sec_per_km = (total_time / (distance / 1000)) if distance > 0 else None

            laps.append({
                "split_number": idx,
                "distance": distance,
                "elapsed_time": total_time,
                "moving_time": total_time,
                "avg_hr": avg_hr,
                "max_hr": max_hr,
                "avg_speed": avg_speed,
                "max_speed": max_speed,
                "avg_pace_sec_per_km": round(pace_sec_per_km, 1) if pace_sec_per_km else None,
                "avg_cadence": None,
                "elevation_gain": 0,
                "elevation_loss": 0,
                "calories": calories,
            })
        return laps
    except Exception as e:
        print(f"TCX parse error: {e}")
        return []


def map_lap_dto(lap: dict, idx: int) -> dict:
    """Map a Garmin lapDTO into our normalized lap shape."""
    distance_m = lap.get("distance") or 0
    elapsed_s = lap.get("elapsedDuration") or lap.get("duration") or 0
    avg_speed = lap.get("averageSpeed")
    pace_sec_per_km = (elapsed_s / (distance_m / 1000)) if distance_m > 0 else None
    return {
        "split_number": lap.get("lapIndex") or idx,
        "distance": distance_m,
        "elapsed_time": elapsed_s,
        "moving_time": lap.get("movingDuration"),
        "avg_hr": lap.get("averageHR") or lap.get("averageHeartRate") or lap.get("avgHr"),
        "max_hr": lap.get("maxHR") or lap.get("maxHeartRate") or lap.get("maxHr"),
        "avg_speed": avg_speed,
        "max_speed": lap.get("maxSpeed"),
        "avg_pace_sec_per_km": round(pace_sec_per_km, 1) if pace_sec_per_km else None,
        "avg_cadence": lap.get("averageRunCadence") or lap.get("averageRunningCadenceInStepsPerMinute"),
        "elevation_gain": int(lap.get("elevationGain") or 0),
        "elevation_loss": int(lap.get("elevationLoss") or 0),
        "calories": lap.get("calories"),
    }


# ── /garmin-login ──
@app.post("/garmin-login")
async def garmin_login(request: Request):
    body = await request.json()
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password required")

    try:
        token_path = get_user_token_path(email)
        client = Garmin(email=email, password=password)
        client.login(token_path)
        try:
            display_name = client.get_full_name() or email
        except Exception:
            display_name = email
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        raise HTTPException(status_code=401, detail=f"Garmin login failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=SESSION_TTL_DAYS)
    SESSIONS[token] = {"email": email, "password": password, "expires_at": expires_at}
    cleanup_expired_sessions()

    return {
        "session_token": token,
        "expires_at": expires_at.isoformat() + "Z",
        "display_name": display_name,
    }


# ── /garmin-logout ──
@app.post("/garmin-logout")
async def garmin_logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        SESSIONS.pop(token, None)
    return {"success": True}


# ── /garmin-activities ──
@app.post("/garmin-activities")
async def post_activities(request: Request, authorization: Optional[str] = Header(None)):
    session = get_session(authorization)
    email = session["email"]
    password = session["password"]

    body = await request.json()
    days = body.get("days", 30)

    try:
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

    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        raise HTTPException(status_code=401, detail=f"Garmin login failed: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── /garmin-activity-details ──
@app.post("/garmin-activity-details")
async def post_activity_details(request: Request, authorization: Optional[str] = Header(None)):
    session = get_session(authorization)
    email = session["email"]
    password = session["password"]

    body = await request.json()
    activity_ids = body.get("activity_ids", "")

    try:
        token_path = get_user_token_path(email)
        client = Garmin(email=email, password=password)
        client.login(token_path)

        ids = [aid.strip() for aid in activity_ids.split(",") if aid.strip()]
        result = {}

        for activity_id in ids:
            try:
                item = {"laps": [], "weather": None, "map_polyline": None}

                # ── 3-tier lap fetch: laps → splits → TCX ──
                mapped_laps = []

                # Tier 1: get_activity_laps (manual lap-button presses)
                try:
                    laps_data = client.get_activity_laps(activity_id)
                    raw_laps = laps_data.get("lapDTOs", []) or []
                    if raw_laps:
                        mapped_laps = [map_lap_dto(lap, i + 1) for i, lap in enumerate(raw_laps)]
                except Exception as e:
                    print(f"get_activity_laps failed for {activity_id}: {e}")

                # Tier 2: get_activity_splits (auto 1km/mile splits)
                if not mapped_laps:
                    try:
                        splits_data = client.get_activity_splits(activity_id)
                        raw_splits = splits_data.get("lapDTOs", []) or []
                        if raw_splits:
                            mapped_laps = [map_lap_dto(lap, i + 1) for i, lap in enumerate(raw_splits)]
                    except Exception as e:
                        print(f"get_activity_splits failed for {activity_id}: {e}")

                # Tier 3: TCX fallback (most reliable for HR)
                # Trigger if we have NO laps OR laps are missing HR data
                needs_tcx_fallback = not mapped_laps or all(
                    not lap.get("avg_hr") for lap in mapped_laps
                )
                if needs_tcx_fallback:
                    try:
                        tcx_data = client.download_activity(
                            activity_id,
                            dl_fmt=client.ActivityDownloadFormat.TCX
                        )
                        if tcx_data:
                            tcx_laps = parse_tcx_laps(tcx_data)
                            if tcx_laps:
                                # If we already have laps but missing HR, merge HR from TCX
                                if mapped_laps and len(mapped_laps) == len(tcx_laps):
                                    for existing, tcx_lap in zip(mapped_laps, tcx_laps):
                                        if not existing.get("avg_hr"):
                                            existing["avg_hr"] = tcx_lap.get("avg_hr")
                                        if not existing.get("max_hr"):
                                            existing["max_hr"] = tcx_lap.get("max_hr")
                                else:
                                    # Use TCX laps wholesale
                                    mapped_laps = tcx_laps
                    except Exception as tcx_err:
                        print(f"TCX fallback failed for {activity_id}: {tcx_err}")

                item["laps"] = mapped_laps

                # Weather
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

                # GPX → polyline
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

    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
