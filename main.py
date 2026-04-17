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
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
import polyline
import xml.etree.ElementTree as ET

BASE_TOKEN_PATH = os.environ.get("GARMIN_TOKEN_PATH", "/tmp/garmin_tokens")
SESSION_TTL_DAYS = 365
SESSION_SECRET = os.environ.get("SESSION_SECRET")
if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET env var is required")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_user_token_path(email: str) -> str:
    user_hash = hashlib.sha256(email.lower().strip().encode()).hexdigest()
    path = os.path.join(BASE_TOKEN_PATH, user_hash)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def issue_session_token(email: str) -> tuple[str, datetime]:
    """Create a signed JWT containing the user's email. Stateless — no server storage."""
    expires_at = datetime.now(timezone.utc) + timedelta(days=SESSION_TTL_DAYS)
    payload = {
        "email": email,
        "exp": int(expires_at.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }
    token = jwt.encode(payload, SESSION_SECRET, algorithm="HS256")
    return token, expires_at


def get_email_from_session(authorization: Optional[str]) -> str:
    """Decode bearer JWT → return email. Raises 401 on any failure."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid session: {e}")
    email = payload.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid session payload")
    return email


def login_with_cached_tokens(email: str) -> Garmin:
    """Re-login using cached Garmin tokens on disk (no password needed if tokens valid).
    Raises 401 if cached tokens are missing or invalid — user must reconnect."""
    token_path = get_user_token_path(email)
    # Check the directory has token files
    has_tokens = any(Path(token_path).iterdir()) if Path(token_path).exists() else False
    if not has_tokens:
        raise HTTPException(
            status_code=401,
            detail="Garmin tokens not found on server. Please reconnect."
        )
    try:
        client = Garmin()
        client.login(token_path)
        return client
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        raise HTTPException(
            status_code=401,
            detail=f"Garmin tokens invalid or expired. Please reconnect. ({e})"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Garmin login error: {e}")


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
    try:
        root = ET.fromstring(tcx_bytes)
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
        # Login with password — this writes Garmin tokens to disk for future stateless reuse
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

    # Issue stateless JWT — no in-memory storage
    token, expires_at = issue_session_token(email)

    return {
        "session_token": token,
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "display_name": display_name,
    }


# ── /garmin-logout ──
@app.post("/garmin-logout")
async def garmin_logout(authorization: Optional[str] = Header(None)):
    # Stateless JWT — nothing to revoke server-side. Optionally wipe cached Garmin tokens.
    try:
        email = get_email_from_session(authorization)
        token_path = Path(get_user_token_path(email))
        if token_path.exists():
            for f in token_path.iterdir():
                try:
                    f.unlink()
                except Exception:
                    pass
    except HTTPException:
        pass  # Invalid/expired token — nothing to clean
    return {"success": True}


# ── /garmin-activities ──
@app.post("/garmin-activities")
async def post_activities(request: Request, authorization: Optional[str] = Header(None)):
    email = get_email_from_session(authorization)
    body = await request.json()
    days = body.get("days", 30)

    try:
        client = login_with_cached_tokens(email)

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
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── /garmin-activity-details ──
@app.post("/garmin-activity-details")
async def post_activity_details(request: Request, authorization: Optional[str] = Header(None)):
    email = get_email_from_session(authorization)
    body = await request.json()
    activity_ids = body.get("activity_ids", "")

    try:
        client = login_with_cached_tokens(email)

        ids = [aid.strip() for aid in activity_ids.split(",") if aid.strip()]
        result = {}

        for activity_id in ids:
            try:
                item = {"laps": [], "weather": None, "map_polyline": None}

                # ── 3-tier lap fetch: laps → splits → TCX ──
                mapped_laps = []

                try:
                    laps_data = client.get_activity_laps(activity_id)
                    raw_laps = laps_data.get("lapDTOs", []) or []
                    if raw_laps:
                        mapped_laps = [map_lap_dto(lap, i + 1) for i, lap in enumerate(raw_laps)]
                except Exception as e:
                    print(f"get_activity_laps failed for {activity_id}: {e}")

                if not mapped_laps:
                    try:
                        splits_data = client.get_activity_splits(activity_id)
                        raw_splits = splits_data.get("lapDTOs", []) or []
                        if raw_splits:
                            mapped_laps = [map_lap_dto(lap, i + 1) for i, lap in enumerate(raw_splits)]
                    except Exception as e:
                        print(f"get_activity_splits failed for {activity_id}: {e}")

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
                                if mapped_laps and len(mapped_laps) == len(tcx_laps):
                                    for existing, tcx_lap in zip(mapped_laps, tcx_laps):
                                        if not existing.get("avg_hr"):
                                            existing["avg_hr"] = tcx_lap.get("avg_hr")
                                        if not existing.get("max_hr"):
                                            existing["max_hr"] = tcx_lap.get("max_hr")
                                else:
                                    mapped_laps = tcx_laps
                    except Exception as tcx_err:
                        print(f"TCX fallback failed for {activity_id}: {tcx_err}")

                item["laps"] = mapped_laps

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
    uvicorn.run(app, host="0.0.0.0", port=port)
