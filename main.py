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
    print(msg, flush=True)
    sys.stdout.flush()


# ─── Token / session serialization (version-tolerant) ─────────────────────────
def dump_session(client: Garmin) -> str:
    """Serialize the Garmin session to a string blob across library versions."""
    for attr_path in (("garth",), ("client",), ("_garth",)):
        obj = client
        ok = True
        for attr in attr_path:
            if hasattr(obj, attr):
                obj = getattr(obj, attr)
            else:
                ok = False
                break
        if ok and hasattr(obj, "dumps"):
            return obj.dumps()
    if hasattr(client, "dumps"):
        return client.dumps()
    raise RuntimeError("Cannot find a dumps() method on Garmin client (unsupported version)")


def restore_client(token_blob: str) -> Garmin:
    """Rehydrate a Garmin client from a previously dumped session blob."""
    garmin = Garmin()
    # Try direct loads on the client
    if hasattr(garmin, "loads"):
        try:
            garmin.loads(token_blob)
            return garmin
        except Exception:
            pass
    # Try loads on inner garth
    if hasattr(garmin, "garth") and hasattr(garmin.garth, "loads"):
        try:
            garmin.garth.loads(token_blob)
            return garmin
        except Exception:
            pass
    # Fall back: pass blob to login()
    garmin.login(token_blob)
    return garmin


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
        log(f"[LOGIN] login() returned type={type(result).__name__}")

        # Detect "MFA required". The library may signal it as:
        #   - tuple ("needs_mfa", client_state)
        #   - bare string "needs_mfa"
        needs_mfa = False
        if isinstance(result, tuple) and len(result) >= 1 and result[0] == "needs_mfa":
            needs_mfa = True
        elif isinstance(result, str) and result == "needs_mfa":
            needs_mfa = True

        if needs_mfa:
            # This library version doesn't expose a serializable MFA state.
            # Tell the client to resubmit email + password + code together;
            # step 2 will redo the login with a prompt_mfa callback.
            log("[LOGIN] MFA required — client must resubmit with code")
            return {
                "success": True,
                "needs_mfa": True,
                "mfa_state": "stateless",  # marker only, not used server-side
            }

        # No MFA — login completed
        try:
            blob = dump_session(garmin)
        except Exception as e:
            log(f"[LOGIN] dump failed (no-MFA path): {e}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Cannot dump session: {e}")

        log("[LOGIN] no MFA, login complete")
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
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")

    mfa_code = body.get("mfa_code")
    email = body.get("email")
    password = body.get("password")

    log(f"[MFA] received: has_code={bool(mfa_code)}, has_email={bool(email)}, has_password={bool(password)}")

    if not mfa_code or not email or not password:
        raise HTTPException(status_code=400, detail="mfa_code, email and password required")

    code = str(mfa_code).strip()

    try:
        # Single-shot login with a prompt_mfa callback.
        # The library will trigger MFA, call our callback to get the code,
        # then complete the login in one call — no state to serialize.
        log("[MFA] starting fresh login with prompt_mfa callback")
        garmin = Garmin(email=email, password=password, prompt_mfa=lambda: code)
        garmin.login()
        log("[MFA] login() with prompt_mfa completed")

        try:
            blob = dump_session(garmin)
        except Exception as e:
            log(f"[MFA] dump failed: {e}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Cannot dump session: {e}")

        log(f"[MFA] success — token blob length={len(blob)}")
        return {
            "success": True,
            "oauth1_token": blob,
            "oauth2_token": blob,
        }

    except GarminConnectAuthenticationError as e:
        log(f"[MFA] auth failed: {e}")
        raise HTTPException(status_code=401, detail=f"MFA verification failed: {e}")
    except GarminConnectTooManyRequestsError as e:
        log(f"[MFA] rate limit: {e}")
        raise HTTPException(status_code=429, detail=f"Garmin rate limit: {e}")
    except Exception as e:
        log(f"[MFA] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        traceback.print_exc()
        sys.stdout.flush()
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

    if not email or not oauth1_token:
        raise HTTPException(status_code=400, detail="email and oauth1_token required")

    try:
        try:
            client = restore_client(oauth1_token)
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid Garmin tokens: {type(e).__name__}: {e}")

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
                        dl_fmt=client.ActivityDownloadFormat.GPX,
                    )
                    if gpx_data:
                        item["map_polyline"] = parse_gpx_to_polyline(gpx_data)
                except Exception as gpx_err:
                    log(f"GPX download failed for {activity_id}: {gpx_err}")

                result[str(activity_id)] = item
            except Exception as e:
                log(f"Skipping details for {activity_id}: {e}")
                result[str(activity_id)] = None

        return result

    except HTTPException:
        raise
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
