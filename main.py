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
import shutil
import tempfile
import traceback
import json
from pathlib import Path
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


# ─── Token store helpers ──────────────────────────────────────────────────────
# python-garminconnect wraps `garth`. The source of truth for current tokens
# is `garmin.garth.oauth1_token` and `garmin.garth.oauth2_token` — Python
# objects with a `.dumps()` method that returns the JSON blob we persist.
#
# We do NOT rely on garth dumping files to disk, because behavior varies by
# version (sometimes it writes to the dir we pass, sometimes to ~/.garminconnect,
# sometimes not at all if the OAuth2 token is still valid).

OAUTH1_FILENAME = "oauth1_token.json"
OAUTH2_FILENAME = "oauth2_token.json"


def _write_tokenstore(oauth1_blob: str, oauth2_blob: str | None) -> str:
    tdir = tempfile.mkdtemp(prefix="gctok_")
    Path(tdir, OAUTH1_FILENAME).write_text(oauth1_blob)
    # Only write oauth2 file if we actually have a real oauth2 blob.
    # Seeding it with the oauth1 blob corrupts login (garth tries to parse
    # an OAuth1 ticket as an OAuth2 token and fails).
    if oauth2_blob:
        Path(tdir, OAUTH2_FILENAME).write_text(oauth2_blob)
    return tdir


def _extract_tokens_from_client(garmin: Garmin) -> tuple[str, str]:
    """Pull the current OAuth1 + OAuth2 token blobs straight from the
    `garth` client embedded in the Garmin object. This is version-agnostic:
    no matter what garminconnect 3.x does with on-disk files, the in-memory
    garth client holds the live tokens after a successful login."""
    garth = getattr(garmin, "garth", None)
    if garth is None:
        raise RuntimeError("garmin.garth is missing — unsupported library version")

    o1_obj = getattr(garth, "oauth1_token", None)
    o2_obj = getattr(garth, "oauth2_token", None)
    if o1_obj is None or o2_obj is None:
        raise RuntimeError("garth has no oauth1_token / oauth2_token after login")

    # Both garth token objects expose .dumps() → JSON string.
    # Fall back to json.dumps(asdict) if .dumps is missing on some versions.
    def to_blob(tok) -> str:
        if hasattr(tok, "dumps") and callable(tok.dumps):
            return tok.dumps()
        # Last-ditch: serialize __dict__
        try:
            return json.dumps(tok.__dict__, default=str)
        except Exception as e:
            raise RuntimeError(f"cannot serialize garth token: {e}")

    return to_blob(o1_obj), to_blob(o2_obj)


def login_with_tokens(oauth1_blob: str, oauth2_blob: str | None = None):
    """Restore a Garmin session from stored tokens.

    Returns (client, refreshed_oauth1, refreshed_oauth2). Always echo the
    refreshed blobs back so Supabase can re-encrypt and persist them — this
    is what keeps the OAuth2 token alive past 24h without re-prompting.
    """
    tdir = _write_tokenstore(oauth1_blob, oauth2_blob)
    try:
        garmin = Garmin()
        garmin.login(tdir)  # auto-refreshes OAuth2 in place if expired
        new_o1, new_o2 = _extract_tokens_from_client(garmin)
        return garmin, new_o1, new_o2
    finally:
        shutil.rmtree(tdir, ignore_errors=True)


class _MFARequired(Exception):
    pass


def fresh_login(email: str, password: str, mfa_code: str | None = None):
    """Fresh credentials login. Returns (client, oauth1, oauth2).

    Raises _MFARequired if Garmin needs an MFA code and none was supplied.
    """
    tdir = tempfile.mkdtemp(prefix="gctok_")
    try:
        if mfa_code is not None:
            code = str(mfa_code).strip()
            garmin = Garmin(email=email, password=password, prompt_mfa=lambda: code)
            garmin.login(tdir)
        else:
            garmin = Garmin(email=email, password=password, return_on_mfa=True)
            result = garmin.login(tdir)
            needs_mfa = (
                (isinstance(result, tuple) and len(result) >= 1 and result[0] == "needs_mfa")
                or (isinstance(result, str) and result == "needs_mfa")
            )
            if needs_mfa:
                raise _MFARequired()
        oauth1, oauth2 = _extract_tokens_from_client(garmin)
        if not oauth1 or not oauth2:
            raise RuntimeError("login succeeded but garth returned empty tokens")
        return garmin, oauth1, oauth2
    finally:
        shutil.rmtree(tdir, ignore_errors=True)


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
        try:
            _, oauth1, oauth2 = fresh_login(email, password, mfa_code=None)
        except _MFARequired:
            log("[LOGIN] MFA required — client must resubmit with code")
            return {"success": True, "needs_mfa": True, "mfa_state": "stateless"}

        log("[LOGIN] no MFA, login complete")
        return {
            "success": True,
            "needs_mfa": False,
            "oauth1_token": oauth1,
            "oauth2_token": oauth2,
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

    try:
        _, oauth1, oauth2 = fresh_login(email, password, mfa_code=mfa_code)
        log(f"[MFA] success — oauth1 len={len(oauth1)} oauth2 len={len(oauth2)}")
        return {"success": True, "oauth1_token": oauth1, "oauth2_token": oauth2}

    except GarminConnectAuthenticationError as e:
        log(f"[MFA] auth failed: {e}")
        raise HTTPException(status_code=401, detail=f"MFA verification failed: {e}")
    except GarminConnectTooManyRequestsError as e:
        log(f"[MFA] rate limit: {e}")
        raise HTTPException(status_code=429, detail=f"Garmin rate limit: {e}")
    except Exception as e:
        log(f"[MFA] UNEXPECTED ERROR: {type(e).__name__}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-activities ───────────────────────────────────────────────────────
@app.post("/garmin-activities")
async def post_activities(request: Request):
    body = await request.json()
    email = body.get("email")
    oauth1_token = body.get("oauth1_token")
    oauth2_token = body.get("oauth2_token")
    start_date_str = body.get("start_date")
    end_date_str = body.get("end_date")
    days = body.get("days")

    if not email or not oauth1_token:
        raise HTTPException(status_code=400, detail="email and oauth1_token required")

    try:
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d")
        else:
            end_date = datetime.now()
            start_date = end_date - timedelta(days=int(days) if days else 30)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format (expected YYYY-MM-DD): {e}")

    if start_date > end_date:
        raise HTTPException(status_code=400, detail="start_date must be <= end_date")

    log(f"[ACTIVITIES] window {start_date.date()} → {end_date.date()} for {email}")

    try:
        try:
            client, new_o1, new_o2 = login_with_tokens(oauth1_token, oauth2_token)
        except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
            raise HTTPException(status_code=401, detail=f"Garmin session expired: {e}")
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid Garmin tokens: {type(e).__name__}: {e}")

        activities = client.get_activities_by_date(
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )

        log(f"[ACTIVITIES] fetched {len(activities)} activities")

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

        return {
            "activities": results,
            "oauth1_token": new_o1,
            "oauth2_token": new_o2,
        }

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
    oauth2_token = body.get("oauth2_token")
    activity_ids = body.get("activity_ids", "")

    if not email or not oauth1_token:
        raise HTTPException(status_code=400, detail="email and oauth1_token required")

    try:
        try:
            client, new_o1, new_o2 = login_with_tokens(oauth1_token, oauth2_token)
        except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
            raise HTTPException(status_code=401, detail=f"Garmin session expired: {e}")
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

        return {
            "details": result,
            "oauth1_token": new_o1,
            "oauth2_token": new_o2,
        }

    except HTTPException:
        raise
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ─── /garmin-health-stats ─────────────────────────────────────────────────────
@app.post("/garmin-health-stats")
async def post_health_stats(request: Request):
    """Return vo2max, resting HR, sleep duration, and sleep score for a date.

    Body:
      - email          (required)
      - oauth1_token   (required)
      - oauth2_token   (optional but recommended)
      - date           (optional, "YYYY-MM-DD" — defaults to today)
    """
    body = await request.json()
    email = body.get("email")
    oauth1_token = body.get("oauth1_token")
    oauth2_token = body.get("oauth2_token")
    date_str = body.get("date") or datetime.now().strftime("%Y-%m-%d")

    if not email or not oauth1_token:
        raise HTTPException(status_code=400, detail="email and oauth1_token required")

    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD")

    log(f"[HEALTH] {email} date={date_str}")

    try:
        try:
            client, new_o1, new_o2 = login_with_tokens(oauth1_token, oauth2_token)
        except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
            raise HTTPException(status_code=401, detail=f"Garmin session expired: {e}")
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"Invalid Garmin tokens: {type(e).__name__}: {e}")

        # Resting HR — try get_heart_rates first, fall back to user summary.
        resting_hr = None
        try:
            hr = client.get_heart_rates(date_str) or {}
            resting_hr = hr.get("restingHeartRate")
        except Exception as e:
            log(f"[HEALTH] heart_rates failed: {e}")
        if resting_hr is None:
            try:
                summary = client.get_user_summary(date_str) or {}
                resting_hr = summary.get("restingHeartRate")
            except Exception as e:
                log(f"[HEALTH] user_summary failed: {e}")

        # Sleep duration + sleep score
        sleep_seconds = None
        sleep_score = None
        try:
            sleep = client.get_sleep_data(date_str) or {}
            daily = sleep.get("dailySleepDTO", {}) or {}
            sleep_seconds = daily.get("sleepTimeSeconds")
            scores = daily.get("sleepScores", {}) or {}
            overall = scores.get("overall", {}) or {}
            sleep_score = overall.get("value")
        except Exception as e:
            log(f"[HEALTH] sleep_data failed: {e}")

        # VO2max — get_max_metrics returns a list; running entry sits under "generic".
        vo2max = None
        try:
            mm = client.get_max_metrics(date_str)
            entry = mm[0] if isinstance(mm, list) and mm else (mm or {})
            generic = (entry.get("generic") or {}) if isinstance(entry, dict) else {}
            vo2max = generic.get("vo2MaxValue")
        except Exception as e:
            log(f"[HEALTH] max_metrics failed: {e}")

        return {
            "date": date_str,
            "vo2max": vo2max,
            "resting_hr": resting_hr,
            "sleep_seconds": sleep_seconds,
            "sleep_score": sleep_score,
            "oauth1_token": new_o1,
            "oauth2_token": new_o2,
        }

    except HTTPException:
        raise
    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit")
    except (GarminConnectAuthenticationError, GarminConnectConnectionError) as e:
        raise HTTPException(status_code=401, detail=f"Garmin session expired: {e}")
    except Exception as e:
        log(f"[HEALTH] UNEXPECTED: {type(e).__name__}: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
