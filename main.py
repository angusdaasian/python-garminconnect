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
from datetime import datetime, timedelta
from pathlib import Path
import polyline
import xml.etree.ElementTree as ET

BASE_TOKEN_PATH = os.environ.get("GARMIN_TOKEN_PATH", "/tmp/garmin_tokens")

# Garmin SSO endpoints used during ticket exchange
SSO_URL = "https://sso.garmin.com/sso"
SSO_EMBED_URL = "https://sso.garmin.com/sso/embed"
OAUTH_CONSUMER_URL = "https://thegarth.s3.amazonaws.com/oauth_consumer.json"

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    client.login(token_path)
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


# ─── /garmin-exchange-ticket ──────────────────────────────────────────────────
@app.post("/garmin-exchange-ticket")
async def garmin_exchange_ticket(request: Request):
    """
    Exchange a Garmin SSO service ticket (ST-xxxx) for OAuth1/OAuth2 tokens.
    Body: { ticket, callback? }
    Response: { success: true, email, display_name }
    """
    body = await request.json()
    ticket = body.get("ticket")
    callback = body.get("callback")  # the same `service=` URL used on the SSO page

    if not ticket:
        raise HTTPException(status_code=400, detail="ticket required")

    try:
        client = garth.Client()

        # 1) Exchange the SSO service ticket for OAuth1, then OAuth2 tokens.
        # garth's internals expose `_set_oauth1_token` via `set_oauth1_token`,
        # but the public path is to call _exchange via login_with_ticket if available.
        # Fallback: call the SSO endpoint directly to consume the ticket and get
        # the OAuth1 credentials, then upgrade to OAuth2.
        try:
            # garth >= 0.5 ships login_with_ticket
            client.login_with_ticket(ticket, callback_url=callback)
        except AttributeError:
            # Manual fallback for older garth: hit the embed endpoint with the
            # ticket so the session captures the OAuth1 cookie, then exchange.
            import requests

            sess = requests.Session()
            params = {"ticket": ticket}
            if callback:
                params["service"] = callback
            r = sess.get(f"{SSO_EMBED_URL}", params=params, allow_redirects=True, timeout=20)
            if r.status_code >= 400:
                raise HTTPException(status_code=401, detail=f"Ticket exchange failed: HTTP {r.status_code}")

            # Use garth's internal helpers to pull OAuth1 + OAuth2 from the now-authed session.
            consumer = requests.get(OAUTH_CONSUMER_URL, timeout=10).json()
            garth.sso.OAUTH_CONSUMER = consumer
            oauth1 = garth.sso.get_oauth1_token(ticket, consumer)
            client.oauth1_token = oauth1
            client.oauth2_token = garth.sso.exchange(oauth1, consumer)

        # 2) Pull the user's profile (display name + email) so we can name the token folder.
        profile = client.connectapi("/userprofile-service/socialProfile")
        display_name = (
            profile.get("displayName")
            or profile.get("fullName")
            or profile.get("userName")
            or "Garmin user"
        )
        email = profile.get("emailAddress") or profile.get("userName")

        if not email:
            # Fallback: use a stable identifier so we still have a folder to dump into.
            email = profile.get("userName") or display_name

        token_path = get_user_token_path(email)
        client.dump(token_path)

        return {
            "success": True,
            "email": email,
            "display_name": display_name,
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Ticket exchange error: {e}")
        raise HTTPException(status_code=401, detail=f"Ticket exchange failed: {e}")


# ─── /garmin-activities (token-only) ──────────────────────────────────────────
@app.post("/garmin-activities")
async def post_activities(request: Request):
    """
    Body: { email, days?, detail_limit? }
    Token-only. Returns 401 reauth_required if no/expired tokens.
    """
    body = await request.json()
    email = body.get("email")
    days = body.get("days", 30)

    if not email:
        raise HTTPException(status_code=400, detail="email required")

    try:
        try:
            client = login_with_tokens(email)
        except GarminConnectAuthenticationError:
            raise HTTPException(status_code=401, detail="reauth_required")

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
    except (GarminConnectAuthenticationError, GarminConnectConnectionError):
        raise HTTPException(status_code=401, detail="reauth_required")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── /garmin-activity-details (token-only) ────────────────────────────────────
@app.post("/garmin-activity-details")
async def post_activity_details(request: Request):
    """
    Body: { email, activity_ids }
    Token-only. Returns 401 reauth_required if no/expired tokens.
    """
    body = await request.json()
    email = body.get("email")
    activity_ids = body.get("activity_ids", "")

    if not email:
        raise HTTPException(status_code=400, detail="email required")

    try:
        try:
            client = login_with_tokens(email)
        except GarminConnectAuthenticationError:
            raise HTTPException(status_code=401, detail="reauth_required")

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
    uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
