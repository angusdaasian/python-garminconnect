from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from garminconnect import (
    Garmin,
    GarminConnectAuthenticationError,
    GarminConnectConnectionError,
    GarminConnectTooManyRequestsError,
)
import uvicorn
import os
from datetime import datetime, timedelta
from pathlib import Path

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TOKEN_PATH = "/tmp/garmin_tokens"


@app.get("/garmin-activities")
def get_activities(
    email: str = Query(...),
    password: str = Query(...),
    days: int = Query(30),
    detail_limit: int = Query(5),  # ← NEW: set to 0 from edge function Phase 1
):
    try:
        Path(TOKEN_PATH).mkdir(parents=True, exist_ok=True)
        client = Garmin(email=email, password=password)
        client.login(TOKEN_PATH)

        activities = client.get_activities(0, 50)
        mapped_data = []
        limit_date = datetime.now() - timedelta(days=days)
        detail_count = 0

        for act in activities:
            start_time_str = act.get("startTimeLocal")
            start_time_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")

            if start_time_dt < limit_date:
                continue

            activity_id = act.get("activityId")
            raw_type = act.get("activityType", {}).get("typeKey", "").lower()

            sport_type = "Run"
            if "walk" in raw_type:
                sport_type = "Walk"
            elif "cycle" in raw_type or "ride" in raw_type:
                sport_type = "Ride"
            elif "hike" in raw_type:
                sport_type = "Hike"
            elif "trail_running" in raw_type:
                sport_type = "TrailRun"

            activity_item = {
                "activity_id": activity_id,
                "name": act.get("activityName") or f"{sport_type} Workout",
                "sport_type": sport_type,
                "distance": int(act.get("distance", 0)),
                "moving_time": int(act.get("duration", 0)),
                "start_date": start_time_dt.isoformat(),
                "average_heartrate": int(act.get("averageHR", 0)) if act.get("averageHR") else None,
                "average_pace": round(act.get("averagePace", 0), 2),
                "total_elevation_gain": int(act.get("elevationGain", 0)) if act.get("elevationGain") else 0,
                "source": "Garmin",
                "laps": [],
                "map_polyline": None,
            }

            # Only fetch details if detail_limit > 0 and we haven't hit the cap
            if detail_limit > 0 and detail_count < detail_limit:
                try:
                    splits_data = client.get_activity_splits(activity_id)
                    for lap in splits_data.get("lapDTOs", []):
                        activity_item["laps"].append({
                            "split_number": lap.get("lapIndex"),
                            "distance": lap.get("distance"),
                            "elapsed_time": lap.get("elapsedDuration"),
                            "avg_hr": lap.get("averageHeartRate"),
                            "avg_speed": lap.get("averageSpeed"),
                            "elevation_gain": int(lap.get("elevationGain", 0)) if lap.get("elevationGain") else 0,
                        })

                    details = client.get_activity_details(activity_id)
                    summary_dto = details.get("summaryDTO", {})
                    activity_item["map_polyline"] = summary_dto.get("polyline")

                    detail_count += 1
                except Exception as detail_err:
                    print(f"Skipping details for {activity_id}: {detail_err}")

            mapped_data.append(activity_item)

        return mapped_data

    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit: Please wait 1-2 hours.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/garmin-activity-details")
def get_activity_details(
    email: str = Query(...),
    password: str = Query(...),
    activity_ids: str = Query(...),  # comma-separated IDs
):
    """Fetch splits + map polyline for specific activity IDs (max ~5 at a time)."""
    try:
        Path(TOKEN_PATH).mkdir(parents=True, exist_ok=True)
        client = Garmin(email=email, password=password)
        client.login(TOKEN_PATH)

        ids = [aid.strip() for aid in activity_ids.split(",") if aid.strip()]
        result = {}

        for activity_id in ids:
            try:
                item = {"laps": [], "map_polyline": None}

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

                details = client.get_activity_details(activity_id)
                summary_dto = details.get("summaryDTO", {})
                item["map_polyline"] = summary_dto.get("polyline")

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
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
