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

# Enable CORS for Lovable/Frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Railway persistent storage for session tokens
TOKEN_PATH = "/tmp/garmin_tokens"

@app.get("/garmin-activities")
def get_activities(
    email: str = Query(...), 
    password: str = Query(...), 
    days: int = Query(30)
):
    try:
        Path(TOKEN_PATH).mkdir(parents=True, exist_ok=True)

        client = Garmin(email=email, password=password)
        client.login(TOKEN_PATH)
        
        # Fetch activity list
        activities = client.get_activities(0, 50)
        
        mapped_data = []
        limit_date = datetime.now() - timedelta(days=days)

        # Limit detail fetching to prevent Garmin rate limits (last 5 runs)
        detail_limit = 5 
        detail_count = 0

        for act in activities:
            start_time_str = act.get("startTimeLocal")
            start_time_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")

            if start_time_dt < limit_date:
                continue

            activity_id = act.get("activityId")
            raw_type = act.get("activityType", {}).get("typeKey", "").lower()
            
            # Basic sport type categorization
            sport_type = "Run"
            if "walk" in raw_type: sport_type = "Walk"
            elif "cycle" in raw_type or "ride" in raw_type: sport_type = "Ride"
            elif "hike" in raw_type: sport_type = "Hike"
            elif "trail_running" in raw_type: sport_type = "TrailRun"

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
                "map_polyline": None 
            }

            # Fetch detailed splits and map data for recent activities
            if detail_count < detail_limit:
                try:
                    # 1. Fetch Laps/Splits
                    splits_data = client.get_activity_splits(activity_id)
                    laps = splits_data.get("lapDTOs", [])
                    
                    for lap in laps:
                        activity_item["laps"].append({
                            "split_number": lap.get("lapIndex"),
                            "distance": lap.get("distance"),
                            "elapsed_time": lap.get("elapsedDuration"),
                            "avg_hr": lap.get("averageHeartRate"),
                            "avg_speed": lap.get("averageSpeed"),
                            "elevation_gain": int(lap.get("elevationGain", 0)) if lap.get("elevationGain") else 0
                        })

                    # 2. Fetch Map Polyline
                    # get_activity_details returns the encoded summary polyline
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
