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

# Allow Lovable to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Token storage path (Railway's /tmp is writable)
TOKEN_PATH = "/tmp/garmin_tokens"

@app.get("/")
def home():
    return {"status": "online", "message": "Garmin Bridge with Token Caching"}

@app.get("/garmin-activities")
def get_activities(
    email: str = Query(...), 
    password: str = Query(...), 
    days: int = Query(30)
):
    try:
        # 1. Create token directory if it doesn't exist
        Path(TOKEN_PATH).mkdir(parents=True, exist_ok=True)

        # 2. Initialize Garmin with Token Storage
        # This will automatically try to use saved tokens first
        client = Garmin(email=email, password=password)
        client.login(TOKEN_PATH)
        
        # 3. Fetch Activities
        activities = client.get_activities(0, 50)
        
        mapped_data = []
        limit_date = datetime.now() - timedelta(days=days)

        for act in activities:
            start_time_str = act.get("startTimeLocal")
            start_time_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")

            if start_time_dt < limit_date:
                continue

            # Mapping logic
            raw_type = act.get("activityType", {}).get("typeKey", "").lower()
            sport_type = "Run"
            if "walk" in raw_type: sport_type = "Walk"
            elif "cycle" in raw_type or "ride" in raw_type: sport_type = "Ride"
            elif "hike" in raw_type: sport_type = "Hike"
            elif "trail_running" in raw_type: sport_type = "TrailRun"

            mapped_data.append({
                "name": act.get("activityName") or f"{sport_type} Workout",
                "sport_type": sport_type,
                "distance": int(act.get("distance", 0)),
                "moving_time": int(act.get("duration", 0)),
                "start_date": start_time_dt.isoformat(),
                "average_heartrate": int(act.get("averageHR", 0)) if act.get("averageHR") else None,
                "source": "Garmin"
            })
            
        return mapped_data

    except GarminConnectTooManyRequestsError:
        raise HTTPException(status_code=429, detail="Garmin Rate Limit: Please wait 1-2 hours.")
    except GarminConnectAuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid Garmin Credentials.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
