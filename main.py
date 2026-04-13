from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from garminconnect import Garmin
import uvicorn

app = FastAPI()

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/sync")
def sync_garmin(data: LoginRequest):
    try:
        # 1. Login
        client = Garmin(data.email, data.password)
        client.login()
        
        # 2. Fetch last 30 days
        activities = client.get_activities(0, 30)
        
        # 3. Simple mapping for your database
        mapped_data = []
        for act in activities:
            mapped_data.append({
                "name": act.get("activityName"),
                "sport_type": act.get("activityType", {}).get("typeKey", "Workout"),
                "distance": int(act.get("distance", 0)), # Already in meters usually
                "moving_time": int(act.get("duration", 0)), # Seconds
                "start_date": act.get("startTimeLocal"),
                "average_heartrate": int(act.get("averageHR", 0)) if act.get("averageHR") else None,
                "source": "Garmin"
            })
        return mapped_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)