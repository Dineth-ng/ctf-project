from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict
import os
import json
from datetime import datetime
import uvicorn

# Initialize FastAPI App
app = FastAPI(
    title="Operation NightHawk CTF API",
    description="FastAPI Backend with Scoreboard & JSON persistence",
    version="1.1.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SCOREBOARD_FILE = os.path.join(DATA_DIR, "scoreboard.json")

PUBLIC_DIR = os.path.join(BASE_DIR, "public")
if not os.path.exists(PUBLIC_DIR):
    PUBLIC_DIR = os.path.join(os.path.dirname(BASE_DIR), "public")

# Ensure Data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Helper to read scoreboard from JSON file
def load_scoreboard() -> dict:
    if os.path.exists(SCOREBOARD_FILE):
        try:
            with open(SCOREBOARD_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading scoreboard JSON: {e}")
    return {"teams": []}

# Helper to write scoreboard to JSON file
def save_scoreboard(data: dict):
    try:
        with open(SCOREBOARD_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Error saving scoreboard JSON: {e}")

# Challenge Configuration (Flags & Points)
CHALLENGES = {
    1: {"title": "OSINT & Public Intelligence", "flag": "NH{public_osint_leak}", "points": 100},
    2: {"title": "Hidden Messages & Decryption", "flag": "NH{cipher_stream_decoded}", "points": 150},
    3: {"title": "Vulnerable Web Portal", "flag": "NH{sql_bypass_prom_auth}", "points": 200},
    4: {"title": "Network Traffic & PCAP Forensics", "flag": "NH{pcap_exfiltrated_stream}", "points": 250},
    5: {"title": "Protected Linux Host Escalation", "flag": "NH{privesc_suid_root_access}", "points": 300},
    6: {"title": "Prometheus Vault Recovery", "flag": "NH{prometheus_core_vault_unlocked}", "points": 500}
}

# ==========================================================================
# Pydantic Request Models
# ==========================================================================
class TeamStartRequest(BaseModel):
    teamName: Optional[str] = None
    team_name: Optional[str] = None

class FlagVerifyRequest(BaseModel):
    stage: int
    flag: str
    team_name: Optional[str] = None
    teamName: Optional[str] = None
    time_elapsed: Optional[str] = None
    timeElapsed: Optional[str] = None
    seconds_elapsed: Optional[int] = None
    secondsElapsed: Optional[int] = None

# ==========================================================================
# API Endpoints
# ==========================================================================

@app.post("/api/start")
def start_mission(payload: TeamStartRequest):
    """Register team name and record in scoreboard JSON"""
    name = (payload.teamName or payload.team_name or "").strip()
    
    if not name:
        raise HTTPException(status_code=400, detail="Team name is required.")

    scoreboard = load_scoreboard()
    team_entry = next((t for t in scoreboard["teams"] if t["team_name"].lower() == name.lower()), None)

    if not team_entry:
        new_team = {
            "team_name": name,
            "total_score": 0,
            "completed_count": 0,
            "total_time": "00:00:00",
            "total_seconds": 0,
            "is_finished": False,
            "stage_times": {},
            "registered_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }
        scoreboard["teams"].append(new_team)
        save_scoreboard(scoreboard)
        print(f"[+] FastAPI: Registered Team '{name}' to JSON Scoreboard")
    else:
        print(f"[*] FastAPI: Resumed Team '{name}'")

    return {
        "success": True,
        "message": f"Team '{name}' registered successfully!",
        "teamName": name,
        "redirectUrl": f"/challenge.html?team={name}"
    }

@app.post("/api/verify-flag")
def verify_flag(payload: FlagVerifyRequest):
    """Verify flag, record submission time for the stage, and save to scoreboard.json"""
    stage_id = payload.stage
    submitted_flag = payload.flag.strip()
    team_name = (payload.teamName or payload.team_name or "Anonymous").strip()
    time_str = (payload.timeElapsed or payload.time_elapsed or "00:00:00").strip()
    sec_count = payload.secondsElapsed if payload.secondsElapsed is not None else (payload.seconds_elapsed or 0)

    if stage_id not in CHALLENGES:
        raise HTTPException(status_code=404, detail="Invalid challenge stage.")

    challenge = CHALLENGES[stage_id]
    expected_flag = challenge["flag"]

    if submitted_flag == expected_flag:
        scoreboard = load_scoreboard()
        team_entry = next((t for t in scoreboard["teams"] if t["team_name"].lower() == team_name.lower()), None)

        if not team_entry:
            team_entry = {
                "team_name": team_name,
                "total_score": 0,
                "completed_count": 0,
                "total_time": "00:00:00",
                "total_seconds": 0,
                "is_finished": False,
                "stage_times": {},
                "registered_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat()
            }
            scoreboard["teams"].append(team_entry)

        stage_key = str(stage_id)
        
        # If this stage wasn't recorded before, add points and record submission time
        if stage_key not in team_entry["stage_times"]:
            team_entry["stage_times"][stage_key] = time_str
            team_entry["total_score"] += challenge["points"]
            team_entry["completed_count"] += 1
            team_entry["total_time"] = time_str
            team_entry["total_seconds"] = sec_count
            team_entry["last_updated"] = datetime.now().isoformat()

            if team_entry["completed_count"] >= len(CHALLENGES):
                team_entry["is_finished"] = True

            save_scoreboard(scoreboard)
            print(f"[✓] Flag Cleared by '{team_name}': Stage {stage_id} at {time_str} (Saved to JSON)")

        is_completed = team_entry["completed_count"] >= len(CHALLENGES)

        return {
            "success": True,
            "message": f"✓ Correct flag! Stage {stage_id} cleared in {time_str}.",
            "stage": stage_id,
            "next_stage": stage_id + 1 if stage_id < 6 else None,
            "points_earned": challenge["points"],
            "total_score": team_entry["total_score"],
            "time_recorded": time_str,
            "is_completed": is_completed
        }
    else:
        return {
            "success": False,
            "message": "✕ Incorrect flag. Check your analysis and try again."
        }

@app.get("/api/scoreboard")
def get_scoreboard():
    """Retrieve full scoreboard ranked by score (desc) and total time (asc)"""
    scoreboard = load_scoreboard()
    teams = scoreboard.get("teams", [])

    # Rank sorting: highest score first; for same score, fastest total seconds first
    sorted_teams = sorted(
        teams, 
        key=lambda t: (-t.get("total_score", 0), t.get("total_seconds", 999999))
    )

    return {
        "success": True,
        "total_teams": len(sorted_teams),
        "scoreboard": sorted_teams
    }

@app.get("/api/teams")
def get_teams():
    return get_scoreboard()

# ==========================================================================
# Serve Frontend Static Files
# ==========================================================================
if os.path.exists(PUBLIC_DIR):
    app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="public")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
