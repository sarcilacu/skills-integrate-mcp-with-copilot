"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

session_secret = os.environ.get("SESSION_SECRET_KEY")
if not session_secret:
    raise RuntimeError("Set SESSION_SECRET_KEY before starting the application")

teacher_cookie_name = "teacher_session"
teacher_session_seconds = 8 * 60 * 60
secure_cookies = os.environ.get("COOKIE_SECURE", "false").lower() == "true"

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

teachers_file = current_dir / "teachers.json"
password_iterations = 600_000


class TeacherLogin(BaseModel):
    username: str
    password: str


def require_teacher(request: Request) -> str:
    username = get_authenticated_teacher(request)
    if not username:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


def create_teacher_session(username: str) -> str:
    payload = json.dumps(
        {"username": username, "expires_at": int(time.time()) + teacher_session_seconds},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = hmac.new(
        session_secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def get_authenticated_teacher(request: Request) -> str | None:
    token = request.cookies.get(teacher_cookie_name, "")
    try:
        encoded_payload, signature = token.rsplit(".", 1)
        expected_signature = hmac.new(
            session_secret.encode("utf-8"), encoded_payload.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None

        padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload + padding))
        if payload.get("expires_at", 0) <= time.time():
            return None
        return payload.get("username")
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def load_teacher_credentials():
    try:
        with teachers_file.open(encoding="utf-8") as credentials_file:
            return json.load(credentials_file).get("teachers", [])
    except FileNotFoundError:
        return []


def verify_teacher(username: str, password: str) -> bool:
    for teacher in load_teacher_credentials():
        if teacher.get("username") == username:
            password_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                teacher["salt"].encode("utf-8"),
                password_iterations,
            ).hex()
            return hmac.compare_digest(password_hash, teacher.get("password_hash", ""))
    return False

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.get("/auth/me")
def get_teacher_session(request: Request):
    username = get_authenticated_teacher(request)
    return {"authenticated": bool(username), "username": username}


@app.post("/auth/login")
def teacher_login(credentials: TeacherLogin, request: Request):
    if not verify_teacher(credentials.username, credentials.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response = JSONResponse({"authenticated": True, "username": credentials.username})
    response.set_cookie(
        key=teacher_cookie_name,
        value=create_teacher_session(credentials.username),
        max_age=teacher_session_seconds,
        httponly=True,
        secure=secure_cookies,
        samesite="lax",
    )
    return response


@app.post("/auth/logout")
def teacher_logout(request: Request):
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(key=teacher_cookie_name, httponly=True, secure=secure_cookies, samesite="lax")
    return response


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, request: Request):
    """Unregister a student from an activity"""
    require_teacher(request)

    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
