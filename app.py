"""FastAPI app for a simple time tracking web application."""
from __future__ import annotations

import datetime as dt
import threading
from typing import Optional

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from auto_tracking import run_auto_tracking_loop
from db import get_connection

app = FastAPI(title="Easy Time Tracking")
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")


def _serialize_session(row: dict) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "user_name": row["user_name"],
        "start_time": row["start_time"].isoformat(),
        "end_time": row["end_time"].isoformat() if row["end_time"] else None,
        "note": row["note"],
    }


@app.on_event("startup")
def start_auto_tracking() -> None:
    thread = threading.Thread(target=run_auto_tracking_loop, daemon=True)
    thread.start()


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, name FROM users ORDER BY name")
        users = cursor.fetchall()
    return templates.TemplateResponse("index.html", {"request": request, "users": users})


@app.post("/start")
def start_session(user_id: int = Form(...)) -> JSONResponse:
    now = dt.datetime.utcnow()
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM sessions WHERE user_id = %s AND end_time IS NULL",
            (user_id,),
        )
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO sessions (user_id, start_time) VALUES (%s, %s)",
                (user_id, now),
            )
            connection.commit()
    return JSONResponse({"status": "started", "time": now.isoformat()})


@app.post("/stop")
def stop_session(user_id: int = Form(...)) -> JSONResponse:
    now = dt.datetime.utcnow()
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE sessions
            SET end_time = %s
            WHERE user_id = %s AND end_time IS NULL
            """,
            (now, user_id),
        )
        connection.commit()
    return JSONResponse({"status": "stopped", "time": now.isoformat()})


@app.get("/sessions")
def list_sessions(
    user_id: Optional[int] = Query(None),
    date: Optional[str] = Query(None),
) -> JSONResponse:
    query = (
        """
        SELECT sessions.id, sessions.user_id, users.name AS user_name,
               sessions.start_time, sessions.end_time, sessions.note
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE 1=1
        """
    )
    params: list = []
    if user_id:
        query += " AND users.id = %s"
        params.append(user_id)
    if date:
        query += " AND DATE(sessions.start_time) = %s"
        params.append(date)
    query += " ORDER BY sessions.start_time DESC"

    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        sessions = cursor.fetchall()

    return JSONResponse({"sessions": [_serialize_session(row) for row in sessions]})


@app.post("/note")
def add_note(session_id: int = Form(...), note: str = Form(...)) -> JSONResponse:
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE sessions SET note = %s WHERE id = %s",
            (note, session_id),
        )
        connection.commit()
    return JSONResponse({"status": "updated"})


@app.get("/status/{user_id}")
def presence_status(user_id: int) -> JSONResponse:
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM sessions WHERE user_id = %s AND end_time IS NULL",
            (user_id,),
        )
        active = cursor.fetchone()

    return JSONResponse({"status": "anwesend" if active else "abwesend"})
