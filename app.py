"""FastAPI app for a simple time tracking web application."""
from __future__ import annotations

import datetime as dt
import os
import threading
from typing import Optional

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ldap3 import Connection, NTLM, Server, SIMPLE
from ldap3.utils.conv import escape_filter_chars
from starlette.middleware.sessions import SessionMiddleware

from auto_tracking import run_auto_tracking_loop
from db import get_connection

app = FastAPI(title="Easy Time Tracking")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", "change-me"))
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://localhost")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=example,dc=local")
LDAP_USER_ATTRIBUTE = os.getenv("LDAP_USER_ATTRIBUTE", "uid")
LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")
LDAP_USER_DN_TEMPLATE = os.getenv("LDAP_USER_DN_TEMPLATE")
LDAP_UPN_SUFFIX = os.getenv("LDAP_UPN_SUFFIX")
LDAP_AUTHENTICATION = os.getenv("LDAP_AUTHENTICATION", "SIMPLE").upper()


def _serialize_session(row: dict) -> dict:
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "user_name": row["user_name"],
        "start_time": row["start_time"].isoformat(),
        "end_time": row["end_time"].isoformat() if row["end_time"] else None,
        "note": row["note"],
    }


def _get_current_user_id(request: Request) -> Optional[int]:
    return request.session.get("user_id")


def _get_current_username(request: Request) -> Optional[str]:
    return request.session.get("username")


def _require_login(request: Request) -> Optional[RedirectResponse]:
    if _get_current_user_id(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    return None


def _domain_from_base_dn(base_dn: str) -> Optional[str]:
    parts = [part.strip() for part in base_dn.split(",") if part.strip()]
    if not parts:
        return None
    domain_parts = []
    for part in parts:
        if not part.lower().startswith("dc="):
            return None
        domain_parts.append(part.split("=", 1)[1])
    return ".".join(domain_parts) if domain_parts else None


def _build_ldap_bind_candidates(username: str) -> list[str]:
    candidates = []
    normalized = username.strip()
    if normalized:
        candidates.append(normalized)
    if LDAP_USER_DN_TEMPLATE and normalized and "=" not in normalized:
        candidates.append(LDAP_USER_DN_TEMPLATE.format(username=normalized))
    if normalized and "@" not in normalized and "=" not in normalized:
        upn_suffix = LDAP_UPN_SUFFIX or _domain_from_base_dn(LDAP_BASE_DN)
        if upn_suffix:
            candidates.append(f"{normalized}@{upn_suffix}")
    if normalized and "=" not in normalized:
        candidates.append(f"{LDAP_USER_ATTRIBUTE}={normalized},{LDAP_BASE_DN}")

    seen = set()
    unique_candidates = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique_candidates.append(candidate)
    return unique_candidates


def _authentication_strategy(username: str):
    if LDAP_AUTHENTICATION == "NTLM" or (
        LDAP_AUTHENTICATION == "AUTO" and "\\" in username
    ):
        return NTLM
    return SIMPLE


def _authenticate_with_ldap(username: str, password: str) -> bool:
    if not username or not password:
        return False

    server = Server(LDAP_SERVER)
    for bind_dn in _build_ldap_bind_candidates(username):
        try:
            with Connection(
                server,
                user=bind_dn,
                password=password,
                auto_bind=True,
                authentication=_authentication_strategy(bind_dn),
            ):
                return True
        except Exception:
            continue
    user_dn = _find_ldap_user_dn(server, username)
    if user_dn:
        try:
            with Connection(server, user=user_dn, password=password, auto_bind=True):
                return True
        except Exception:
            return False
    return False


def _find_ldap_user_dn(server: Server, username: str) -> Optional[str]:
    try:
        if LDAP_BIND_DN:
            with Connection(
                server,
                user=LDAP_BIND_DN,
                password=LDAP_BIND_PASSWORD or "",
                auto_bind=True,
            ) as connection:
                return _search_for_user_dn(connection, username)
        with Connection(server, auto_bind=True) as connection:
            return _search_for_user_dn(connection, username)
    except Exception:
        return None


def _search_for_user_dn(connection: Connection, username: str) -> Optional[str]:
    escaped_username = escape_filter_chars(username)
    search_filter = f"({LDAP_USER_ATTRIBUTE}={escaped_username})"
    if not connection.search(LDAP_BASE_DN, search_filter, attributes=["dn"]):
        return None
    if not connection.entries:
        return None
    return connection.entries[0].entry_dn


def _get_or_create_user(username: str) -> int:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT id FROM users WHERE ldap_username = %s",
            (username,),
        )
        row = cursor.fetchone()
        if row:
            return row["id"]

        cursor.execute(
            "INSERT INTO users (name, ldap_username) VALUES (%s, %s)",
            (username, username),
        )
        connection.commit()
        return cursor.lastrowid


@app.on_event("startup")
def start_auto_tracking() -> None:
    thread = threading.Thread(target=run_auto_tracking_loop, daemon=True)
    thread.start()


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)) -> HTMLResponse:
    if not _authenticate_with_ldap(username, password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Login fehlgeschlagen. Bitte prüfen."},
            status_code=401,
        )

    user_id = _get_or_create_user(username)
    request.session["user_id"] = user_id
    request.session["username"] = username
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    redirect = _require_login(request)
    if redirect:
        return redirect

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": _get_current_username(request),
        },
    )


@app.post("/start")
def start_session(request: Request) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

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
def stop_session(request: Request) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

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
    request: Request,
    user_id: Optional[int] = Query(None),
    date: Optional[str] = Query(None),
) -> JSONResponse:
    session_user_id = _get_current_user_id(request)
    if session_user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    effective_user_id = user_id or session_user_id

    query = (
        """
        SELECT sessions.id, sessions.user_id, users.name AS user_name,
               sessions.start_time, sessions.end_time, sessions.note
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE users.id = %s
        """
    )
    params: list = [effective_user_id]
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
def add_note(request: Request, session_id: int = Form(...), note: str = Form(...)) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE sessions SET note = %s WHERE id = %s AND user_id = %s",
            (note, session_id, user_id),
        )
        connection.commit()
    return JSONResponse({"status": "updated"})


@app.get("/status")
def presence_status(request: Request) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM sessions WHERE user_id = %s AND end_time IS NULL",
            (user_id,),
        )
        active = cursor.fetchone()

    return JSONResponse({"status": "anwesend" if active else "abwesend"})
