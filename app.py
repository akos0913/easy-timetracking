"""FastAPI app for a simple time tracking web application."""
from __future__ import annotations

import datetime as dt
import os
import threading
from typing import Iterable, List, Optional, Tuple

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ldap3 import Connection, NTLM, Server, SIMPLE
from ldap3.utils.conv import escape_filter_chars
from starlette.middleware.sessions import SessionMiddleware

from auto_tracking import run_auto_tracking_loop
from db import get_connection

def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


UTC = dt.timezone.utc


def _attach_utc(value: dt.datetime) -> dt.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


app = FastAPI(title="Easy Time Tracking")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-me"),
    max_age=int(os.getenv("SESSION_MAX_AGE", "43200")),
    same_site=os.getenv("SESSION_SAMESITE", "lax"),
    https_only=_env_bool("SESSION_HTTPS_ONLY", False),
)
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

LDAP_SERVER = os.getenv("LDAP_SERVER", "ldap://ldap.landeron-swiss-movements.com")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=ldap,dc=landeron-swiss-movements,dc=com")
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
        "start_time": _attach_utc(row["start_time"]).isoformat(),
        "end_time": _attach_utc(row["end_time"]).isoformat() if row["end_time"] else None,
        "note": row["note"],
        "source": row.get("source"),
    }


def _get_current_user_id(request: Request) -> Optional[int]:
    return request.session.get("user_id")


def _get_current_username(request: Request) -> Optional[str]:
    return request.session.get("username")

def _is_admin(request: Request) -> bool:
    return bool(request.session.get("is_admin"))


def _require_login(request: Request) -> Optional[RedirectResponse]:
    if _get_current_user_id(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    return None

def _require_admin(request: Request) -> Optional[RedirectResponse]:
    if _get_current_user_id(request) is None:
        return RedirectResponse(url="/login", status_code=303)
    if not _is_admin(request):
        return RedirectResponse(url="/", status_code=303)
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


def _get_user_by_ldap(username: str) -> Optional[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, name, ldap_username, department, role_title, manager_id, mac_address, is_active
            FROM users
            WHERE ldap_username = %s
            """,
            (username,),
        )
        return cursor.fetchone()


def _create_user(username: str, name: Optional[str] = None) -> dict:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "INSERT INTO users (name, ldap_username) VALUES (%s, %s)",
            (name or username, username),
        )
        connection.commit()
        cursor.execute(
            """
            SELECT id, name, ldap_username, department, role_title, manager_id, mac_address, is_active
            FROM users
            WHERE id = %s
            """,
            (cursor.lastrowid,),
        )
        return cursor.fetchone()


def _get_or_create_user(username: str) -> dict:
    row = _get_user_by_ldap(username)
    if row:
        return row
    return _create_user(username)


def _parse_month_param(month_value: Optional[str]) -> Optional[Tuple[int, int]]:
    if not month_value:
        return None
    try:
        year_str, month_str = month_value.split("-", 1)
        year = int(year_str)
        month = int(month_str)
        if 1 <= month <= 12:
            return year, month
    except ValueError:
        return None
    return None


def _month_range(year: int, month: int) -> Tuple[dt.datetime, dt.datetime]:
    start = dt.datetime(year, month, 1)
    if month == 12:
        end = dt.datetime(year + 1, 1, 1)
    else:
        end = dt.datetime(year, month + 1, 1)
    return start, end


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_pdf(lines: List[str]) -> bytes:
    content_lines = []
    y = 770
    for line in lines:
        content_lines.append(f"1 0 0 1 72 {y} Tm ({_pdf_escape(line)}) Tj")
        y -= 16
    content = "BT /F1 12 Tf " + " ".join(content_lines) + " ET"
    content_bytes = content.encode("latin-1")

    objects: List[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Length " + str(len(content_bytes)).encode("ascii") + b" >>\nstream\n" + content_bytes + b"\nendstream")

    xref = [b"0000000000 65535 f "]
    offsets = []
    result = b"%PDF-1.4\n"
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(result))
        result += f"{i} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"

    xref_start = len(result)
    result += b"xref\n0 " + str(len(objects) + 1).encode("ascii") + b"\n"
    result += xref[0] + b"\n"
    for offset in offsets:
        result += f"{offset:010d} 00000 n \n".encode("ascii")
    result += b"trailer\n<< /Size " + str(len(objects) + 1).encode("ascii") + b" /Root 1 0 R >>\nstartxref\n"
    result += str(xref_start).encode("ascii") + b"\n%%EOF\n"
    return result


def _parse_datetime_local(value: str, tz_offset: int) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        local_dt = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError:
        return None
    return local_dt + dt.timedelta(minutes=tz_offset)

def _parse_optional_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _fetch_user_by_id(user_id: int) -> Optional[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT users.id, users.name, users.ldap_username, users.department, users.role_title,
                   users.manager_id, managers.name AS manager_name, users.mac_address, users.is_active
            FROM users
            LEFT JOIN users AS managers ON users.manager_id = managers.id
            WHERE id = %s
            """,
            (user_id,),
        )
        return cursor.fetchone()

def _fetch_manager_options() -> List[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, name
            FROM users
            WHERE is_active = 1
            ORDER BY name
            """
        )
        return cursor.fetchall()


def _fetch_users_with_month_totals(start: dt.datetime, end: dt.datetime) -> List[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT users.id, users.name, users.ldap_username, users.department, users.role_title,
                   users.manager_id, managers.name AS manager_name, users.mac_address, users.is_active,
                   COALESCE(SUM(TIMESTAMPDIFF(SECOND, sessions.start_time, COALESCE(sessions.end_time, UTC_TIMESTAMP()))), 0) AS month_seconds
            FROM users
            LEFT JOIN sessions
              ON sessions.user_id = users.id
             AND sessions.start_time >= %s
             AND sessions.start_time < %s
            LEFT JOIN users AS managers ON users.manager_id = managers.id
            GROUP BY users.id, users.name, users.ldap_username, users.department, users.role_title,
                     users.manager_id, managers.name, users.mac_address, users.is_active
            ORDER BY users.name
            """,
            (start, end),
        )
        return cursor.fetchall()


def _fetch_sessions_for_user(user_id: int, start: dt.datetime, end: dt.datetime) -> List[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT sessions.id, sessions.user_id, users.name AS user_name,
                   sessions.start_time, sessions.end_time, sessions.note, sessions.source
            FROM sessions
            JOIN users ON sessions.user_id = users.id
            WHERE users.id = %s
              AND sessions.start_time >= %s
              AND sessions.start_time < %s
            ORDER BY sessions.start_time DESC
            """,
            (user_id, start, end),
        )
        return cursor.fetchall()


def _calculate_total_seconds(sessions: Iterable[dict], now: dt.datetime) -> int:
    total = 0
    for row in sessions:
        start = row["start_time"]
        end = row["end_time"] or now
        if end < start:
            continue
        total += int((end - start).total_seconds())
    return total


def _format_duration(seconds: int) -> str:
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes:02d}m"

def create_user(connection, cursor, username: str) -> int:
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

    is_admin = _is_admin_via_ldap(username)

    user = _get_or_create_user(username)
    if not user["is_active"]:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Benutzer ist deaktiviert."},
            status_code=403,
        )

    request.session["user_id"] = user["id"]
    request.session["username"] = username
    request.session["is_admin"] = is_admin
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
    now = dt.datetime.utcnow()

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "current_year": now.year,
            "current_month": f"{now.month:02d}",
        },
    )


@app.post("/start")
def start_session(request: Request) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    now = dt.datetime.utcnow()
    now_aware = _attach_utc(now)
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "SELECT id FROM sessions WHERE user_id = %s AND end_time IS NULL",
            (user_id,),
        )
        if cursor.fetchone() is None:
            cursor.execute(
                "INSERT INTO sessions (user_id, start_time, source) VALUES (%s, %s, %s)",
                (user_id, now, "manual"),
            )
            connection.commit()
    return JSONResponse({"status": "started", "time": now_aware.isoformat()})


@app.post("/stop")
def stop_session(request: Request) -> JSONResponse:
    user_id = _get_current_user_id(request)
    if user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    now = dt.datetime.utcnow()
    now_aware = _attach_utc(now)
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
    return JSONResponse({"status": "stopped", "time": now_aware.isoformat()})


@app.get("/sessions")
def list_sessions(
    request: Request,
    date: Optional[str] = Query(None),
    tz_offset: Optional[int] = Query(None),
) -> JSONResponse:
    session_user_id = _get_current_user_id(request)
    if session_user_id is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    query = (
        """
        SELECT sessions.id, sessions.user_id, users.name AS user_name,
               sessions.start_time, sessions.end_time, sessions.note, sessions.source
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE users.id = %s
        """
    )
    params: list = [session_user_id]
    if date:
        if tz_offset is not None:
            try:
                start_local = dt.datetime.strptime(date, "%Y-%m-%d")
            except ValueError:
                return JSONResponse({"error": "invalid date"}, status_code=400)
            end_local = start_local + dt.timedelta(days=1)
            offset = dt.timedelta(minutes=tz_offset)
            start_utc = start_local + offset
            end_utc = end_local + offset
            query += " AND sessions.start_time >= %s AND sessions.start_time < %s"
            params.extend([start_utc, end_utc])
        else:
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


@app.get("/payroll", response_class=HTMLResponse)
def payroll_page(request: Request, month: Optional[str] = Query(None)) -> HTMLResponse:
    redirect = _require_login(request)
    if redirect:
        return redirect

    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    user_id = _get_current_user_id(request)
    if user_id is None:
        return RedirectResponse(url="/login", status_code=303)

    user = _fetch_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    start, end = _month_range(year, month_num)
    sessions = _fetch_sessions_for_user(user_id, start, end)
    total_seconds = _calculate_total_seconds(sessions, now)

    return templates.TemplateResponse(
        "payroll.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "year": year,
            "month": f"{month_num:02d}",
            "total_duration": _format_duration(total_seconds),
        },
    )


@app.get("/payroll/pdf")
def payroll_pdf(
    request: Request,
    month: Optional[str] = Query(None),
) -> Response:
    redirect = _require_login(request)
    if redirect:
        return redirect

    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    user_id = _get_current_user_id(request)
    if user_id is None:
        return RedirectResponse(url="/login", status_code=303)

    user = _fetch_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    start, end = _month_range(year, month_num)
    sessions = _fetch_sessions_for_user(user_id, start, end)
    total_seconds = _calculate_total_seconds(sessions, now)
    lines = [
        "Lohnabrechnung",
        f"Mitarbeiter: {user['name']}",
        f"Monat: {year}-{month_num:02d}",
        f"Gesamtzeit: {_format_duration(total_seconds)}",
        f"Erstellt: {now.strftime('%Y-%m-%d %H:%M')} UTC",
    ]
    pdf_bytes = _build_pdf(lines)
    filename = f"lohnabrechnung_{user['ldap_username']}_{year}-{month_num:02d}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )


@app.get("/admin")
def admin_root(request: Request) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect
    return RedirectResponse(url="/admin/users", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, month: Optional[str] = Query(None)) -> HTMLResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    start, end = _month_range(year, month_num)
    users = _fetch_users_with_month_totals(start, end)
    managers = _fetch_manager_options()
    total_users = len(users)
    active_users = sum(1 for user in users if user["is_active"])
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "users": users,
            "managers": managers,
            "total_users": total_users,
            "active_users": active_users,
            "year": year,
            "month": f"{month_num:02d}",
        },
    )


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    name: str = Form(...),
    ldap_username: str = Form(...),
    department: Optional[str] = Form(None),
    role_title: Optional[str] = Form(None),
    manager_id: Optional[str] = Form(None),
    mac_address: Optional[str] = Form(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    mac_value = mac_address or None
    manager_value = _parse_optional_int(manager_id)
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (name, ldap_username, department, role_title, manager_id, mac_address)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (name, ldap_username, department or None, role_title or None, manager_value, mac_value),
        )
        connection.commit()
    return RedirectResponse(url="/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/toggle")
def admin_toggle_user(request: Request, user_id: int) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET is_active = NOT is_active WHERE id = %s", (user_id,))
        connection.commit()
    return RedirectResponse(url="/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/update")
def admin_update_user(
    request: Request,
    user_id: int,
    name: str = Form(...),
    ldap_username: str = Form(...),
    department: Optional[str] = Form(None),
    role_title: Optional[str] = Form(None),
    manager_id: Optional[str] = Form(None),
    mac_address: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    mac_value = mac_address or None
    manager_value = _parse_optional_int(manager_id)
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE users
            SET name = %s,
                ldap_username = %s,
                department = %s,
                role_title = %s,
                manager_id = %s,
                mac_address = %s,
                is_active = %s
            WHERE id = %s
            """,
            (
                name,
                ldap_username,
                department or None,
                role_title or None,
                manager_value,
                mac_value,
                1 if is_active else 0,
                user_id,
            ),
        )
        connection.commit()
    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=303)


@app.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(request: Request, user_id: int, month: Optional[str] = Query(None)) -> HTMLResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    user = _fetch_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/admin/users", status_code=303)

    managers = _fetch_manager_options()
    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    start, end = _month_range(year, month_num)
    sessions = _fetch_sessions_for_user(user_id, start, end)
    total_seconds = _calculate_total_seconds(sessions, now)

    return templates.TemplateResponse(
        "admin_user.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "user": user,
            "managers": managers,
            "sessions": [_serialize_session(row) for row in sessions],
            "year": year,
            "month": f"{month_num:02d}",
            "total_duration": _format_duration(total_seconds),
        },
    )


@app.post("/admin/sessions/{session_id}/update")
def admin_update_session(
    request: Request,
    session_id: int,
    start_time: str = Form(...),
    end_time: Optional[str] = Form(None),
    note: Optional[str] = Form(None),
    tz_offset: int = Form(0),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    start_dt = _parse_datetime_local(start_time, tz_offset)
    if start_dt is None:
        return RedirectResponse(url=request.headers.get("referer", "/admin/users"), status_code=303)

    end_dt = _parse_datetime_local(end_time, tz_offset) if end_time else None

    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            "UPDATE sessions SET start_time = %s, end_time = %s, note = %s WHERE id = %s",
            (start_dt, end_dt, note, session_id),
        )
        connection.commit()
    return RedirectResponse(url=request.headers.get("referer", "/admin/users"), status_code=303)


@app.get("/admin/users/{user_id}/payroll/pdf")
def admin_payroll_pdf(
    request: Request,
    user_id: int,
    month: Optional[str] = Query(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    user = _fetch_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/admin/users", status_code=303)

    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    start, end = _month_range(year, month_num)
    sessions = _fetch_sessions_for_user(user_id, start, end)
    total_seconds = _calculate_total_seconds(sessions, now)
    lines = [
        "Lohnabrechnung",
        f"Mitarbeiter: {user['name']}",
        f"Monat: {year}-{month_num:02d}",
        f"Gesamtzeit: {_format_duration(total_seconds)}",
        f"Erstellt: {now.strftime('%Y-%m-%d %H:%M')} UTC",
    ]
    pdf_bytes = _build_pdf(lines)
    filename = f"lohnabrechnung_{user['ldap_username']}_{year}-{month_num:02d}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )
