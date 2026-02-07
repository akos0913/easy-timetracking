"""FastAPI app for a simple time tracking web application."""
from __future__ import annotations

import datetime as dt
import os
from contextlib import contextmanager
import secrets
import threading
from decimal import Decimal, ROUND_HALF_UP
from typing import Iterable, List, Optional, Tuple

def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _load_env_file(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    continue
                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in {"'", '"'}
                ):
                    value = value[1:-1]
                os.environ.setdefault(key, value)
    except FileNotFoundError:
        return
    except OSError:
        return


_load_env_file("/opt/timetracking/.env")
_load_env_file(".env")


from pydantic import BaseModel

from fastapi import FastAPI, Form, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ldap3 import BASE, Connection, NTLM, Server, SIMPLE
from ldap3.utils.conv import escape_filter_chars
from starlette.middleware.sessions import SessionMiddleware

from auto_tracking import run_auto_tracking_loop
from db import ensure_schema, get_connection


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
LDAP_USER_SEARCH_BASE = os.getenv("LDAP_USER_SEARCH_BASE")
LDAP_UPN_SUFFIX = os.getenv("LDAP_UPN_SUFFIX")
LDAP_AUTHENTICATION = os.getenv("LDAP_AUTHENTICATION", "SIMPLE").upper()
LDAP_ADMIN_GROUP_DN = os.getenv("LDAP_ADMIN_GROUP_DN")
LDAP_USE_SSL = _env_bool("LDAP_USE_SSL", LDAP_SERVER.lower().startswith("ldaps://"))
LDAP_STARTTLS = _env_bool("LDAP_STARTTLS", False)

AUTO_TRACKING_ENABLED = _env_bool("AUTO_TRACKING_ENABLED", False)
TERMINAL_API_KEY = os.getenv("TERMINAL_API_KEY", "")


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


def _normalize_nfc_uid(value: str) -> str:
    return (value or "").strip().replace(":", "").replace("-", "").upper()


def _terminal_key_ok(value: Optional[str]) -> bool:
    if not TERMINAL_API_KEY:
        return False
    if value is None:
        return False
    return secrets.compare_digest(value, TERMINAL_API_KEY)


class TerminalScanRequest(BaseModel):
    uid: str
    terminal_id: Optional[str] = None
    ts: Optional[int] = None


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
    search_base = LDAP_USER_SEARCH_BASE or LDAP_BASE_DN
    if normalized:
        candidates.append(normalized)
    if LDAP_USER_DN_TEMPLATE and normalized and "=" not in normalized:
        candidates.append(LDAP_USER_DN_TEMPLATE.format(username=normalized))
    if normalized and "@" not in normalized and "=" not in normalized:
        upn_suffix = LDAP_UPN_SUFFIX or _domain_from_base_dn(LDAP_BASE_DN)
        if upn_suffix:
            candidates.append(f"{normalized}@{upn_suffix}")
    if normalized and "=" not in normalized:
        candidates.append(f"{LDAP_USER_ATTRIBUTE}={normalized},{search_base}")

    seen = set()
    unique_candidates = []
    for candidate in candidates:
        if candidate and candidate not in seen:
            seen.add(candidate)
            unique_candidates.append(candidate)
    return unique_candidates


def _username_variants(username: str) -> list[str]:
    candidates = []
    normalized = username.strip()
    if normalized:
        candidates.append(normalized)
    if "\\" in normalized:
        candidates.append(normalized.split("\\", 1)[1])
    if "@" in normalized:
        candidates.append(normalized.split("@", 1)[0])
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


def _service_account_authentication(bind_dn: Optional[str]):
    if not bind_dn:
        return SIMPLE
    if LDAP_AUTHENTICATION in {"NTLM", "AUTO"} and "\\" in bind_dn:
        return NTLM
    return SIMPLE


def _ldap_server() -> Server:
    return Server(LDAP_SERVER, use_ssl=LDAP_USE_SSL)


@contextmanager
def _bound_ldap_connection(
    server: Server,
    user: Optional[str] = None,
    password: Optional[str] = None,
    authentication: Optional[object] = None,
) -> Connection:
    connection = Connection(
        server,
        user=user,
        password=password,
        authentication=authentication or SIMPLE,
        auto_bind=False,
    )
    try:
        if LDAP_STARTTLS and not LDAP_USE_SSL:
            connection.open()
            connection.start_tls()
        if not connection.bind():
            raise RuntimeError("LDAP bind failed")
        yield connection
    finally:
        try:
            connection.unbind()
        except Exception:
            pass


def _authenticate_with_ldap(username: str, password: str) -> bool:
    if not username or not password:
        return False

    server = _ldap_server()
    for bind_dn in _build_ldap_bind_candidates(username):
        try:
            with _bound_ldap_connection(
                server,
                user=bind_dn,
                password=password,
                authentication=_authentication_strategy(bind_dn),
            ):
                return True
        except Exception:
            continue
    user_dn = _find_ldap_user_dn(server, username)
    if user_dn:
        try:
            with _bound_ldap_connection(server, user=user_dn, password=password):
                return True
        except Exception:
            return False
    return False


def _is_admin_via_ldap(username: str) -> bool:
    if not LDAP_ADMIN_GROUP_DN:
        return False
    server = _ldap_server()
    username_candidates = _username_variants(username)
    if not username_candidates:
        return False
    user_dns = []
    for candidate in username_candidates:
        user_dn = _find_ldap_user_dn(server, candidate)
        if user_dn and user_dn not in user_dns:
            user_dns.append(user_dn)

    filter_parts = []
    for user_dn in user_dns:
        escaped_dn = escape_filter_chars(user_dn)
        filter_parts.append(f"(member={escaped_dn})")
        filter_parts.append(f"(uniqueMember={escaped_dn})")
    for candidate in username_candidates:
        filter_parts.append(f"(memberUid={escape_filter_chars(candidate)})")
    search_filter = "(|" + "".join(filter_parts) + ")"
    try:
        if LDAP_BIND_DN:
            with _bound_ldap_connection(
                server,
                user=LDAP_BIND_DN,
                password=LDAP_BIND_PASSWORD or "",
                authentication=_service_account_authentication(LDAP_BIND_DN),
            ) as connection:
                return connection.search(
                    LDAP_ADMIN_GROUP_DN,
                    search_filter,
                    search_scope=BASE,
                    attributes=["dn"],
                )
        with _bound_ldap_connection(server) as connection:
            return connection.search(
                LDAP_ADMIN_GROUP_DN,
                search_filter,
                search_scope=BASE,
                attributes=["dn"],
            )
    except Exception:
        return False

def _find_ldap_user_dn(server: Server, username: str) -> Optional[str]:
    try:
        if LDAP_BIND_DN:
            with _bound_ldap_connection(
                server,
                user=LDAP_BIND_DN,
                password=LDAP_BIND_PASSWORD or "",
                authentication=_service_account_authentication(LDAP_BIND_DN),
            ) as connection:
                return _search_for_user_dn(connection, username)
        with _bound_ldap_connection(server) as connection:
            return _search_for_user_dn(connection, username)
    except Exception:
        return None


def _search_for_user_dn(connection: Connection, username: str) -> Optional[str]:
    escaped_username = escape_filter_chars(username)
    search_filter = f"({LDAP_USER_ATTRIBUTE}={escaped_username})"
    search_bases = []
    if LDAP_USER_SEARCH_BASE:
        search_bases.append(LDAP_USER_SEARCH_BASE)
    if LDAP_BASE_DN and LDAP_BASE_DN not in search_bases:
        search_bases.append(LDAP_BASE_DN)
    if not search_bases:
        return None
    for search_base in search_bases:
        if not connection.search(search_base, search_filter, attributes=["dn"]):
            continue
        if connection.entries:
            return connection.entries[0].entry_dn
    return None


def _get_user_by_ldap(username: str) -> Optional[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, name, ldap_username, department, role_title, manager_id, mac_address,
                   pay_type, hourly_rate, salary_monthly, overtime_multiplier, tax_rate, social_rate,
                   pension_rate, other_rate, employer_social_rate, employer_pension_rate,
                   employer_other_rate, payment_method, is_active
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
            SELECT id, name, ldap_username, department, role_title, manager_id, mac_address,
                   pay_type, hourly_rate, salary_monthly, overtime_multiplier, tax_rate, social_rate,
                   pension_rate, other_rate, employer_social_rate, employer_pension_rate,
                   employer_other_rate, payment_method, is_active
            FROM users
            WHERE users.id = %s
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

def _parse_optional_decimal(value: Optional[str]) -> Optional[Decimal]:
    if value is None or value == "":
        return None
    try:
        return Decimal(value)
    except Exception:
        return None

def _to_decimal(value: Optional[object], default: str = "0") -> Decimal:
    if value is None:
        return Decimal(default)
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))

def _round_money(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def _round_hours(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

def _round_rate(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)

def _format_currency(value: Decimal) -> str:
    return f"{_round_money(value):.2f} CHF"

def _format_rate(value: Decimal) -> str:
    percent = (value * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"{percent:.2f}%"

def _format_hours(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP):.2f} h"

def _format_date(value: dt.date) -> str:
    return value.strftime("%Y-%m-%d")

def _pay_date_for_period(year: int, month: int) -> dt.date:
    return dt.date(year, month, 25)


def _fetch_user_by_id(user_id: int) -> Optional[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT users.id, users.name, users.ldap_username, users.department, users.role_title,
                   users.manager_id, managers.name AS manager_name, users.mac_address,
                   users.pay_type, users.hourly_rate, users.salary_monthly, users.overtime_multiplier,
                   users.tax_rate, users.social_rate, users.pension_rate, users.other_rate,
                   users.employer_social_rate, users.employer_pension_rate, users.employer_other_rate,
                   users.payment_method, users.is_active
            FROM users
            LEFT JOIN users AS managers ON users.manager_id = managers.id
            WHERE users.id = %s
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
                   users.manager_id, managers.name AS manager_name, users.mac_address,
                   users.pay_type, users.hourly_rate, users.salary_monthly, users.overtime_multiplier,
                   users.tax_rate, users.social_rate, users.pension_rate, users.other_rate,
                   users.employer_social_rate, users.employer_pension_rate, users.employer_other_rate,
                   users.payment_method, users.is_active,
                   COALESCE(SUM(TIMESTAMPDIFF(SECOND, sessions.start_time, COALESCE(sessions.end_time, UTC_TIMESTAMP()))), 0) AS month_seconds
            FROM users
            LEFT JOIN sessions
              ON sessions.user_id = users.id
             AND sessions.start_time >= %s
             AND sessions.start_time < %s
            LEFT JOIN users AS managers ON users.manager_id = managers.id
            GROUP BY users.id, users.name, users.ldap_username, users.department, users.role_title,
                     users.manager_id, managers.name, users.mac_address,
                     users.pay_type, users.hourly_rate, users.salary_monthly, users.overtime_multiplier,
                     users.tax_rate, users.social_rate, users.pension_rate, users.other_rate,
                     users.employer_social_rate, users.employer_pension_rate, users.employer_other_rate,
                     users.payment_method, users.is_active
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

def _fetch_paycheck(user_id: int, year: int, month: int) -> Optional[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT *
            FROM paychecks
            WHERE user_id = %s AND period_year = %s AND period_month = %s
            """,
            (user_id, year, month),
        )
        return cursor.fetchone()

def _fetch_paychecks_for_period(year: int, month: int) -> List[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT *
            FROM paychecks
            WHERE period_year = %s AND period_month = %s
            """,
            (year, month),
        )
        return cursor.fetchall()

def _fetch_paycheck_year_totals(user_id: int, year: int) -> dict:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT
                COALESCE(SUM(base_pay), 0) AS ytd_base_pay,
                COALESCE(SUM(overtime_pay), 0) AS ytd_overtime_pay,
                COALESCE(SUM(bonus_amount), 0) AS ytd_bonus,
                COALESCE(SUM(allowance_amount), 0) AS ytd_allowance,
                COALESCE(SUM(gross_pay), 0) AS ytd_gross,
                COALESCE(SUM(tax_amount), 0) AS ytd_tax,
                COALESCE(SUM(social_amount), 0) AS ytd_social,
                COALESCE(SUM(pension_amount), 0) AS ytd_pension,
                COALESCE(SUM(other_deduction_amount), 0) AS ytd_other,
                COALESCE(SUM(total_deductions), 0) AS ytd_deductions,
                COALESCE(SUM(net_pay), 0) AS ytd_net,
                COALESCE(SUM(total_hours), 0) AS ytd_hours
            FROM paychecks
            WHERE user_id = %s AND period_year = %s
            """,
            (user_id, year),
        )
        return cursor.fetchone() or {}


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

def _normalize_pay_type(value: Optional[str]) -> str:
    if value in {"hourly", "salary"}:
        return value
    return "hourly"

def _calculate_payroll_amounts(
    pay_type: str,
    hourly_rate: Decimal,
    salary_monthly: Decimal,
    total_hours: Decimal,
    overtime_hours: Decimal,
    overtime_multiplier: Decimal,
    bonus_amount: Decimal,
    allowance_amount: Decimal,
    tax_rate: Decimal,
    social_rate: Decimal,
    pension_rate: Decimal,
    other_rate: Decimal,
    employer_social_rate: Decimal,
    employer_pension_rate: Decimal,
    employer_other_rate: Decimal,
) -> dict:
    normalized_type = _normalize_pay_type(pay_type)
    base_pay = salary_monthly if normalized_type == "salary" else hourly_rate * total_hours
    overtime_rate = hourly_rate * overtime_multiplier if hourly_rate > 0 else Decimal("0")
    overtime_pay = overtime_hours * overtime_rate
    gross_pay = base_pay + overtime_pay + bonus_amount + allowance_amount

    tax_amount = gross_pay * tax_rate
    social_amount = gross_pay * social_rate
    pension_amount = gross_pay * pension_rate
    other_deduction_amount = gross_pay * other_rate

    total_deductions = tax_amount + social_amount + pension_amount + other_deduction_amount
    net_pay = gross_pay - total_deductions

    employer_social_amount = gross_pay * employer_social_rate
    employer_pension_amount = gross_pay * employer_pension_rate
    employer_other_amount = gross_pay * employer_other_rate

    return {
        "pay_type": normalized_type,
        "base_pay": _round_money(base_pay),
        "overtime_rate": _round_money(overtime_rate),
        "overtime_pay": _round_money(overtime_pay),
        "gross_pay": _round_money(gross_pay),
        "tax_amount": _round_money(tax_amount),
        "social_amount": _round_money(social_amount),
        "pension_amount": _round_money(pension_amount),
        "other_deduction_amount": _round_money(other_deduction_amount),
        "total_deductions": _round_money(total_deductions),
        "net_pay": _round_money(net_pay),
        "employer_social_amount": _round_money(employer_social_amount),
        "employer_pension_amount": _round_money(employer_pension_amount),
        "employer_other_amount": _round_money(employer_other_amount),
    }

def _build_payroll_context(
    user: dict,
    year: int,
    month: int,
    total_hours: Decimal,
    paycheck: Optional[dict],
    ytd: Optional[dict],
) -> dict:
    pay_type = _normalize_pay_type((paycheck or user).get("pay_type"))
    hourly_rate = _to_decimal((paycheck or user).get("hourly_rate"))
    salary_monthly = _to_decimal((paycheck or user).get("salary_monthly"))
    overtime_multiplier = _to_decimal((paycheck or user).get("overtime_multiplier"), "1.25")
    overtime_hours = _to_decimal((paycheck or {}).get("overtime_hours"))
    bonus_amount = _to_decimal((paycheck or {}).get("bonus_amount"))
    allowance_amount = _to_decimal((paycheck or {}).get("allowance_amount"))
    tax_rate = _to_decimal((paycheck or user).get("tax_rate"))
    social_rate = _to_decimal((paycheck or user).get("social_rate"))
    pension_rate = _to_decimal((paycheck or user).get("pension_rate"))
    other_rate = _to_decimal((paycheck or user).get("other_rate"))
    employer_social_rate = _to_decimal((paycheck or user).get("employer_social_rate"))
    employer_pension_rate = _to_decimal((paycheck or user).get("employer_pension_rate"))
    employer_other_rate = _to_decimal((paycheck or user).get("employer_other_rate"))
    payment_method = (paycheck or {}).get("payment_method") or user.get("payment_method") or "Bank Transfer"

    amounts = _calculate_payroll_amounts(
        pay_type=pay_type,
        hourly_rate=hourly_rate,
        salary_monthly=salary_monthly,
        total_hours=total_hours,
        overtime_hours=overtime_hours,
        overtime_multiplier=overtime_multiplier,
        bonus_amount=bonus_amount,
        allowance_amount=allowance_amount,
        tax_rate=tax_rate,
        social_rate=social_rate,
        pension_rate=pension_rate,
        other_rate=other_rate,
        employer_social_rate=employer_social_rate,
        employer_pension_rate=employer_pension_rate,
        employer_other_rate=employer_other_rate,
    )

    period_start, period_end = _month_range(year, month)
    pay_date = _pay_date_for_period(year, month)
    ytd_values = ytd or {}

    return {
        "status": (paycheck or {}).get("status") or "preview",
        "company_name": "Landeron Swiss Movements",
        "company_tax_id": "TAXIDPLACEHOLDER",
        "company_address_line1": "Junkholzweg 1",
        "company_address_line2": "4303 Kaiseraugst",
        "employee_name": user.get("name") or "",
        "employee_id": user.get("ldap_username") or "",
        "employee_department": user.get("department") or "-",
        "employee_role": user.get("role_title") or "-",
        "employee_manager": user.get("manager_name") or "-",
        "pay_period_start": _format_date(period_start.date()),
        "pay_period_end": _format_date((period_end - dt.timedelta(days=1)).date()),
        "pay_date": _format_date(pay_date),
        "payment_method": payment_method,
        "pay_type": pay_type,
        "hourly_rate": _format_currency(hourly_rate),
        "salary_monthly": _format_currency(salary_monthly),
        "total_hours": _format_hours(total_hours),
        "overtime_hours": _format_hours(overtime_hours),
        "overtime_rate": _format_currency(amounts["overtime_rate"]),
        "base_pay": _format_currency(amounts["base_pay"]),
        "overtime_pay": _format_currency(amounts["overtime_pay"]),
        "bonus_amount": _format_currency(bonus_amount),
        "allowance_amount": _format_currency(allowance_amount),
        "gross_pay": _format_currency(amounts["gross_pay"]),
        "tax_rate": _format_rate(tax_rate),
        "social_rate": _format_rate(social_rate),
        "pension_rate": _format_rate(pension_rate),
        "other_rate": _format_rate(other_rate),
        "tax_amount": _format_currency(amounts["tax_amount"]),
        "social_amount": _format_currency(amounts["social_amount"]),
        "pension_amount": _format_currency(amounts["pension_amount"]),
        "other_deduction_amount": _format_currency(amounts["other_deduction_amount"]),
        "total_deductions": _format_currency(amounts["total_deductions"]),
        "net_pay": _format_currency(amounts["net_pay"]),
        "employer_social_rate": _format_rate(employer_social_rate),
        "employer_pension_rate": _format_rate(employer_pension_rate),
        "employer_other_rate": _format_rate(employer_other_rate),
        "employer_social_amount": _format_currency(amounts["employer_social_amount"]),
        "employer_pension_amount": _format_currency(amounts["employer_pension_amount"]),
        "employer_other_amount": _format_currency(amounts["employer_other_amount"]),
        "ytd_base_pay": _format_currency(_to_decimal(ytd_values.get("ytd_base_pay"))),
        "ytd_overtime_pay": _format_currency(_to_decimal(ytd_values.get("ytd_overtime_pay"))),
        "ytd_bonus": _format_currency(_to_decimal(ytd_values.get("ytd_bonus"))),
        "ytd_allowance": _format_currency(_to_decimal(ytd_values.get("ytd_allowance"))),
        "ytd_gross": _format_currency(_to_decimal(ytd_values.get("ytd_gross"))),
        "ytd_tax": _format_currency(_to_decimal(ytd_values.get("ytd_tax"))),
        "ytd_social": _format_currency(_to_decimal(ytd_values.get("ytd_social"))),
        "ytd_pension": _format_currency(_to_decimal(ytd_values.get("ytd_pension"))),
        "ytd_other": _format_currency(_to_decimal(ytd_values.get("ytd_other"))),
        "ytd_deductions": _format_currency(_to_decimal(ytd_values.get("ytd_deductions"))),
        "ytd_net": _format_currency(_to_decimal(ytd_values.get("ytd_net"))),
        "ytd_hours": _format_hours(_to_decimal(ytd_values.get("ytd_hours"))),
    }

def create_user(connection, cursor, username: str) -> int:
    cursor.execute(
        "INSERT INTO users (name, ldap_username) VALUES (%s, %s)",
        (username, username),
    )
    connection.commit()
    return cursor.lastrowid



@app.on_event("startup")
def start_background_tasks() -> None:
    ensure_schema()
    if not AUTO_TRACKING_ENABLED:
        return
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


@app.post("/api/terminal/scan")
def terminal_scan(
    payload: TerminalScanRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> JSONResponse:
    if not _terminal_key_ok(x_api_key):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)

    nfc_uid = _normalize_nfc_uid(payload.uid)
    if not nfc_uid:
        return JSONResponse({"ok": False, "error": "invalid_uid"}, status_code=400)

    now = dt.datetime.utcnow()
    now_aware = _attach_utc(now)

    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, name, is_active FROM users WHERE nfc_uid = %s",
            (nfc_uid,),
        )
        user = cursor.fetchone()
        if not user:
            return JSONResponse(
                {"ok": False, "error": "unknown_card", "uid": nfc_uid},
                status_code=404,
            )
        if not user["is_active"]:
            return JSONResponse(
                {"ok": False, "error": "user_disabled", "uid": nfc_uid},
                status_code=403,
            )

        cursor.execute(
            """
            SELECT id
            FROM sessions
            WHERE user_id = %s AND end_time IS NULL
            ORDER BY start_time DESC
            LIMIT 1
            """,
            (user["id"],),
        )
        active = cursor.fetchone()

        if active is None:
            cursor2 = connection.cursor()
            cursor2.execute(
                "INSERT INTO sessions (user_id, start_time, source) VALUES (%s, %s, %s)",
                (user["id"], now, "nfc"),
            )
            connection.commit()
            session_id = cursor2.lastrowid
            return JSONResponse(
                {
                    "ok": True,
                    "action": "checked_in",
                    "status": "anwesend",
                    "time_utc": now_aware.isoformat(),
                    "session_id": session_id,
                    "user": {"id": user["id"], "name": user["name"]},
                    "message": f"IN: {user['name']}",
                }
            )

        cursor2 = connection.cursor()
        cursor2.execute(
            "UPDATE sessions SET end_time = %s WHERE id = %s",
            (now, active["id"]),
        )
        connection.commit()
        return JSONResponse(
            {
                "ok": True,
                "action": "checked_out",
                "status": "abwesend",
                "time_utc": now_aware.isoformat(),
                "session_id": active["id"],
                "user": {"id": user["id"], "name": user["name"]},
                "message": f"OUT: {user['name']}",
            }
        )


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
    total_hours = _to_decimal(total_seconds) / Decimal("3600")
    paycheck = _fetch_paycheck(user_id, year, month_num)
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    ytd = _fetch_paycheck_year_totals(user_id, year)
    payroll = _build_payroll_context(user, year, month_num, total_hours, paycheck, ytd)

    return templates.TemplateResponse(
        "payroll.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "year": year,
            "month": f"{month_num:02d}",
            "payroll": payroll,
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
    total_hours = _to_decimal(total_seconds) / Decimal("3600")
    paycheck = _fetch_paycheck(user_id, year, month_num)
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    ytd = _fetch_paycheck_year_totals(user_id, year)
    payroll = _build_payroll_context(user, year, month_num, total_hours, paycheck, ytd)
    lines = [
        "Payroll Statement",
        f"Company: {payroll['company_name']}",
        f"Tax ID: {payroll['company_tax_id']}",
        f"Address: {payroll['company_address_line1']}, {payroll['company_address_line2']}",
        f"Employee: {payroll['employee_name']} ({payroll['employee_id']})",
        f"Department: {payroll['employee_department']} | Role: {payroll['employee_role']}",
        f"Pay Period: {payroll['pay_period_start']} to {payroll['pay_period_end']}",
        f"Pay Date: {payroll['pay_date']} | Method: {payroll['payment_method']}",
        f"Status: {payroll['status']}",
        " ",
        "Earnings",
        f"Base Pay: {payroll['base_pay']}",
        f"Overtime: {payroll['overtime_pay']}",
        f"Bonus: {payroll['bonus_amount']}",
        f"Allowance: {payroll['allowance_amount']}",
        f"Gross Pay: {payroll['gross_pay']}",
        " ",
        "Deductions",
        f"Tax ({payroll['tax_rate']}): {payroll['tax_amount']}",
        f"Social ({payroll['social_rate']}): {payroll['social_amount']}",
        f"Pension ({payroll['pension_rate']}): {payroll['pension_amount']}",
        f"Other ({payroll['other_rate']}): {payroll['other_deduction_amount']}",
        f"Total Deductions: {payroll['total_deductions']}",
        " ",
        f"Net Pay: {payroll['net_pay']}",
        f"YTD Gross: {payroll['ytd_gross']} | YTD Net: {payroll['ytd_net']}",
        f"Generated: {now.strftime('%Y-%m-%d %H:%M')} UTC",
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

@app.get("/admin/paychecks", response_class=HTMLResponse)
def admin_paychecks(request: Request, month: Optional[str] = Query(None)) -> HTMLResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    parsed = _parse_month_param(month)
    now = dt.datetime.utcnow()
    year, month_num = parsed if parsed else (now.year, now.month)
    start, end = _month_range(year, month_num)
    users = _fetch_users_with_month_totals(start, end)
    paychecks = _fetch_paychecks_for_period(year, month_num)
    paychecks_by_user = {row["user_id"]: row for row in paychecks}

    rows = []
    for user in users:
        total_hours = _round_hours(_to_decimal(user.get("month_seconds")) / Decimal("3600"))
        paycheck = paychecks_by_user.get(user["id"])
        if paycheck and paycheck.get("total_hours") is not None:
            total_hours = _to_decimal(paycheck["total_hours"])
        payroll = _build_payroll_context(user, year, month_num, total_hours, paycheck, {})
        rows.append(
            {
                "user": user,
                "payroll": payroll,
                "status": payroll["status"],
            }
        )

    return templates.TemplateResponse(
        "admin_paychecks.html",
        {
            "request": request,
            "username": _get_current_username(request),
            "is_admin": _is_admin(request),
            "rows": rows,
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
    pay_type: Optional[str] = Form(None),
    hourly_rate: Optional[str] = Form(None),
    salary_monthly: Optional[str] = Form(None),
    overtime_multiplier: Optional[str] = Form(None),
    tax_rate: Optional[str] = Form(None),
    social_rate: Optional[str] = Form(None),
    pension_rate: Optional[str] = Form(None),
    other_rate: Optional[str] = Form(None),
    employer_social_rate: Optional[str] = Form(None),
    employer_pension_rate: Optional[str] = Form(None),
    employer_other_rate: Optional[str] = Form(None),
    payment_method: Optional[str] = Form(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    mac_value = mac_address or None
    manager_value = _parse_optional_int(manager_id)
    normalized_pay_type = _normalize_pay_type(pay_type)
    hourly_value = _parse_optional_decimal(hourly_rate)
    salary_value = _parse_optional_decimal(salary_monthly)
    overtime_value = _parse_optional_decimal(overtime_multiplier) or Decimal("1.25")
    tax_value = _parse_optional_decimal(tax_rate) or Decimal("0")
    social_value = _parse_optional_decimal(social_rate) or Decimal("0")
    pension_value = _parse_optional_decimal(pension_rate) or Decimal("0")
    other_value = _parse_optional_decimal(other_rate) or Decimal("0")
    employer_social_value = _parse_optional_decimal(employer_social_rate) or Decimal("0")
    employer_pension_value = _parse_optional_decimal(employer_pension_rate) or Decimal("0")
    employer_other_value = _parse_optional_decimal(employer_other_rate) or Decimal("0")
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                name, ldap_username, department, role_title, manager_id, mac_address,
                pay_type, hourly_rate, salary_monthly, overtime_multiplier, tax_rate, social_rate,
                pension_rate, other_rate, employer_social_rate, employer_pension_rate, employer_other_rate,
                payment_method
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                name,
                ldap_username,
                department or None,
                role_title or None,
                manager_value,
                mac_value,
                normalized_pay_type,
                hourly_value,
                salary_value,
                overtime_value,
                tax_value,
                social_value,
                pension_value,
                other_value,
                employer_social_value,
                employer_pension_value,
                employer_other_value,
                payment_method or None,
            ),
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
    pay_type: Optional[str] = Form(None),
    hourly_rate: Optional[str] = Form(None),
    salary_monthly: Optional[str] = Form(None),
    overtime_multiplier: Optional[str] = Form(None),
    tax_rate: Optional[str] = Form(None),
    social_rate: Optional[str] = Form(None),
    pension_rate: Optional[str] = Form(None),
    other_rate: Optional[str] = Form(None),
    employer_social_rate: Optional[str] = Form(None),
    employer_pension_rate: Optional[str] = Form(None),
    employer_other_rate: Optional[str] = Form(None),
    payment_method: Optional[str] = Form(None),
    is_active: Optional[str] = Form(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    mac_value = mac_address or None
    manager_value = _parse_optional_int(manager_id)
    normalized_pay_type = _normalize_pay_type(pay_type)
    hourly_value = _parse_optional_decimal(hourly_rate)
    salary_value = _parse_optional_decimal(salary_monthly)
    overtime_value = _parse_optional_decimal(overtime_multiplier) or Decimal("1.25")
    tax_value = _parse_optional_decimal(tax_rate) or Decimal("0")
    social_value = _parse_optional_decimal(social_rate) or Decimal("0")
    pension_value = _parse_optional_decimal(pension_rate) or Decimal("0")
    other_value = _parse_optional_decimal(other_rate) or Decimal("0")
    employer_social_value = _parse_optional_decimal(employer_social_rate) or Decimal("0")
    employer_pension_value = _parse_optional_decimal(employer_pension_rate) or Decimal("0")
    employer_other_value = _parse_optional_decimal(employer_other_rate) or Decimal("0")
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
                pay_type = %s,
                hourly_rate = %s,
                salary_monthly = %s,
                overtime_multiplier = %s,
                tax_rate = %s,
                social_rate = %s,
                pension_rate = %s,
                other_rate = %s,
                employer_social_rate = %s,
                employer_pension_rate = %s,
                employer_other_rate = %s,
                payment_method = %s,
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
                normalized_pay_type,
                hourly_value,
                salary_value,
                overtime_value,
                tax_value,
                social_value,
                pension_value,
                other_value,
                employer_social_value,
                employer_pension_value,
                employer_other_value,
                payment_method or None,
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
    total_hours = _round_hours(_to_decimal(total_seconds) / Decimal("3600"))
    paycheck = _fetch_paycheck(user_id, year, month_num)
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    ytd = _fetch_paycheck_year_totals(user_id, year)
    payroll = _build_payroll_context(user, year, month_num, total_hours, paycheck, ytd)
    paycheck_form = {
        "overtime_hours": f"{_to_decimal((paycheck or {}).get('overtime_hours')):.2f}",
        "bonus_amount": f"{_to_decimal((paycheck or {}).get('bonus_amount')):.2f}",
        "allowance_amount": f"{_to_decimal((paycheck or {}).get('allowance_amount')):.2f}",
        "payment_method": (paycheck or {}).get("payment_method") or user.get("payment_method") or "Bank Transfer",
        "status": (paycheck or {}).get("status") or "draft",
    }

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
            "payroll": payroll,
            "paycheck_form": paycheck_form,
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


@app.post("/admin/users/{user_id}/paycheck")
def admin_save_paycheck(
    request: Request,
    user_id: int,
    month: str = Form(...),
    overtime_hours: Optional[str] = Form(None),
    bonus_amount: Optional[str] = Form(None),
    allowance_amount: Optional[str] = Form(None),
    payment_method: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
) -> Response:
    redirect = _require_admin(request)
    if redirect:
        return redirect

    parsed = _parse_month_param(month)
    if not parsed:
        return RedirectResponse(url=f"/admin/users/{user_id}", status_code=303)
    year, month_num = parsed

    user = _fetch_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/admin/users", status_code=303)

    start, end = _month_range(year, month_num)
    sessions = _fetch_sessions_for_user(user_id, start, end)
    total_seconds = _calculate_total_seconds(sessions, dt.datetime.utcnow())
    total_hours = _round_hours(_to_decimal(total_seconds) / Decimal("3600"))

    overtime_value = _round_hours(_to_decimal(_parse_optional_decimal(overtime_hours)))
    bonus_value = _round_money(_to_decimal(_parse_optional_decimal(bonus_amount)))
    allowance_value = _round_money(_to_decimal(_parse_optional_decimal(allowance_amount)))
    normalized_status = status if status in {"draft", "final"} else "draft"
    method_value = payment_method or user.get("payment_method") or "Bank Transfer"

    pay_type = _normalize_pay_type(user.get("pay_type"))
    hourly_rate = _round_money(_to_decimal(user.get("hourly_rate")))
    salary_monthly = _round_money(_to_decimal(user.get("salary_monthly")))
    overtime_multiplier = _to_decimal(user.get("overtime_multiplier"), "1.25")
    tax_rate = _round_rate(_to_decimal(user.get("tax_rate")))
    social_rate = _round_rate(_to_decimal(user.get("social_rate")))
    pension_rate = _round_rate(_to_decimal(user.get("pension_rate")))
    other_rate = _round_rate(_to_decimal(user.get("other_rate")))
    employer_social_rate = _round_rate(_to_decimal(user.get("employer_social_rate")))
    employer_pension_rate = _round_rate(_to_decimal(user.get("employer_pension_rate")))
    employer_other_rate = _round_rate(_to_decimal(user.get("employer_other_rate")))

    amounts = _calculate_payroll_amounts(
        pay_type=pay_type,
        hourly_rate=hourly_rate,
        salary_monthly=salary_monthly,
        total_hours=total_hours,
        overtime_hours=overtime_value,
        overtime_multiplier=overtime_multiplier,
        bonus_amount=bonus_value,
        allowance_amount=allowance_value,
        tax_rate=tax_rate,
        social_rate=social_rate,
        pension_rate=pension_rate,
        other_rate=other_rate,
        employer_social_rate=employer_social_rate,
        employer_pension_rate=employer_pension_rate,
        employer_other_rate=employer_other_rate,
    )

    pay_date = _pay_date_for_period(year, month_num)
    with get_connection() as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO paychecks (
                user_id, period_year, period_month, pay_date, pay_type, hourly_rate, salary_monthly,
                total_hours, overtime_hours, overtime_multiplier, base_pay, overtime_pay,
                bonus_amount, allowance_amount, gross_pay, tax_rate, social_rate, pension_rate, other_rate,
                tax_amount, social_amount, pension_amount, other_deduction_amount, total_deductions, net_pay,
                employer_social_rate, employer_pension_rate, employer_other_rate,
                employer_social_amount, employer_pension_amount, employer_other_amount,
                status, payment_method
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                pay_date = VALUES(pay_date),
                pay_type = VALUES(pay_type),
                hourly_rate = VALUES(hourly_rate),
                salary_monthly = VALUES(salary_monthly),
                total_hours = VALUES(total_hours),
                overtime_hours = VALUES(overtime_hours),
                overtime_multiplier = VALUES(overtime_multiplier),
                base_pay = VALUES(base_pay),
                overtime_pay = VALUES(overtime_pay),
                bonus_amount = VALUES(bonus_amount),
                allowance_amount = VALUES(allowance_amount),
                gross_pay = VALUES(gross_pay),
                tax_rate = VALUES(tax_rate),
                social_rate = VALUES(social_rate),
                pension_rate = VALUES(pension_rate),
                other_rate = VALUES(other_rate),
                tax_amount = VALUES(tax_amount),
                social_amount = VALUES(social_amount),
                pension_amount = VALUES(pension_amount),
                other_deduction_amount = VALUES(other_deduction_amount),
                total_deductions = VALUES(total_deductions),
                net_pay = VALUES(net_pay),
                employer_social_rate = VALUES(employer_social_rate),
                employer_pension_rate = VALUES(employer_pension_rate),
                employer_other_rate = VALUES(employer_other_rate),
                employer_social_amount = VALUES(employer_social_amount),
                employer_pension_amount = VALUES(employer_pension_amount),
                employer_other_amount = VALUES(employer_other_amount),
                status = VALUES(status),
                payment_method = VALUES(payment_method)
            """,
            (
                user_id,
                year,
                month_num,
                pay_date,
                pay_type,
                hourly_rate,
                salary_monthly,
                total_hours,
                overtime_value,
                overtime_multiplier,
                amounts["base_pay"],
                amounts["overtime_pay"],
                bonus_value,
                allowance_value,
                amounts["gross_pay"],
                tax_rate,
                social_rate,
                pension_rate,
                other_rate,
                amounts["tax_amount"],
                amounts["social_amount"],
                amounts["pension_amount"],
                amounts["other_deduction_amount"],
                amounts["total_deductions"],
                amounts["net_pay"],
                employer_social_rate,
                employer_pension_rate,
                employer_other_rate,
                amounts["employer_social_amount"],
                amounts["employer_pension_amount"],
                amounts["employer_other_amount"],
                normalized_status,
                method_value,
            ),
        )
        connection.commit()
    return RedirectResponse(url=f"/admin/users/{user_id}?month={year}-{month_num:02d}", status_code=303)


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
    total_hours = _to_decimal(total_seconds) / Decimal("3600")
    paycheck = _fetch_paycheck(user_id, year, month_num)
    if paycheck and paycheck.get("total_hours") is not None:
        total_hours = _to_decimal(paycheck["total_hours"])
    ytd = _fetch_paycheck_year_totals(user_id, year)
    payroll = _build_payroll_context(user, year, month_num, total_hours, paycheck, ytd)
    lines = [
        "Payroll Statement",
        f"Company: {payroll['company_name']}",
        f"Tax ID: {payroll['company_tax_id']}",
        f"Address: {payroll['company_address_line1']}, {payroll['company_address_line2']}",
        f"Employee: {payroll['employee_name']} ({payroll['employee_id']})",
        f"Department: {payroll['employee_department']} | Role: {payroll['employee_role']}",
        f"Pay Period: {payroll['pay_period_start']} to {payroll['pay_period_end']}",
        f"Pay Date: {payroll['pay_date']} | Method: {payroll['payment_method']}",
        f"Status: {payroll['status']}",
        " ",
        "Earnings",
        f"Base Pay: {payroll['base_pay']}",
        f"Overtime: {payroll['overtime_pay']}",
        f"Bonus: {payroll['bonus_amount']}",
        f"Allowance: {payroll['allowance_amount']}",
        f"Gross Pay: {payroll['gross_pay']}",
        " ",
        "Deductions",
        f"Tax ({payroll['tax_rate']}): {payroll['tax_amount']}",
        f"Social ({payroll['social_rate']}): {payroll['social_amount']}",
        f"Pension ({payroll['pension_rate']}): {payroll['pension_amount']}",
        f"Other ({payroll['other_rate']}): {payroll['other_deduction_amount']}",
        f"Total Deductions: {payroll['total_deductions']}",
        " ",
        f"Net Pay: {payroll['net_pay']}",
        f"YTD Gross: {payroll['ytd_gross']} | YTD Net: {payroll['ytd_net']}",
        f"Generated: {now.strftime('%Y-%m-%d %H:%M')} UTC",
    ]
    pdf_bytes = _build_pdf(lines)
    filename = f"lohnabrechnung_{user['ldap_username']}_{year}-{month_num:02d}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )
