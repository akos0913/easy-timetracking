"""Auto tracking loop using ARP scan to detect devices on the local network."""
from __future__ import annotations

import datetime as dt
import subprocess
import time
from typing import Iterable, Set

from db import get_connection

SCAN_INTERVAL_SECONDS = 30
ABSENCE_TIMEOUT_SECONDS = 120


def _parse_arp_scan_output(output: str) -> Set[str]:
    """Extract MAC addresses from arp-scan output."""
    macs: Set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and ":" in parts[1]:
            macs.add(parts[1].lower())
    return macs


def scan_for_macs() -> Set[str]:
    """Run arp-scan and return discovered MAC addresses.

    If arp-scan is not available, return an empty set and rely on manual tracking.
    """
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return set()

    return _parse_arp_scan_output(result.stdout)


def _fetch_known_users() -> Iterable[dict]:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, mac_address FROM users WHERE mac_address IS NOT NULL")
        return cursor.fetchall()


def _start_session_if_needed(user_id: int, now: dt.datetime) -> None:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, start_time, end_time
            FROM sessions
            WHERE user_id = %s AND end_time IS NULL
            ORDER BY start_time DESC
            LIMIT 1
            """,
            (user_id,),
        )
        active = cursor.fetchone()
        if active is None:
            cursor.execute(
                "INSERT INTO sessions (user_id, start_time) VALUES (%s, %s)",
                (user_id, now),
            )
            connection.commit()


def _end_session_if_needed(user_id: int, now: dt.datetime) -> None:
    with get_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, start_time
            FROM sessions
            WHERE user_id = %s AND end_time IS NULL
            ORDER BY start_time DESC
            LIMIT 1
            """,
            (user_id,),
        )
        active = cursor.fetchone()
        if active is None:
            return

        last_seen = now - dt.timedelta(seconds=ABSENCE_TIMEOUT_SECONDS)
        if active["start_time"] <= last_seen:
            cursor.execute(
                "UPDATE sessions SET end_time = %s WHERE id = %s",
                (now, active["id"]),
            )
            connection.commit()


def run_auto_tracking_loop() -> None:
    """Continuously scan the network and manage sessions based on presence."""
    while True:
        now = dt.datetime.utcnow()
        visible_macs = scan_for_macs()
        users = _fetch_known_users()

        for user in users:
            if user["mac_address"] and user["mac_address"].lower() in visible_macs:
                _start_session_if_needed(user["id"], now)
            else:
                _end_session_if_needed(user["id"], now)

        time.sleep(SCAN_INTERVAL_SECONDS)
