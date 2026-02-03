"""Database helpers for MySQL connections."""
from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Iterator, Sequence, Tuple

import mysql.connector
from mysql.connector import pooling

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "timetracker"),
    "password": os.getenv("DB_PASSWORD", "timetracker"),
    "database": os.getenv("DB_NAME", "timetracking"),
    "port": int(os.getenv("DB_PORT", "3306")),
}

_pool = pooling.MySQLConnectionPool(pool_name="timetracking_pool", pool_size=5, **DB_CONFIG)


@contextmanager
def get_connection() -> Iterator[mysql.connector.MySQLConnection]:
    """Yield a MySQL connection from the pool."""
    connection = _pool.get_connection()
    try:
        yield connection
    finally:
        connection.close()


def _column_exists(cursor: mysql.connector.cursor.MySQLCursor, table: str, column: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND COLUMN_NAME = %s
        """,
        (table, column),
    )
    return bool(cursor.fetchone()[0])


def _index_exists(cursor: mysql.connector.cursor.MySQLCursor, table: str, index: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
          AND INDEX_NAME = %s
        """,
        (table, index),
    )
    return bool(cursor.fetchone()[0])


def _ensure_columns(
    cursor: mysql.connector.cursor.MySQLCursor,
    table: str,
    columns: Sequence[Tuple[str, str]],
) -> bool:
    changed = False
    for column_name, column_def in columns:
        if _column_exists(cursor, table, column_name):
            continue
        cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column_name}` {column_def}")
        changed = True
    return changed


def ensure_schema() -> None:
    """Ensure required columns and indexes exist for the current app version."""
    with get_connection() as connection:
        cursor = connection.cursor()
        changed = False
        changed |= _ensure_columns(
            cursor,
            "users",
            (
                ("department", "VARCHAR(100)"),
                ("role_title", "VARCHAR(100)"),
                ("manager_id", "INT"),
                ("mac_address", "VARCHAR(32)"),
                ("is_active", "TINYINT(1) NOT NULL DEFAULT 1"),
            ),
        )
        changed |= _ensure_columns(
            cursor,
            "sessions",
            (("source", "VARCHAR(16) NOT NULL DEFAULT 'manual'"),),
        )
        if not _index_exists(cursor, "sessions", "idx_sessions_user_start"):
            cursor.execute(
                "ALTER TABLE sessions ADD INDEX idx_sessions_user_start (user_id, start_time)"
            )
            changed = True
        if changed:
            connection.commit()
