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

def _table_exists(cursor: mysql.connector.cursor.MySQLCursor, table: str) -> bool:
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = %s
        """,
        (table,),
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
                ("nfc_uid", "VARCHAR(32)"),
                ("pay_type", "VARCHAR(16) NOT NULL DEFAULT 'hourly'"),
                ("hourly_rate", "DECIMAL(10,2)"),
                ("salary_monthly", "DECIMAL(10,2)"),
                ("overtime_multiplier", "DECIMAL(4,2) NOT NULL DEFAULT 1.25"),
                ("tax_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("social_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("pension_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("other_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("employer_social_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("employer_pension_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("employer_other_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                ("payment_method", "VARCHAR(40)"),
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
        if not _index_exists(cursor, "users", "uniq_users_nfc_uid"):
            cursor.execute(
                "ALTER TABLE users ADD UNIQUE INDEX uniq_users_nfc_uid (nfc_uid)"
            )
            changed = True
        if not _table_exists(cursor, "paychecks"):
            cursor.execute(
                """
                CREATE TABLE paychecks (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    period_year INT NOT NULL,
                    period_month INT NOT NULL,
                    pay_date DATE NOT NULL,
                    pay_type VARCHAR(16) NOT NULL,
                    hourly_rate DECIMAL(10,2),
                    salary_monthly DECIMAL(10,2),
                    total_hours DECIMAL(10,2) NOT NULL DEFAULT 0,
                    overtime_hours DECIMAL(10,2) NOT NULL DEFAULT 0,
                    overtime_multiplier DECIMAL(4,2) NOT NULL DEFAULT 1.25,
                    base_pay DECIMAL(12,2) NOT NULL DEFAULT 0,
                    overtime_pay DECIMAL(12,2) NOT NULL DEFAULT 0,
                    bonus_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    allowance_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    gross_pay DECIMAL(12,2) NOT NULL DEFAULT 0,
                    tax_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    social_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    pension_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    other_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    tax_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    social_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    pension_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    other_deduction_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    total_deductions DECIMAL(12,2) NOT NULL DEFAULT 0,
                    net_pay DECIMAL(12,2) NOT NULL DEFAULT 0,
                    employer_social_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    employer_pension_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    employer_other_rate DECIMAL(6,4) NOT NULL DEFAULT 0,
                    employer_social_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    employer_pension_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    employer_other_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
                    status VARCHAR(16) NOT NULL DEFAULT 'draft',
                    payment_method VARCHAR(40),
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY uniq_paycheck_period (user_id, period_year, period_month),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
                """
            )
            changed = True
        else:
            changed |= _ensure_columns(
                cursor,
                "paychecks",
                (
                    ("period_year", "INT NOT NULL"),
                    ("period_month", "INT NOT NULL"),
                    ("pay_date", "DATE NOT NULL"),
                    ("pay_type", "VARCHAR(16) NOT NULL"),
                    ("hourly_rate", "DECIMAL(10,2)"),
                    ("salary_monthly", "DECIMAL(10,2)"),
                    ("total_hours", "DECIMAL(10,2) NOT NULL DEFAULT 0"),
                    ("overtime_hours", "DECIMAL(10,2) NOT NULL DEFAULT 0"),
                    ("overtime_multiplier", "DECIMAL(4,2) NOT NULL DEFAULT 1.25"),
                    ("base_pay", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("overtime_pay", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("bonus_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("allowance_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("gross_pay", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("tax_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("social_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("pension_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("other_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("tax_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("social_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("pension_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("other_deduction_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("total_deductions", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("net_pay", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("employer_social_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("employer_pension_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("employer_other_rate", "DECIMAL(6,4) NOT NULL DEFAULT 0"),
                    ("employer_social_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("employer_pension_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("employer_other_amount", "DECIMAL(12,2) NOT NULL DEFAULT 0"),
                    ("status", "VARCHAR(16) NOT NULL DEFAULT 'draft'"),
                    ("payment_method", "VARCHAR(40)"),
                    ("created_at", "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"),
                    ("updated_at", "DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"),
                ),
            )
            if not _index_exists(cursor, "paychecks", "uniq_paycheck_period"):
                cursor.execute(
                    "ALTER TABLE paychecks ADD UNIQUE INDEX uniq_paycheck_period (user_id, period_year, period_month)"
                )
                changed = True
        if changed:
            connection.commit()
