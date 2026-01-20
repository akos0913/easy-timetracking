"""Database helpers for MySQL connections."""
from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Iterator

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
