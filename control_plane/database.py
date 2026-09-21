import hashlib
import os

import psycopg
from psycopg.rows import dict_row


def connect():
    return psycopg.connect(os.environ["RMM_DATABASE_URL"], row_factory=dict_row,
                           connect_timeout=5, options="-c statement_timeout=5000 -c lock_timeout=2000")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def initialize():
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id uuid PRIMARY KEY, name text NOT NULL,
                technician_hash text UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id uuid PRIMARY KEY, workspace_id uuid NOT NULL REFERENCES workspaces(id),
                public_key text UNIQUE NOT NULL, approved_at timestamptz NOT NULL DEFAULT now(),
                last_seen timestamptz, activate_before timestamptz
            );
            ALTER TABLE devices ADD COLUMN IF NOT EXISTS activate_before timestamptz;
            CREATE TABLE IF NOT EXISTS pairings (
                public_key text PRIMARY KEY, code_hash text UNIQUE NOT NULL,
                expires_at timestamptz NOT NULL
            );
            CREATE TABLE IF NOT EXISTS request_budget (
                name text PRIMARY KEY, window_start timestamptz NOT NULL, attempts integer NOT NULL
            );
        """)
