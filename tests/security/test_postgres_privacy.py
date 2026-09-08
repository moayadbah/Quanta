"""Exercise the real grants used by Supabase's Data API on CI's disposable Postgres."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

from quanta.web.db import Database


def test_postgres_storage_is_private_and_pooler_compatible(tmp_path: Path) -> None:
    url = os.environ.get("QUANTA_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Requires CI's disposable PostgreSQL database")

    roles = ("anon", "authenticated", "service_role")
    with psycopg.connect(url) as conn:
        conn.execute("CREATE SCHEMA IF NOT EXISTS quanta")
        for role in roles:
            if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
            # Simulate an existing project's permissive grants, including grants
            # inherited by tables that Quanta hasn't created yet.
            for statement in (
                "GRANT ALL ON SCHEMA quanta TO {}",
                "GRANT ALL ON ALL TABLES IN SCHEMA quanta TO {}",
                "GRANT ALL ON ALL SEQUENCES IN SCHEMA quanta TO {}",
                "ALTER DEFAULT PRIVILEGES IN SCHEMA quanta GRANT ALL ON TABLES TO {}",
                "ALTER DEFAULT PRIVILEGES IN SCHEMA quanta GRANT ALL ON SEQUENCES TO {}",
            ):
                conn.execute(sql.SQL(statement).format(sql.Identifier(role)))

    db = Database(tmp_path / "unused.sqlite", url)
    with db.connect(write=True) as conn:
        assert conn.execute("SELECT current_schema()").fetchone()[0] == "quanta"
        conn.execute(
            "INSERT INTO usage_counters(id,used) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET used=1",
            ("postgres-privacy-test", 1),
        )
        # A repeated parameterized query would cross psycopg's default prepare
        # threshold, which Supavisor transaction pooling does not support.
        for _ in range(8):
            assert conn.execute(
                "SELECT used FROM usage_counters WHERE id=?", ("postgres-privacy-test",)
            ).fetchone() == {"used": 1}
        assert conn.execute("SELECT COUNT(*) FROM pg_prepared_statements").fetchone()[0] == 0
        assert conn.execute(
            "SELECT bool_and(relrowsecurity) FROM pg_class "
            "WHERE relnamespace='quanta'::regnamespace AND relkind='r'"
        ).fetchone()[0]

    for role in roles:
        for statement in (
            "SELECT token FROM quanta.sessions",
            "SELECT data FROM quanta.artifact_blobs",
            "UPDATE quanta.usage_counters SET used=0",
            "DELETE FROM quanta.jobs",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(url) as conn:
                conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role)))
                conn.execute(statement)

    # RLS is a second boundary if a browser role is accidentally granted access.
    with psycopg.connect(url) as conn:
        conn.execute("GRANT USAGE ON SCHEMA quanta TO anon")
        conn.execute("GRANT SELECT,INSERT ON quanta.usage_counters TO anon")
        conn.execute("SET LOCAL ROLE anon")
        assert conn.execute("SELECT * FROM quanta.usage_counters").fetchall() == []
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO quanta.usage_counters VALUES ('forged-quota',0)")
        conn.rollback()  # Undo this test's accidental grants.

    # A fresh function instance retains the private data and schema selection.
    restarted = Database(tmp_path / "another.sqlite", url)
    with restarted.connect(write=True) as conn:
        assert (
            conn.execute(
                "SELECT used FROM usage_counters WHERE id=?", ("postgres-privacy-test",)
            ).fetchone()[0]
            == 1
        )
        conn.execute("DELETE FROM usage_counters WHERE id=?", ("postgres-privacy-test",))
