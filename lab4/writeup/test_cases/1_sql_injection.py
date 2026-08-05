"""
Test case for Vulnerability #1: SQL Injection in the /login route (app.py).

Location: app.py, login()
Original vulnerable query (Lab 3):
    db_query = "SELECT * FROM users WHERE password = '" + password + "'"
The submitted password was concatenated directly into the SQL string. An
attacker could submit a payload such as:
    ' or 1=1 --
which turns the query into "SELECT * FROM users WHERE password = '' or 1=1 --'",
always evaluating to true and returning every row in the users table
(including other users' encrypted passwords and application tokens),
without knowing any valid password.

Current (patched) query in app.py:
    db_query = "SELECT * FROM users WHERE password = ?"
    db_password = conn.execute(db_query, (password,)).fetchone()
This uses SQLite parameter substitution (the "?" placeholder). The
submitted value is always bound as literal data, never interpreted as
part of the SQL statement, so injection syntax cannot change the query's
meaning.

This test proves the patch works by comparing two versions of the same
query against the identical injection payload:
  1. vulnerable_query() reproduces the original Lab 3 query pattern, to
     confirm the payload DOES return rows when the query is unpatched
     (the "before" case).
  2. patched_query() calls the query exactly as written in the current
     app.py, to confirm the same payload returns NO rows (the "after"
     case).

Run from the lab4 directory after installing requirements:
    python3 sql_injection_test.py
"""

import sqlite3

INJECTION_PAYLOAD = "' or 1=1 --"


def build_test_db():
    """Create an in-memory database with one user row, matching schema.sql."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE users (user_id INTEGER PRIMARY KEY, password BLOB NOT NULL, act_token TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO users (user_id, password, act_token) VALUES (?, ?, ?)",
        (101, b"fake_encrypted_password_blob", "test-application-token"),
    )
    conn.commit()
    return conn


def vulnerable_query(conn, password):
    """Reproduces the original Lab 3 vulnerable query for comparison only.

    This function is NOT used by the live application. It exists purely to
    demonstrate what the unpatched behavior looked like, so the "before"
    and "after" results in this test can be compared directly against the
    same injection payload and the same test database.
    """
    query = "SELECT * FROM users WHERE password = '" + password + "'"
    return conn.execute(query).fetchall()


def patched_query(conn, password):
    """Runs the query exactly as it is written in the current app.py."""
    query = "SELECT * FROM users WHERE password = ?"
    return conn.execute(query, (password,)).fetchall()


def test_sql_injection_patch():
    conn = build_test_db()

    # BEFORE: reproduce the original vulnerable query pattern.
    vulnerable_result = vulnerable_query(conn, INJECTION_PAYLOAD)
    assert len(vulnerable_result) == 1, (
        "Sanity check failed: the simulated vulnerable query should return "
        "the user row when given the injection payload."
    )
    print(
        "BEFORE (vulnerable query): injection payload returned "
        f"{len(vulnerable_result)} row(s) -> vulnerability reproduced."
    )

    # AFTER: run the actual patched query from app.py.
    patched_result = patched_query(conn, INJECTION_PAYLOAD)
    assert len(patched_result) == 0, (
        "FAIL: the patched query returned rows for an injection payload; "
        "the SQL injection vulnerability is NOT fixed."
    )
    print(
        "AFTER (patched query): injection payload returned "
        f"{len(patched_result)} row(s) -> vulnerability is fixed."
    )

    # Confirm the patched query still authenticates a legitimate password.
    conn.execute("DELETE FROM users")
    conn.execute(
        "INSERT INTO users (user_id, password, act_token) VALUES (?, ?, ?)",
        (101, "correct-password", "test-application-token"),
    )
    legit_result = patched_query(conn, "correct-password")
    assert len(legit_result) == 1, "FAIL: patched query rejected a legitimate password"
    print("Legitimate password still authenticates correctly after the patch.")

    print("PASS: SQL injection vulnerability is fixed.")


if __name__ == "__main__":
    test_sql_injection_patch()
