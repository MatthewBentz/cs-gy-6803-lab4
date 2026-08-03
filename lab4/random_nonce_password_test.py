"""
Test case for Vulnerability #3: hardcoded AES-EAX nonce in app.py.

This test verifies the patch by checking that:
1. Encrypting the same password twice produces different encrypted values.
2. The ciphertext portions are different because the nonce is random.
3. verify_password() still authenticates the correct password and rejects an incorrect password.

Run from the lab4 directory after installing requirements:
    python3 random_nonce_password_test.py
"""

import sqlite3

from app import encrypt_password, verify_password, NONCE_SIZE, TAG_SIZE


def test_random_nonce_encryption_and_password_verification():
    password = "SQLi_is_easier_than_this"
    act_token = "test-application-token"

    encrypted_1 = encrypt_password(password)
    encrypted_2 = encrypt_password(password)

    # Before the patch, these values would be identical because the nonce was hardcoded.
    assert encrypted_1 != encrypted_2, "FAIL: encrypting the same password twice returned identical blobs"
    assert encrypted_1[:NONCE_SIZE] != encrypted_2[:NONCE_SIZE], "FAIL: nonce was reused"
    assert encrypted_1[NONCE_SIZE + TAG_SIZE:] != encrypted_2[NONCE_SIZE + TAG_SIZE:], (
        "FAIL: ciphertext did not change for the same password"
    )

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE users (user_id INTEGER PRIMARY KEY, password BLOB NOT NULL, act_token TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT INTO users (user_id, password, act_token) VALUES (?, ?, ?)",
        (101, sqlite3.Binary(encrypted_1), act_token),
    )

    is_valid, returned_token = verify_password(conn, password)
    assert is_valid is True, "FAIL: correct password was rejected after random nonce patch"
    assert returned_token == act_token, "FAIL: verify_password returned the wrong application token"

    is_valid, returned_token = verify_password(conn, "wrong-password")
    assert is_valid is False, "FAIL: incorrect password was accepted"
    assert returned_token == "", "FAIL: incorrect password should not return an application token"

    print("PASS: random nonce encryption works and password verification still succeeds.")
    print(f"Encrypted value #1 length: {len(encrypted_1)} bytes")
    print(f"Encrypted value #2 length: {len(encrypted_2)} bytes")
    print(f"Nonce #1: {encrypted_1[:NONCE_SIZE].hex()}")
    print(f"Nonce #2: {encrypted_2[:NONCE_SIZE].hex()}")
    print(f"Ciphertext #1: {encrypted_1[NONCE_SIZE + TAG_SIZE:].hex()}")
    print(f"Ciphertext #2: {encrypted_2[NONCE_SIZE + TAG_SIZE:].hex()}")


if __name__ == "__main__":
    test_random_nonce_encryption_and_password_verification()
