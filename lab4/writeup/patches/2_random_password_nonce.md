# Hardcoded Nonce Value for Password Encryption

## Vulnerability

`app.py` previously used a static AES-EAX nonce when encrypting passwords:

```python
nonce = b'0123456789abcdef'
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
```

AES-EAX requires a unique nonce for each encryption operation. Reusing the same nonce makes password encryption deterministic: encrypting the same password with the same key creates the same encrypted value. This leaks relationships between encrypted password values and weakens the confidentiality of stored authentication data.

## Files changed

- `cs-gy-6803-lab4/app.py`
- `cs-gy-6803-lab4/random_nonce_password_test.py`
- `cs-gy-6803-lab4/writeup/Vulnerability 3 - Hardcoded Nonce Patch.md`

Supporting testability-only changes were also made to:

- `cs-gy-6803-lab4/SampleNetworkClient.py`
- `cs-gy-6803-lab4/SampleNetworkServer.py`

Those two files now wrap their executable simulator/client startup code in `if __name__ == "__main__":`. This allows the test scripts to import classes and functions without automatically starting the GUI or simulator. Running either file directly still starts the program normally.

## Patch description

### 1. Random nonce generation

The password encryption function now creates a new random nonce for each encryption operation:

```python
nonce = get_random_bytes(NONCE_SIZE)
cipher = AES.new(PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
return nonce + tag + ciphertext
```

The stored encrypted password format remains:

```text
nonce || tag || ciphertext
```

This keeps the nonce available for decryption while ensuring the nonce is no longer reused.

### 2. Password verification logic updated

Because encryption now uses a random nonce, `verify_password()` can no longer encrypt the submitted password and compare the encrypted bytes to the database value. The same password should now produce different encrypted bytes each time.

To preserve authentication functionality, `verify_password()` now:

1. Retrieves the stored encrypted password from the database.
2. Splits the stored value into nonce, tag, and ciphertext.
3. Decrypts and authenticates the stored AES-EAX value.
4. Compares the decrypted stored password to the submitted password using `hmac.compare_digest()`.
5. Returns the existing application token only when the password is correct.

### 3. New helper functions

#### `split_encrypted_password(encrypted_password)`

Splits the stored password blob into three parts:

- 16-byte nonce
- 16-byte AES-EAX authentication tag
- ciphertext

It also rejects malformed encrypted password values that are too short.

#### `decrypt_password(encrypted_password)`

Uses the nonce and tag stored with the encrypted password to decrypt and authenticate the ciphertext. If the value has been modified or has the wrong tag, decryption fails.

## Test case documentation

### Test Case Description

This test checks whether password encryption uses a fresh AES-EAX nonce each time and whether application password authentication still works after replacing the hardcoded nonce.

### Precondition

The patch in `app.py` is applied. The lab dependencies from `requirements.txt` are installed, especially Flask and pycryptodome.

### Test procedure

Run the following command from the `cs-gy-6803-lab4` directory:

```bash
python3 random_nonce_password_test.py
```

The test performs the following steps:

1. Calls `encrypt_password()` twice using the same plaintext password.
2. Verifies that the full encrypted password blobs are different.
3. Verifies that the nonce values are different.
4. Verifies that the ciphertext portions are different.
5. Stores one encrypted password value in an in-memory SQLite database.
6. Calls `verify_password()` with the correct password and confirms that authentication succeeds.
7. Calls `verify_password()` with the wrong password and confirms that authentication fails.

### Expected Result

After the patch:

- The same password encrypted twice should produce different encrypted values.
- The nonce values should be different.
- The ciphertext values should be different.
- The correct password should still authenticate successfully.
- The wrong password should be rejected.

### Actual Result

When the test is run after installing the lab dependencies, the expected successful output is:

```text
PASS: random nonce encryption works and password verification still succeeds.
Encrypted value #1 length: <length> bytes
Encrypted value #2 length: <length> bytes
Nonce #1: <hex value>
Nonce #2: <different hex value>
Ciphertext #1: <hex value>
Ciphertext #2: <different hex value>
```

### Post Condition

The application can still verify stored encrypted passwords, but password encryption no longer reuses a static nonce.

### Pass/Fail

Pass if the test prints the `PASS` message and the two nonce/ciphertext outputs are different. Fail if either encryption output is identical, if the nonce is reused, if the correct password is rejected, or if the wrong password is accepted.

### Explanation

This test validates the security fix because the vulnerable implementation was deterministic: encrypting the same password twice returned the same encrypted bytes due to the hardcoded nonce. The patched implementation should produce different encrypted values for the same password while preserving successful authentication. Testing both encryption randomness and `verify_password()` ensures the vulnerability is fixed without breaking the login password-verification path.

## Risk assessment update

| Risk Item | Before Patch | After Patch | Justification |
|---|---:|---:|---|
| Hardcoded AES-EAX nonce for password encryption | High | Low | The application no longer reuses the same nonce for every password encryption operation. A fresh random nonce prevents deterministic password encryption and removes the direct relationship leakage between repeated encrypted values. |

