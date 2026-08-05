# [Lab 4](../../Lab%204.pdf) Writeup

This file provides guidance on how to review this Lab 4 submission.

## Risk Assessment

In reference to the findings from the [patches](./patches) and [test cases](./test_cases), we have the following revised Risk Assessment:
- [Risk Assessment.pdf](Risk%20Assessment.pdf).

## Patches

Each patch is contained in two parts:
- `patches/*.md` that provides an overview of the code changed, the vulnerability testing results, applicable screenshots, and explanations for new functions.
- `test_cases/*.py` that provides validation for the code change, as well as any applicable explanations of the relevant code change and testing methodology.

### Patch 1 - SQL Injection:

- [Test Cases](./test_cases/1_sql_injection.py)
- [Patch Writeup](./patches/1_sql_injection.md)

### Patch 2 - Reused Nonce:

- [Test Cases](./test_cases/2_random_password_nonce.py)
- [Patch Writeup](./patches/2_random_password_nonce.md)

### Patch 3 - Run Command Injection:

- [Test Cases](./test_cases/3_run_command_injection.py)
- [Patch Writeup](./patches/3_run_command_injection.md)

### Patch 4 - Socket Timeout (DoS):

- [Test Cases](./test_cases/4_socket_timeout.py)
- [Patch Writeup](./patches/5_additional_patch_notes.md)

## Additional Notes

Review the additional notes for new dependencies and changes to running the incubator in this writeup.
- [Additional Notes.md](Additional%20Notes.md)