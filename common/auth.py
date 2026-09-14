#!/usr/bin/env python3
"""PBKDF2-SHA256 password hashing. Stdlib-only so the proxy container (which
needs to verify passwords for Squid's auth helper) doesn't need pip at all.
"""
from __future__ import annotations

import hashlib
import hmac
import os

ITERATIONS = 260_000
ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), ITERATIONS)
    return f"{ALGORITHM}${ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_s, salt, expected_hex = encoded.split("$", 3)
        iterations = int(iterations_s)
    except (ValueError, AttributeError):
        return False
    if algorithm != ALGORITHM:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return hmac.compare_digest(digest.hex(), expected_hex)


def verify_admin_credentials(
    username: str, password: str, expected_username: str | None, expected_hash: str | None
) -> bool:
    """The one admin-credential check shared by `dashboard/dashboard.py`'s
    HTTP-Basic admin login and `dashboard/captive_portal_server.py`'s
    portal-side admin action -- factored out here instead of each keeping
    its own copy, so there is exactly one place that decides what counts
    as valid admin credentials.

    Deliberately takes the expected username/hash as plain arguments
    rather than a DB connection -- this module stays stdlib-only, zero
    external dependencies (see its own module docstring; the `proxy`
    container needs that to hold), so fetching `settings.admin_username`/
    `admin_password_hash` is the caller's job.

    `expected_username`/`expected_hash` being falsy (no admin account
    configured yet) always fails closed.
    """
    if not expected_username or not expected_hash:
        return False
    return username == expected_username and verify_password(password, expected_hash)
