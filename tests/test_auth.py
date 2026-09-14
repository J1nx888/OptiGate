"""common/auth.py: PBKDF2 password hashing, stdlib-only."""
from __future__ import annotations

import auth


def test_round_trip_correct_password():
    encoded = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", encoded) is True


def test_wrong_password_rejected():
    encoded = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("wrong password", encoded) is False


def test_hash_is_salted_and_nondeterministic():
    a = auth.hash_password("same password")
    b = auth.hash_password("same password")
    assert a != b
    assert auth.verify_password("same password", a) is True
    assert auth.verify_password("same password", b) is True


def test_encoded_format_fields():
    encoded = auth.hash_password("hunter2")
    algorithm, iterations, salt, digest = encoded.split("$", 3)
    assert algorithm == auth.ALGORITHM
    assert int(iterations) == auth.ITERATIONS
    assert len(salt) == 32  # 16 bytes hex-encoded
    assert len(digest) == 64  # sha256 digest hex-encoded


def test_malformed_hash_missing_fields_rejected():
    assert auth.verify_password("anything", "garbage") is False
    assert auth.verify_password("anything", "pbkdf2_sha256$1000") is False


def test_malformed_hash_empty_string_rejected():
    assert auth.verify_password("anything", "") is False


def test_none_encoded_rejected():
    assert auth.verify_password("anything", None) is False  # type: ignore[arg-type]


def test_wrong_algorithm_rejected():
    encoded = auth.hash_password("hunter2")
    _, iterations, salt, digest = encoded.split("$", 3)
    tampered = f"md5${iterations}${salt}${digest}"
    assert auth.verify_password("hunter2", tampered) is False


def test_tampered_iteration_count_changes_digest_and_is_rejected():
    encoded = auth.hash_password("hunter2")
    algorithm, iterations, salt, digest = encoded.split("$", 3)
    tampered = f"{algorithm}${int(iterations) + 1}${salt}${digest}"
    assert auth.verify_password("hunter2", tampered) is False


def test_non_numeric_iteration_count_rejected_not_raised():
    encoded = auth.hash_password("hunter2")
    algorithm, _, salt, digest = encoded.split("$", 3)
    tampered = f"{algorithm}$notanumber${salt}${digest}"
    assert auth.verify_password("hunter2", tampered) is False


def test_tampered_salt_rejected():
    encoded = auth.hash_password("hunter2")
    algorithm, iterations, _, digest = encoded.split("$", 3)
    tampered = f"{algorithm}${iterations}$deadbeefdeadbeefdeadbeefdeadbeef${digest}"
    assert auth.verify_password("hunter2", tampered) is False


def test_tampered_digest_rejected():
    encoded = auth.hash_password("hunter2")
    algorithm, iterations, salt, _ = encoded.split("$", 3)
    tampered = f"{algorithm}${iterations}${salt}$" + "0" * 64
    assert auth.verify_password("hunter2", tampered) is False


# ============================================================
# verify_admin_credentials -- the one admin-credential check shared by
# dashboard.py's HTTP-Basic admin login and
# captive_portal_server.py's portal-side admin action.
# ============================================================

def test_verify_admin_credentials_accepts_the_right_username_and_password():
    expected_hash = auth.hash_password("correcthorse")
    assert auth.verify_admin_credentials("admin", "correcthorse", "admin", expected_hash) is True


def test_verify_admin_credentials_rejects_the_wrong_password():
    expected_hash = auth.hash_password("correcthorse")
    assert auth.verify_admin_credentials("admin", "wrongpassword", "admin", expected_hash) is False


def test_verify_admin_credentials_rejects_the_wrong_username():
    expected_hash = auth.hash_password("correcthorse")
    assert auth.verify_admin_credentials("notadmin", "correcthorse", "admin", expected_hash) is False


def test_verify_admin_credentials_fails_closed_with_no_expected_username():
    expected_hash = auth.hash_password("correcthorse")
    assert auth.verify_admin_credentials("admin", "correcthorse", None, expected_hash) is False


def test_verify_admin_credentials_fails_closed_with_no_expected_hash():
    assert auth.verify_admin_credentials("admin", "correcthorse", "admin", None) is False


def test_verify_admin_credentials_fails_closed_with_an_empty_string_expected_hash():
    assert auth.verify_admin_credentials("admin", "correcthorse", "admin", "") is False
