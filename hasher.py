"""
hasher.py
---------
Demonstrates how passwords SHOULD and SHOULD NOT be stored.

Key security concept: fast hashes (MD5, SHA-256) are designed for
speed/integrity checking, NOT for password storage -- an attacker with
a leaked hash database can try billions of guesses per second against
them. Password-hashing algorithms like bcrypt and argon2 are
deliberately SLOW and use salting, making brute-forcing impractical.
"""

import hashlib
import secrets
import time

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False


def demo_fast_hash(password: str) -> dict:
    """
    Shows why plain SHA-256 is a BAD way to store passwords:
    it's unsalted (identical passwords -> identical hashes) and
    extremely fast (bad for resisting brute force).
    """
    start = time.perf_counter()
    digest = hashlib.sha256(password.encode()).hexdigest()
    elapsed = time.perf_counter() - start

    return {
        "algorithm": "SHA-256 (fast hash -- NOT recommended for passwords)",
        "hash": digest,
        "time_seconds": elapsed,
        "warning": (
            "SHA-256 has no built-in salt and computes in microseconds, "
            "so attackers can test billions of guesses per second against "
            "a leaked database. Never use it alone for password storage."
        ),
    }


def demo_salted_hash(password: str) -> dict:
    """
    Shows a manual salt + SHA-256 combo. Better than plain SHA-256
    (defeats precomputed 'rainbow table' attacks) but still fast,
    so still not as good as bcrypt/argon2.
    """
    salt = secrets.token_hex(16)
    salted = (salt + password).encode()
    digest = hashlib.sha256(salted).hexdigest()

    return {
        "algorithm": "SHA-256 + manual salt (better, still not ideal)",
        "salt": salt,
        "hash": digest,
        "note": (
            "Adding a random salt means two identical passwords produce "
            "different hashes, defeating rainbow-table attacks. But the "
            "hash is still fast to compute, so it's still weaker than a "
            "dedicated password-hashing algorithm."
        ),
    }


def demo_bcrypt_hash(password: str) -> dict:
    """
    bcrypt: an adaptive, deliberately slow hashing algorithm built
    specifically for passwords. It has a built-in salt and a 'cost
    factor' that can be increased over time as hardware gets faster.
    """
    if not BCRYPT_AVAILABLE:
        return {"algorithm": "bcrypt", "error": "bcrypt not installed. Run: pip install bcrypt"}

    start = time.perf_counter()
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
    elapsed = time.perf_counter() - start

    is_valid = bcrypt.checkpw(password.encode(), hashed)

    return {
        "algorithm": "bcrypt (recommended)",
        "hash": hashed.decode(),
        "time_seconds": elapsed,
        "verified_correctly": is_valid,
        "note": (
            "bcrypt embeds its salt and cost factor directly in the "
            "output string. The slowness (visible in time_seconds) is "
            "intentional -- it's what makes brute-forcing impractical."
        ),
    }


def demo_argon2_hash(password: str) -> dict:
    """
    Argon2 won the 2015 Password Hashing Competition and is the
    current best-practice recommendation (OWASP). It's tunable for
    time cost, memory cost, and parallelism.
    """
    if not ARGON2_AVAILABLE:
        return {"algorithm": "argon2", "error": "argon2-cffi not installed. Run: pip install argon2-cffi"}

    ph = PasswordHasher()
    start = time.perf_counter()
    hashed = ph.hash(password)
    elapsed = time.perf_counter() - start

    try:
        ph.verify(hashed, password)
        verified = True
    except VerifyMismatchError:
        verified = False

    return {
        "algorithm": "argon2id (current best practice)",
        "hash": hashed,
        "time_seconds": elapsed,
        "verified_correctly": verified,
        "note": (
            "Argon2 also costs memory to compute, not just time, which "
            "makes it resistant to GPU/ASIC-accelerated cracking attempts "
            "in a way that bcrypt is not."
        ),
    }


def run_all_hash_demos(password: str) -> dict:
    """Runs every hashing demo and returns them together for comparison."""
    return {
        "sha256_fast": demo_fast_hash(password),
        "sha256_salted": demo_salted_hash(password),
        "bcrypt": demo_bcrypt_hash(password),
        "argon2": demo_argon2_hash(password),
    }
