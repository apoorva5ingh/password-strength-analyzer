"""
breach_checker.py
------------------
Checks a password against the Have I Been Pwned (HIBP) breach database
using the k-anonymity model, so the full password (or even its full
hash) is NEVER sent over the network.

How k-anonymity works here:
    1. Compute the SHA-1 hash of the password locally.
    2. Send ONLY the first 5 characters of that hash to the API.
    3. The API returns EVERY hash suffix that shares that 5-char
       prefix (often hundreds of them), along with breach counts.
    4. Locally, check if your full hash's suffix appears in that list.

This means the API never sees enough of your hash to identify your
actual password -- it only sees a prefix shared by many other hashes.
"""

import hashlib

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_breach(password: str, timeout: int = 5) -> dict:
    """
    Returns whether the password has appeared in known breaches, and
    how many times, without ever sending the full password or hash.
    """
    if not REQUESTS_AVAILABLE:
        return {
            "checked": False,
            "error": "The 'requests' library is not installed. Run: pip install requests",
        }

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        response = requests.get(f"{HIBP_API_URL}{prefix}", timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as e:
        return {"checked": False, "error": f"Network error contacting HIBP API: {e}"}

    # Response body is lines of "SUFFIX:COUNT"
    for line in response.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return {
                "checked": True,
                "breached": True,
                "times_seen": int(count),
                "message": (
                    f"This password has appeared in {int(count):,} known "
                    "data breaches. Do not use it."
                ),
            }

    return {
        "checked": True,
        "breached": False,
        "times_seen": 0,
        "message": "This password was not found in the HIBP breach database.",
    }
