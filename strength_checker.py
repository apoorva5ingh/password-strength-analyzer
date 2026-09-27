"""
strength_checker.py
--------------------
Core scoring logic:
    1. Rule-based checks (length, character variety)
    2. Entropy calculation (mathematical randomness measure)
    3. Dictionary check against a common-passwords wordlist
    4. Combines everything into a final score + verdict
"""

import math
import os
import re

from pattern_detector import detect_patterns, normalize_leetspeak

COMMON_PASSWORDS_FILE = os.path.join(
    os.path.dirname(__file__), "common_passwords.txt"
)


def load_common_passwords(filepath: str = COMMON_PASSWORDS_FILE) -> set:
    """Loads the wordlist into a set for O(1) membership checks."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def check_length(password: str) -> dict:
    length = len(password)
    if length >= 12:
        return {"passed": True, "message": f"Good length ({length} characters)."}
    elif length >= 8:
        return {"passed": True, "message": f"Acceptable length ({length} characters), 12+ is better."}
    else:
        return {"passed": False, "message": f"Too short ({length} characters). Use at least 8, ideally 12+."}


def check_character_variety(password: str) -> dict:
    """
    Uses regex to check for presence of each character class.
    re.search returns a match object (truthy) or None (falsy).
    """
    checks = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"[0-9]", password)),
        "symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }
    passed_count = sum(checks.values())
    missing = [name for name, ok in checks.items() if not ok]

    return {
        "passed_count": passed_count,
        "total": 4,
        "checks": checks,
        "missing": missing,
    }


def calculate_pool_size(password: str) -> int:
    """
    Determines the size of the character 'alphabet' the password draws
    from, based on which character classes are actually present.
    This is the basis of the entropy formula below.
    """
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32  # approx. size of common symbol set
    return pool_size


def calculate_entropy(password: str) -> float:
    """
    Shannon-style entropy estimate for a password, in bits:

        entropy = length * log2(pool_size)

    Intuition: pool_size is how many possible characters could appear
    at each position. log2(pool_size) is the number of "yes/no"
    guesses needed to pin down ONE character. Multiplying by length
    gives the total guesses needed to pin down the whole password --
    i.e. how resistant it is to brute-force guessing.

    This is an ESTIMATE. It assumes characters are random -- a long
    password made of a real word (low true randomness) will score
    higher here than it deserves, which is exactly why we ALSO run
    dictionary and pattern checks separately.
    """
    pool_size = calculate_pool_size(password)
    if pool_size == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def entropy_label(entropy: float) -> str:
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Reasonable"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"


def check_dictionary(password: str, wordlist: set) -> dict:
    """
    Checks both the raw password AND its leetspeak-normalized form
    against the common-passwords wordlist, so 'P@ssw0rd123' still
    gets caught even though it isn't literally in the file.
    """
    lowered = password.lower()
    normalized = normalize_leetspeak(password)

    if lowered in wordlist:
        return {"found": True, "message": "This exact password appears in a common-password list."}
    if normalized in wordlist:
        return {"found": True, "message": f"This password closely resembles the common password '{normalized}'."}
    return {"found": False, "message": "Not found in the common-password list."}


def calculate_score(length_result, variety_result, entropy, dictionary_result, pattern_warnings) -> int:
    """
    Combines all signals into a single 0-100 score.
    Weighting (out of 100):
        - Length:            20 points
        - Character variety: 20 points
        - Entropy:           40 points
        - Dictionary/pattern penalties subtracted from the total
    """
    score = 0

    # Length component (max 20)
    if length_result["passed"] and "12+" not in length_result["message"] and "Acceptable" not in length_result["message"]:
        score += 20
    elif length_result["passed"]:
        score += 12
    else:
        score += 0

    # Variety component (max 20) -> 5 points per character class present
    score += variety_result["passed_count"] * 5

    # Entropy component (max 40), scaled: 80+ bits = full marks
    entropy_score = min(40, (entropy / 80) * 40)
    score += entropy_score

    # Penalties
    if dictionary_result["found"]:
        score -= 40
    score -= len(pattern_warnings) * 10

    return max(0, min(100, round(score)))


def score_to_verdict(score: int) -> str:
    if score < 30:
        return "Very Weak"
    elif score < 50:
        return "Weak"
    elif score < 70:
        return "Fair"
    elif score < 90:
        return "Strong"
    else:
        return "Very Strong"


def analyze_password(password: str, wordlist: set = None) -> dict:
    """
    Runs the full analysis pipeline and returns a single result dict
    with every sub-result plus a final score/verdict.
    """
    if wordlist is None:
        wordlist = load_common_passwords()

    length_result = check_length(password)
    variety_result = check_character_variety(password)
    entropy = calculate_entropy(password)
    dictionary_result = check_dictionary(password, wordlist)
    pattern_warnings = detect_patterns(password)

    score = calculate_score(length_result, variety_result, entropy, dictionary_result, pattern_warnings)
    verdict = score_to_verdict(score)

    suggestions = []
    if not length_result["passed"]:
        suggestions.append("Increase the length to at least 8-12 characters.")
    if variety_result["missing"]:
        suggestions.append(f"Add missing character types: {', '.join(variety_result['missing'])}.")
    if dictionary_result["found"]:
        suggestions.append("Avoid common/leaked passwords entirely -- pick something unrelated.")
    suggestions.extend(f"Fix: {w}" for w in pattern_warnings)

    return {
        "password": password,
        "length_check": length_result,
        "variety_check": variety_result,
        "entropy_bits": round(entropy, 2),
        "entropy_label": entropy_label(entropy),
        "dictionary_check": dictionary_result,
        "pattern_warnings": pattern_warnings,
        "score": score,
        "verdict": verdict,
        "suggestions": suggestions,
    }
