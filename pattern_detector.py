"""
pattern_detector.py
--------------------
Detects weak structural patterns inside a password using regex and
simple sliding-window logic:
    - repeated characters (aaa, 111)
    - sequential characters (abcd, 1234)
    - keyboard walk patterns (qwerty, asdf)
    - common leetspeak substitutions (p@ssw0rd -> password)
"""

import re

# Rows of a standard QWERTY keyboard, used to detect "keyboard walks"
KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]

# Common leetspeak substitutions, used to "normalize" a password before
# checking it against the common-password dictionary.
LEET_MAP = {
    "@": "a",
    "4": "a",
    "3": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "$": "s",
    "5": "s",
    "7": "t",
    "+": "t",
}


def has_repeated_chars(password: str, min_repeat: int = 3) -> bool:
    """
    Detects 3+ identical characters in a row, e.g. 'aaa', '111'.
    Regex explanation:
        (.)      -> capture any single character
        \\1{2,}  -> that same character repeated 2+ more times
    """
    pattern = r"(.)\1{" + str(min_repeat - 1) + ",}"
    return bool(re.search(pattern, password))


def has_sequential_chars(password: str, min_length: int = 4) -> bool:
    """
    Detects ascending or descending sequences like 'abcd' or '4321'.
    This is NOT pure regex -- sequences of arbitrary characters can't be
    matched with a fixed pattern, so we use a sliding window over the
    string and compare character codes.
    """
    lowered = password.lower()
    for i in range(len(lowered) - min_length + 1):
        window = lowered[i:i + min_length]
        codes = [ord(c) for c in window]

        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))

        if ascending or descending:
            return True
    return False


def has_keyboard_walk(password: str, min_length: int = 4) -> bool:
    """
    Detects substrings that follow a physical keyboard row,
    e.g. 'qwerty', 'asdf', forwards or backwards.
    """
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        reversed_row = row[::-1]
        for i in range(len(row) - min_length + 1):
            chunk = row[i:i + min_length]
            reversed_chunk = reversed_row[i:i + min_length]
            if chunk in lowered or reversed_chunk in lowered:
                return True
    return False


def normalize_leetspeak(password: str) -> str:
    """
    Converts leetspeak substitutions back to plain letters so that
    'p@ssw0rd' becomes 'password' for dictionary comparison.
    """
    normalized = password.lower()
    for leet_char, real_char in LEET_MAP.items():
        normalized = normalized.replace(leet_char, real_char)
    return normalized


def detect_patterns(password: str) -> list:
    """
    Runs all pattern checks and returns a list of human-readable
    warnings for whichever weak patterns were found.
    """
    warnings = []

    if has_repeated_chars(password):
        warnings.append("Contains repeated characters (e.g. 'aaa', '111').")

    if has_sequential_chars(password):
        warnings.append("Contains a sequential run of characters (e.g. 'abcd', '1234').")

    if has_keyboard_walk(password):
        warnings.append("Contains a keyboard walk pattern (e.g. 'qwerty', 'asdf').")

    return warnings
