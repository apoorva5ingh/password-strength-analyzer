# Password Strength & Security Analyzer

A Python CLI tool that analyzes password strength using regex-based pattern
detection, entropy calculation, dictionary checks, and demonstrates secure
password hashing (bcrypt/argon2) plus an optional breach check against
Have I Been Pwned.

## Project structure

```
password_analyzer/
├── main.py                # CLI entry point
├── strength_checker.py    # rule-based checks + entropy + scoring engine
├── pattern_detector.py    # regex pattern detection (repeats, sequences, keyboard walks)
├── hasher.py               # hashing demos: SHA-256, salted SHA-256, bcrypt, argon2
├── breach_checker.py       # Have I Been Pwned k-anonymity breach check
├── common_passwords.txt   # wordlist for dictionary check
├── requirements.txt
└── README.md
```

## Demo

![Password Strength Analyzer Demo](demo/password-analyzer.png)

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Interactive mode (hidden input)
python main.py

# Analyze a password directly
python main.py -p "MyP@ssw0rd123"

# Also show hashing demonstrations
python main.py -p "MyP@ssw0rd123" --hash-demo

# Also check against the HIBP breach database (requires internet)
python main.py -p "MyP@ssw0rd123" --breach-check

# All together
python main.py -p "MyP@ssw0rd123" --hash-demo --breach-check
```

## How it works

1. **Length & character variety** — basic regex checks for lowercase,
   uppercase, digits, and symbols.
2. **Entropy** — `length * log2(pool_size)`, an estimate of how many bits
   of randomness the password contains, i.e. resistance to brute force.
3. **Dictionary check** — compares the password (and a leetspeak-normalized
   version, e.g. `p@ssw0rd` → `password`) against a common-passwords list.
4. **Pattern detection** — regex + sliding-window checks for repeated
   characters, sequential runs (`abcd`, `1234`), and keyboard walks
   (`qwerty`, `asdf`).
5. **Scoring** — combines all of the above into a 0–100 score and verdict.
6. **Hashing demo** — shows the same password hashed with SHA-256 (fast,
   insecure for passwords), salted SHA-256 (better), bcrypt, and argon2
   (current best practice), with timing to illustrate why slow hashing
   matters.
7. **Breach check (optional)** — uses HIBP's k-anonymity API: only the
   first 5 characters of the password's SHA-1 hash are ever sent over
   the network, never the password or full hash.

## Extending it

Some natural next steps if you want to keep building:
- A password *generator* that produces passwords guaranteed to score well
- Batch mode: read a list of passwords from a file and report on all of them
- A `--json` output flag for machine-readable results
- Unit tests with `pytest` for each module
