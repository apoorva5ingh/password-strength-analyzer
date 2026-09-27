"""
main.py
-------
CLI entry point for the Password Strength & Security Analyzer.

Usage examples:
    python main.py                          # interactive prompt
    python main.py -p "MyP@ssw0rd123"       # analyze one password directly
    python main.py -p "MyP@ssw0rd123" --hash-demo   # also show hashing demos
    python main.py -p "MyP@ssw0rd123" --breach-check  # also check HIBP
"""

import argparse
import getpass

from strength_checker import analyze_password, load_common_passwords
from hasher import run_all_hash_demos
from breach_checker import check_breach


DIVIDER = "-" * 60


def print_report(result: dict) -> None:
    print(DIVIDER)
    print(f"PASSWORD STRENGTH REPORT")
    print(DIVIDER)
    print(f"Score:            {result['score']}/100")
    print(f"Verdict:          {result['verdict']}")
    print(f"Entropy:          {result['entropy_bits']} bits ({result['entropy_label']})")
    print()

    print("Length check:")
    print(f"  {result['length_check']['message']}")
    print()

    print("Character variety:")
    variety = result["variety_check"]
    print(f"  {variety['passed_count']}/{variety['total']} character types present.")
    if variety["missing"]:
        print(f"  Missing: {', '.join(variety['missing'])}")
    print()

    print("Dictionary check:")
    print(f"  {result['dictionary_check']['message']}")
    print()

    print("Pattern warnings:")
    if result["pattern_warnings"]:
        for warning in result["pattern_warnings"]:
            print(f"  - {warning}")
    else:
        print("  None detected.")
    print()

    if result["suggestions"]:
        print("Suggestions to improve:")
        for suggestion in result["suggestions"]:
            print(f"  - {suggestion}")
    else:
        print("No suggestions -- this password looks solid across all checks.")
    print(DIVIDER)


def print_hash_demos(password: str) -> None:
    demos = run_all_hash_demos(password)
    print()
    print(DIVIDER)
    print("HASHING DEMONSTRATION (how this password could be stored)")
    print(DIVIDER)
    for key, demo in demos.items():
        print(f"\n[{demo.get('algorithm', key)}]")
        if "error" in demo:
            print(f"  Skipped: {demo['error']}")
            continue
        if "hash" in demo:
            print(f"  Hash: {demo['hash']}")
        if "salt" in demo:
            print(f"  Salt: {demo['salt']}")
        if "time_seconds" in demo:
            print(f"  Time to compute: {demo['time_seconds']:.6f} seconds")
        note = demo.get("note") or demo.get("warning")
        if note:
            print(f"  Note: {note}")
    print(DIVIDER)


def print_breach_check(password: str) -> None:
    print()
    print(DIVIDER)
    print("BREACH CHECK (Have I Been Pwned, via k-anonymity)")
    print(DIVIDER)
    result = check_breach(password)
    if not result.get("checked"):
        print(f"  Could not check: {result.get('error')}")
    else:
        print(f"  {result['message']}")
    print(DIVIDER)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a password's strength and security properties."
    )
    parser.add_argument(
        "-p", "--password",
        help="Password to analyze. If omitted, you'll be prompted securely.",
    )
    parser.add_argument(
        "--hash-demo",
        action="store_true",
        help="Also show how this password would look under different hashing algorithms.",
    )
    parser.add_argument(
        "--breach-check",
        action="store_true",
        help="Also check this password against the Have I Been Pwned breach database.",
    )
    args = parser.parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Enter a password to analyze (input hidden): ")

    if not password:
        print("No password entered. Exiting.")
        return

    wordlist = load_common_passwords()
    result = analyze_password(password, wordlist)
    print_report(result)

    if args.hash_demo:
        print_hash_demos(password)

    if args.breach_check:
        print_breach_check(password)


if __name__ == "__main__":
    main()
