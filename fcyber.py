"""Local defensive security utilities maintained by flexEST."""

import argparse
import hashlib
import hmac
import json
import platform
import secrets
import string
import sys
from pathlib import Path


SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def inspect_headers(path):
    """Read a saved HTTP response header block and report field presence."""
    headers = {}
    with path.open(encoding="iso-8859-1") as stream:
        for index, line in enumerate(stream):
            line = line.rstrip("\r\n")
            if not line:
                break
            if index == 0 and line.startswith("HTTP/"):
                continue
            name, separator, value = line.partition(":")
            if not separator or not name or any(char.isspace() for char in name):
                raise ValueError(f"Malformed header on line {index + 1}")
            headers.setdefault(name.lower(), []).append(value.strip())
    return {name: headers.get(name, []) for name in SECURITY_HEADERS}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("system", help="Show OS, machine architecture, and Python version")
    password = commands.add_parser("password", help="Generate a random password")
    password.add_argument("--length", type=int, default=24)
    digest = commands.add_parser("hash", help="Compute or verify a file's SHA-256 digest")
    digest.add_argument("file", type=Path)
    digest.add_argument("--expect", help="Expected SHA-256 digest")
    headers = commands.add_parser("headers", help="Review headers from a saved HTTP response")
    headers.add_argument("file", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "system":
            print(json.dumps({
                "os": platform.system(),
                "architecture": platform.machine(),
                "python": platform.python_version(),
            }, indent=2))
        elif args.command == "password":
            if not 12 <= args.length <= 1024:
                parser.error("password length must be between 12 and 1024")
            alphabet = string.ascii_letters + string.digits + string.punctuation
            print("".join(secrets.choice(alphabet) for _ in range(args.length)))
        elif args.command == "hash":
            expected = args.expect
            if expected is not None:
                if len(expected) != 64 or any(char not in string.hexdigits for char in expected):
                    parser.error("--expect must be a 64-character hexadecimal digest")
            with args.file.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            print(actual)
            if expected is not None and not hmac.compare_digest(actual, expected.lower()):
                print("SHA-256 digest mismatch", file=sys.stderr)
                return 1
        else:
            print(json.dumps(inspect_headers(args.file), indent=2))
    except (OSError, ValueError) as error:
        print(f"fcyber: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
