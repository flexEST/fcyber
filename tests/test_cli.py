import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "fcyber.py"


class ToolkitTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *map(str, args)],
            capture_output=True,
            text=True,
        )

    def test_system(self):
        result = self.run_cli("system")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout)), {"os", "architecture", "python"})

    def test_password_and_invalid_length(self):
        result = self.run_cli("password", "--length", 32)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.rstrip("\n")), 32)
        self.assertEqual(self.run_cli("password", "--length", 1).returncode, 2)

    def test_hash_match_and_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "sample"
            file.write_bytes(b"sample")
            expected = hashlib.sha256(b"sample").hexdigest()
            result = self.run_cli("hash", file, "--expect", expected.upper())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected)
            self.assertEqual(self.run_cli("hash", file, "--expect", "0" * 64).returncode, 1)
            self.assertEqual(self.run_cli("hash", file, "--expect", "bad").returncode, 2)

    def test_headers_and_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "headers"
            file.write_text("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\n\nbody")
            result = self.run_cli("headers", file)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["x-content-type-options"], ["nosniff"])
            self.assertEqual(report["content-security-policy"], [])
            file.write_text("malformed")
            self.assertEqual(self.run_cli("headers", file).returncode, 1)


if __name__ == "__main__":
    unittest.main()
