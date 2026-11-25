import hashlib
import json
from pathlib import Path
import socket
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


    def test_inventory_tracks_changes_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "files"
            root.mkdir()
            manifest = root.parent / "manifest.json"
            (root / "changed").write_text("before")
            (root / "removed").touch()
            (root / "link").symlink_to(manifest)
            created = self.run_cli("inventory", "create", root, manifest)
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertEqual(set(json.loads(manifest.read_text())["files"]), {"changed", "removed"})
            self.assertEqual(self.run_cli("inventory", "verify", root, manifest).returncode, 0)
            self.assertEqual(self.run_cli("inventory", "create", root, manifest).returncode, 1)
            (root / "changed").write_text("after")
            (root / "removed").unlink()
            (root / "added").touch()
            result = self.run_cli("inventory", "verify", root, manifest)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout), {
                "added": ["added"], "removed": ["removed"], "changed": ["changed"],
            })

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux socket tables required")
    def test_bindings_detects_local_listener(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            result = self.run_cli("bindings")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(any(
                item["address"] == "127.0.0.1" and item["port"] == port
                for item in json.loads(result.stdout)
            ))
            filtered = self.run_cli("bindings", "--non-loopback")
            self.assertEqual(filtered.returncode, 0, filtered.stderr)
            self.assertFalse(any(item["address"] == "127.0.0.1" for item in json.loads(filtered.stdout)))

    def test_resolve_local_address(self):
        result = self.run_cli("resolve", "127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["ipv4"], ["127.0.0.1"])

    def test_log_summary_handles_errors_without_printing_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "logs.jsonl"
            records = [
                {"level": "warn", "message": "private content"},
                {"level": "error"},
                {"level": None},
            ]
            file.write_text("\n".join(map(json.dumps, records)))
            result = self.run_cli("log-summary", file, "--fail-on-error")
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout), {
                "records": 3, "levels": {"WARNING": 1, "ERROR": 1, "UNKNOWN": 1},
            })
            file.write_text("{}\ninvalid")
            malformed = self.run_cli("log-summary", file)
            self.assertEqual(malformed.returncode, 1)
            self.assertIn("line 2", malformed.stderr)


if __name__ == "__main__":
    unittest.main()
