# fcyber



## Requirements

Python 3.11 or newer. All commands use the Python standard library and run without administrator privileges. Hostname resolution uses your system resolver. Socket inspection requires Linux.

## Usage

Run from the repository directory.

```sh
python3 fcyber.py --help
python3 fcyber.py system
python3 fcyber.py password --length 32
python3 fcyber.py hash README.md
python3 fcyber.py headers response-headers.txt
```

Pass `--expect` followed by a trusted 64-character SHA-256 digest to check a file. A mismatch returns exit status 1.

For `headers`, supply a plain-text HTTP response header block, optionally starting with a status line such as `HTTP/1.1 200 OK`. The command reports the observed values of five common security headers as JSON. An empty list means the header was absent. This report checks presence and leaves policy interpretation to the reader.

## Defensive workflows

| Command | Use |
| --- | --- |
| `inventory create DIRECTORY MANIFEST` | Record SHA-256 hashes for regular files. Symlinks and Git metadata are skipped. |
| `inventory verify DIRECTORY MANIFEST` | Report added, removed, and changed paths as JSON. Exit status 1 indicates differences or a command error. |
| `bindings [--non-loopback]` | Inspect the local Linux network namespace for listening TCP sockets and bound UDP sockets. |
| `resolve HOST` | Report IPv4 and IPv6 addresses from the system resolver. |
| `log-summary FILE [--fail-on-error]` | Count severity levels in a JSON Lines log without printing messages. The flag returns exit status 1 for error or critical entries. |

Keep each inventory manifest outside the directory it monitors. A manifest is created only if the destination does not already exist.

```sh
python3 fcyber.py inventory create ./project ../project-baseline.json
python3 fcyber.py inventory verify ./project ../project-baseline.json
python3 fcyber.py bindings --non-loopback
python3 fcyber.py resolve localhost
python3 fcyber.py log-summary app.jsonl --fail-on-error
```

## Tests

```sh
python3 -m unittest discover -s tests
```
