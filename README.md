# fcyber

A local defensive security toolkit maintained by **flexEST**. It was inspired by the toolkit format of [NIVOS](https://github.com/theahmadov/NIVOS) and implemented independently.

## Requirements

Python 3.11 or newer. All commands use the Python standard library and run without administrator privileges or network access.

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

## Tests

```sh
python3 -m unittest discover -s tests
```
