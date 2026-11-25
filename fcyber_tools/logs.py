"""Summarize saved JSON Lines logs without including message contents."""

from collections import Counter
import json


def summarize(args):
    levels = Counter()
    with args.file.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except ValueError as error:
                raise ValueError(f"Invalid JSON on line {number}") from error
            if not isinstance(record, dict):
                raise ValueError(f"Expected a JSON object on line {number}")
            level = record.get("level", "")
            level = level.upper() if isinstance(level, str) else ""
            if level == "WARN":
                level = "WARNING"
            if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
                level = "UNKNOWN"
            levels[level] += 1
    print(json.dumps({"records": sum(levels.values()), "levels": dict(levels)}, indent=2))
    return int(args.fail_on_error and (levels["ERROR"] + levels["CRITICAL"] > 0))
