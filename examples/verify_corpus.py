"""Check the corpus inventory, SHA-256 digests, and independently specified scan results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .corpus import verify_corpus
except ImportError:
    from corpus import verify_corpus


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="Generated or extracted synthetic corpus")
    args = parser.parse_args(argv)
    try:
        result = verify_corpus(args.destination)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Corpus verification failed: {exc}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
