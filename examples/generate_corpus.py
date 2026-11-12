"""Create a new, deterministic synthetic corpus with a manifest of expected results."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from .corpus import generate_corpus
except ImportError:
    from corpus import generate_corpus


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New directory; existing paths are refused")
    args = parser.parse_args(argv)
    try:
        manifest = generate_corpus(args.destination)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Corpus generation failed: {exc}\n")
    print(
        f"Created {manifest['corpus_id']} with {len(manifest['cases'])} cases in {args.destination}"
    )
    print("Synthetic data only. Deliberately malformed records are part of the expected results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
