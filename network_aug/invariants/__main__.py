"""CLI entry point: python -m network_aug.invariants"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from . import InvariantConfig, mine_invariants


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract process invariants from baseline ICS signal data."
    )
    parser.add_argument(
        "--signal-db",
        type=Path,
        required=True,
        help="Path to DuckDB signal database.",
    )
    parser.add_argument(
        "--st-file",
        type=Path,
        default=None,
        help="Optional IEC 61131-3 Structured Text file for state-aware mode.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("invariants.json"),
        help="Output JSON file path (default: invariants.json).",
    )
    parser.add_argument(
        "--baseline-hours",
        type=float,
        default=None,
        help="Use first N hours of data as baseline (default: all data).",
    )
    parser.add_argument(
        "--register-offset",
        type=int,
        default=0,
        help="Offset for AT address -> Modbus register mapping (default: 0).",
    )
    parser.add_argument(
        "--correlation-threshold",
        type=float,
        default=0.7,
        help="Minimum |r| for inter-register correlations (default: 0.7).",
    )
    parser.add_argument(
        "--min-observations",
        type=int,
        default=10,
        help="Minimum observations per register (default: 10).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(name)s: %(message)s",
    )

    config = InvariantConfig(
        signal_db=args.signal_db,
        st_file=args.st_file,
        output=args.output,
        baseline_hours=args.baseline_hours,
        register_offset=args.register_offset,
        correlation_threshold=args.correlation_threshold,
        min_observations=args.min_observations,
    )

    result = mine_invariants(config)

    config.output.write_text(result.to_json())
    print(
        f"Wrote {len(result.invariants)} invariants to {config.output} "
        f"({result.total_observations_used} observations used)"
    )


if __name__ == "__main__":
    main()
