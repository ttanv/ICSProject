"""Dedupe a *_signals.duckdb by emitting a new DB with byte-identical rows collapsed.

Background: some pcap captures (notably the BlackEnergy FT testbed run) include
SPAN/mirror duplicates where the same Ethernet frame appears twice with the same
nanosecond timestamp. That inflates obs_count, confidence scores, and CUSUM
calibration without changing min/max/correlation values. Rather than re-running
pcap extraction with a frame-level dedupe, this tool collapses already-collected
DBs in a single SELECT DISTINCT pass.

Schema-agnostic: works for any signal_observations table (Modbus, MQTT, OPC UA)
because it relies only on full-row equality.

Usage:
    python -m invariantExperiments.dedupe_signal_db INPUT.duckdb OUTPUT.duckdb
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional


def dedupe_signal_db(
    *,
    input_path: Path,
    output_path: Path,
    force: bool = False,
) -> dict[str, int]:
    """Copy input_path's signal_observations table to output_path, deduplicating.

    Returns a small report dict with row counts.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"input does not exist: {input_path}")
    if output_path.exists():
        if not force:
            raise FileExistsError(
                f"refusing to overwrite {output_path} (pass --force to overwrite)"
            )
        output_path.unlink()

    try:
        import duckdb
    except ImportError as exc:
        raise ImportError(
            "DuckDB is required for dedupe_signal_db. "
            "Install it with: pip install duckdb"
        ) from exc

    src = duckdb.connect(str(input_path), read_only=True)
    try:
        tables = {row[0] for row in src.execute("SHOW TABLES").fetchall()}
        if "signal_observations" not in tables:
            raise ValueError(
                f"{input_path}: missing signal_observations table"
            )

        before = int(src.execute(
            "SELECT COUNT(*) FROM signal_observations"
        ).fetchone()[0])
    finally:
        src.close()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    out = duckdb.connect(str(output_path))
    try:
        # ATTACH does not accept prepared-statement parameters in DuckDB; inline
        # the path with single-quote escaping.
        attach_path = str(input_path).replace("'", "''")
        out.execute(f"ATTACH '{attach_path}' AS src (READ_ONLY)")
        out.execute(
            "CREATE TABLE signal_observations AS "
            "SELECT DISTINCT * FROM src.signal_observations"
        )
        out.execute("DETACH src")

        after = int(out.execute(
            "SELECT COUNT(*) FROM signal_observations"
        ).fetchone()[0])
    finally:
        out.close()

    return {
        "input_rows": before,
        "output_rows": after,
        "removed_rows": before - after,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Dedupe a signal DuckDB by collapsing byte-identical rows. "
            "Works for Modbus, MQTT, and OPC UA signal schemas without "
            "any protocol-specific configuration."
        )
    )
    parser.add_argument("input", type=Path, help="Path to the input *_signals.duckdb file.")
    parser.add_argument("output", type=Path, help="Path to write the deduped *_signals.duckdb file.")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists.",
    )
    return parser.parse_args()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args()
    try:
        report = dedupe_signal_db(
            input_path=args.input,
            output_path=args.output,
            force=args.force,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ratio = (
        report["input_rows"] / report["output_rows"]
        if report["output_rows"] > 0
        else 0.0
    )
    print(
        f"{args.input} -> {args.output}: "
        f"{report['input_rows']:,} -> {report['output_rows']:,} rows "
        f"({report['removed_rows']:,} removed, {ratio:.4f}x dupe factor)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
