"""CLI entry point for GECO-style train/score workflows."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from .export import write_alert_cypher
from .scorer import GecoScoreConfig, score_geco
from .trainer import GecoTrainConfig, train_geco


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train and score GECO-style state-transition anomaly detectors."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Train GECO models from baseline signal data.")
    train_parser.add_argument("--signal-db", type=Path, required=True, help="Path to the DuckDB signal database.")
    train_parser.add_argument("--output", type=Path, default=Path("geco_model.json"), help="Output model JSON.")
    train_parser.add_argument("--baseline-hours", type=float, default=None, help="Use only the first N hours for training.")
    train_parser.add_argument("--min-observations", type=int, default=10, help="Minimum raw observations per signal.")
    train_parser.add_argument("--min-rows", type=int, default=12, help="Minimum aligned rows required to fit a model.")
    train_parser.add_argument("--max-function-length", type=int, default=3, help="Maximum number of predictor signals per template.")
    train_parser.add_argument("--candidate-limit", type=int, default=8, help="Top ranked candidate predictors to consider per target.")
    train_parser.add_argument("--fit-ratio", type=float, default=0.8, help="Fraction of aligned rows used for fitting each template.")
    train_parser.add_argument("--scale-factor", type=float, default=1.5, help="CUSUM scale factor S from the paper.")
    train_parser.add_argument("--growth-factor", type=float, default=1.0, help="CUSUM growth factor G from the paper.")
    train_parser.add_argument(
        "--candidate-invariants",
        type=Path,
        default=None,
        help="Optional invariants JSON whose correlation graph is used to prioritize predictor search.",
    )
    train_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")

    score_parser = subparsers.add_parser("score", help="Score a signal database against a trained GECO model.")
    score_parser.add_argument("--signal-db", type=Path, required=True, help="Path to the DuckDB signal database.")
    score_parser.add_argument("--model", type=Path, required=True, help="Path to a GECO model JSON file.")
    score_parser.add_argument("--output", type=Path, default=Path("geco_alerts.json"), help="Output alerts JSON.")
    score_parser.add_argument("--emit-cypher", type=Path, default=None, help="Optional Cypher file for Neo4j import.")
    score_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(levelname)s: %(name)s: %(message)s",
    )

    if args.command == "train":
        config = GecoTrainConfig(
            signal_db=args.signal_db,
            output=args.output,
            baseline_hours=args.baseline_hours,
            min_observations=args.min_observations,
            min_rows=args.min_rows,
            max_function_length=args.max_function_length,
            candidate_limit=args.candidate_limit,
            fit_ratio=args.fit_ratio,
            scale_factor=args.scale_factor,
            growth_factor=args.growth_factor,
            candidate_invariants=args.candidate_invariants,
        )
        result = train_geco(config)
        print(f"Wrote {len(result.models)} GECO models to {config.output}")
        return

    if args.command == "score":
        config = GecoScoreConfig(
            signal_db=args.signal_db,
            model=args.model,
            output=args.output,
        )
        result = score_geco(config)
        if args.emit_cypher is not None:
            write_alert_cypher(result=result, output_path=args.emit_cypher)
            print(
                f"Wrote {len(result.alerts)} GECO alerts to {config.output} "
                f"and Cypher to {args.emit_cypher}"
            )
        else:
            print(f"Wrote {len(result.alerts)} GECO alerts to {config.output}")
        return

    raise AssertionError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    main()
