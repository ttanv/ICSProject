"""Command-line entry point for the PCAP missing traffic augmentation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .enhancer import AugmentationConfig
from .missing_augmentor import MissingTrafficAugmentor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Augment Neo4j export with PCAP-only connections.")
    parser.add_argument("--base-cypher", type=Path, required=True, help="Path to the base neo4j_export.cypher file.")
    parser.add_argument("--output-cypher", type=Path, required=True, help="Path where the augmented Cypher will be written.")
    parser.add_argument("--pcap-dir", type=Path, required=True, help="Directory containing PCAP or PCAPNG files.")
    parser.add_argument("--cache", type=Path, default=Path("pcap_connection_index.pkl"), help="Optional cache file for the PCAP index.")
    parser.add_argument("--force-rebuild", action="store_true", help="Force rebuilding the PCAP index even if the cache exists.")
    parser.add_argument("--assets", type=Path, default=None, help="Optional path to assets.yaml for host/IP resolution.")
    parser.add_argument("--packet-limit", type=int, default=None, help="Optional cap on packets to process per PCAP file (for faster iteration).")
    parser.add_argument(
        "--streaming",
        action="store_true",
        help="Use streaming mode for large PCAP datasets. Processes files one at a time to reduce memory usage.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print aggregation counts without writing an augmented Cypher file.",
    )
    parser.add_argument(
        "--summary-progress",
        action="store_true",
        help="Show progress bars while computing the aggregation summary.",
    )
    parser.add_argument(
        "--summary-fast",
        action="store_true",
        help="Skip raw graph measurement for massive speedup (10-20x faster). Only shows post-aggregation counts.",
    )
    parser.add_argument(
        "--min-aggregation-threshold",
        type=int,
        default=2,
        help="Minimum number of unique ephemeral client ports required to aggregate connections (default: 2).",
    )

    # Correlation configuration
    parser.add_argument(
        "--min-correlation-confidence",
        type=float,
        default=0.5,
        help="Minimum confidence score (0.0-1.0) to accept a PCAP-to-telemetry correlation (default: 0.5).",
    )
    parser.add_argument(
        "--temporal-tolerance",
        type=float,
        default=60.0,
        help="Temporal tolerance in seconds for correlation time window matching (default: 60.0).",
    )
    parser.add_argument(
        "--require-temporal-overlap",
        action="store_true",
        help="Require PCAP packets to temporally overlap with telemetry time windows for correlation.",
    )
    parser.add_argument(
        "--disable-process-attribution",
        action="store_true",
        help="Disable generation of READ_REGISTER/WRITE_REGISTER relationships linking processes to Modbus registers.",
    )
    parser.add_argument(
        "--telemetry-attribution-only",
        action="store_true",
        help="Only attribute processes when telemetry evidence exists. Disables temporal/heuristic fallback.",
    )
    parser.add_argument(
        "--pcap-time-offset",
        type=float,
        default=0.0,
        help="Time offset in hours to apply to PCAP timestamps for timezone alignment. "
             "E.g., -3.0 converts PCAP from UTC+3 (Qatar) to UTC. Default: 0.0 (no offset).",
    )

    # Signal database configuration
    parser.add_argument(
        "--signal-db",
        type=Path,
        default=None,
        help="Path to DuckDB file for storing raw signal observations. "
             "If not specified, signal data is not stored (only lightweight reference nodes created in Neo4j).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = AugmentationConfig(
        base_cypher=args.base_cypher,
        output_cypher=args.output_cypher,
        pcap_directory=args.pcap_dir,
        asset_file=args.assets,
        cache_path=args.cache,
        force_rebuild_index=args.force_rebuild,
        packet_limit=args.packet_limit,
        min_aggregation_threshold=args.min_aggregation_threshold,
        # Correlation configuration
        min_correlation_confidence=args.min_correlation_confidence,
        temporal_tolerance_seconds=args.temporal_tolerance,
        require_temporal_overlap=args.require_temporal_overlap,
        enable_process_attribution=not args.disable_process_attribution,
        telemetry_attribution_only=args.telemetry_attribution_only,
        pcap_time_offset_seconds=args.pcap_time_offset * 3600.0,  # Convert hours to seconds
        # Signal database configuration
        signal_db_path=args.signal_db,
    )

    # Use streaming mode for large PCAP datasets
    if args.streaming:
        from .streaming_augmentor import StreamingAugmentor
        augmentor = StreamingAugmentor(config)
        node_count, rel_count = augmentor.run()
        print(f"Streaming augmentation completed. Added {node_count} virtual nodes and {rel_count} relationships.")
        return

    augmentor = MissingTrafficAugmentor(config)
    if args.summary_only:
        metrics = augmentor.summarize_aggregation(
            show_progress=args.summary_progress,
            fast=args.summary_fast,
        )
        print("=== Aggregation Summary ===")
        print(f"PCAP connections indexed: {metrics.total_connections}")
        print(f"Raw candidate relationships: {metrics.raw_relationships}")
        print(
            "Post-aggregation relationships: "
            f"{metrics.aggregated_relationships} "
            f"(modbus={metrics.modbus_relationships}, "
            f"monitor={metrics.http_monitor_relationships}, "
            f"collapsed={metrics.collapsed_relationships}, "
            f"individual={metrics.individual_relationships})"
        )
        print(f"Existing relationship updates: {metrics.existing_relationship_updates}")
        print(f"Relationships saved by aggregation: {metrics.relationships_saved}")
        print(f"Raw Asset nodes: {metrics.raw_asset_nodes}")
        print(f"Raw NetworkService nodes: {metrics.raw_service_nodes}")
        print(
            "Post-aggregation nodes: "
            f"{metrics.aggregated_node_count} "
            f"(assets={metrics.aggregated_asset_nodes}, "
            f"services={metrics.aggregated_service_nodes}, "
            f"registers={metrics.aggregated_register_nodes})"
        )
        print(f"NetworkService nodes saved by aggregation: {metrics.service_nodes_saved}")
        print(f"Final relationship statements (including updates): {metrics.final_relationship_count}")

        # Correlation statistics
        if metrics.correlation_attempts > 0:
            print("\n=== Correlation Statistics ===")
            corr_rate = 100.0 * metrics.successful_correlations / metrics.correlation_attempts
            print(f"PCAP connections attempted: {metrics.correlation_attempts}")
            print(f"Successful correlations: {metrics.successful_correlations} ({corr_rate:.1f}%)")
            print(f"Temporal matches: {metrics.temporal_matches}")
            if metrics.process_attributed_registers > 0:
                print(f"Process-attributed registers: {metrics.process_attributed_registers}")
        return
    node_count, rel_count = augmentor.run()
    print(f"Augmentation completed. Added {node_count} virtual nodes and {rel_count} relationships.")


if __name__ == "__main__":
    main()
