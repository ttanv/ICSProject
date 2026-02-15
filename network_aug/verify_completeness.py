#!/usr/bin/env python3
"""Verify correlation completeness - ensure we're not missing any correlations.

This script performs a brute-force check to find PCAP connections that SHOULD
have matched telemetry but didn't, identifying potential bugs in the indexing
or matching logic.

Usage:
    python -m network_aug.verify_completeness \
        --base-cypher graphs/base_25-12.cypher \
        --pcap-cache pcap_connection_index.pkl \
        --logged-hosts 192.168.42.12 192.168.42.20 192.168.42.21
"""

from __future__ import annotations

import argparse
import logging
import pickle
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .correlation import (
    CorrelationConfig,
    CorrelationEngine,
    TelemetryConnectionIndex,
    TelemetryAnchor,
)
from .cypher_reader import CypherConnectionExtractor, ExistingConnection
from .models import ConnectionKey, IndexedConnection, PacketRecord

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def load_pcap_connections(pcap_cache_path: Path) -> List[IndexedConnection]:
    """
    Load PCAP connections from cache, handling both old dict format and new object format.
    """
    with open(pcap_cache_path, "rb") as f:
        pcap_data = pickle.load(f)

    connections = []

    if isinstance(pcap_data, dict):
        # Old format: dict of canonical_id -> {origin: {...}, records: [...], ...}
        for canonical_id, conn_dict in pcap_data.items():
            origin_dict = conn_dict.get("origin", {})
            origin = ConnectionKey(
                src_ip=origin_dict.get("src_ip", ""),
                src_port=origin_dict.get("src_port", 0),
                dst_ip=origin_dict.get("dst_ip", ""),
                dst_port=origin_dict.get("dst_port", 0),
                protocol=origin_dict.get("protocol", "tcp"),
            )

            # Convert records - they might be dicts or PacketRecord objects
            records = []
            raw_records = conn_dict.get("records", [])
            for rec in raw_records:
                if isinstance(rec, PacketRecord):
                    records.append(rec)
                elif isinstance(rec, dict):
                    records.append(PacketRecord(
                        pcap_file=rec.get("pcap_file", ""),
                        packet_index=rec.get("packet_index", 0),
                        timestamp=rec.get("timestamp", 0),
                        size=rec.get("size", 0),
                        src_ip=rec.get("src_ip", ""),
                        dst_ip=rec.get("dst_ip", ""),
                        src_port=rec.get("src_port", 0),
                        dst_port=rec.get("dst_port", 0),
                        protocol=rec.get("protocol", "tcp"),
                        high_level_protocol=rec.get("high_level_protocol", ""),
                        ip_layer_index=rec.get("ip_layer_index", 0),
                        ip_layer_count=rec.get("ip_layer_count", 1),
                        src_mac=rec.get("src_mac", ""),
                        dst_mac=rec.get("dst_mac", ""),
                        tcp_flags=rec.get("tcp_flags", ""),
                        tcp_seq=rec.get("tcp_seq"),
                        tcp_ack=rec.get("tcp_ack"),
                        payload_len=rec.get("payload_len", 0),
                    ))

            conn = IndexedConnection(
                canonical_id=canonical_id,
                origin=origin,
                records=records,
                origin_timestamp=conn_dict.get("origin_timestamp", 0.0),
            )
            connections.append(conn)
    else:
        # New format: PCAPConnectionIndex object
        if hasattr(pcap_data, "connections"):
            connections = list(pcap_data.connections.values())
        else:
            raise ValueError(f"Unknown PCAP cache format: {type(pcap_data)}")

    return connections


@dataclass
class MissedCorrelation:
    """Details about a correlation that brute-force found but engine missed."""
    pcap_key: str
    pcap_canonical_id: str
    pcap_src_port: int
    pcap_timestamps: Tuple[float, float]  # (first, last)
    anchor_src_guid: str
    anchor_dst_guid: str
    anchor_session_ports: List[int]
    anchor_time_window: Tuple[Optional[float], Optional[float]]
    match_type: str
    likely_cause: str


@dataclass
class CompletenessReport:
    """Report on correlation completeness."""

    # PCAP statistics
    total_pcap_connections: int = 0
    pcap_from_logged_hosts: int = 0
    pcap_to_known_services: int = 0
    pcap_with_packets: int = 0

    # Telemetry statistics
    total_telemetry_connections: int = 0
    telemetry_with_session_ports: int = 0
    telemetry_with_timestamps: int = 0

    # Correlation results from engine
    engine_correlated_total: int = 0
    engine_session_port_exact: int = 0
    engine_session_port_match: int = 0
    engine_temporal: int = 0
    engine_no_candidates: int = 0
    engine_below_threshold: int = 0

    # Brute-force results
    bf_matched: int = 0
    bf_no_match: int = 0

    # Discrepancies
    missed_correlations: List[MissedCorrelation] = field(default_factory=list)
    false_positives: List[Dict] = field(default_factory=list)

    # Breakdown of legitimate non-matches
    no_match_reasons: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def print_report(self):
        print("\n" + "=" * 70)
        print("CORRELATION COMPLETENESS REPORT")
        print("=" * 70)

        print("\n┌─ PCAP Statistics ─────────────────────────────────────────────────┐")
        print(f"│  Total PCAP connections:     {self.total_pcap_connections:>10,}                        │")
        print(f"│  With packets:               {self.pcap_with_packets:>10,}                        │")
        print(f"│  From logged hosts:          {self.pcap_from_logged_hosts:>10,}                        │")
        print(f"│  To known service ports:     {self.pcap_to_known_services:>10,}                        │")
        print("└────────────────────────────────────────────────────────────────────┘")

        print("\n┌─ Telemetry Statistics ────────────────────────────────────────────┐")
        print(f"│  Total telemetry connections: {self.total_telemetry_connections:>9,}                        │")
        print(f"│  With session port metadata:  {self.telemetry_with_session_ports:>9,}                        │")
        print(f"│  With timestamp window:       {self.telemetry_with_timestamps:>9,}                        │")
        print("└────────────────────────────────────────────────────────────────────┘")

        print("\n┌─ Engine Correlation Results ──────────────────────────────────────┐")
        print(f"│  Total correlated:           {self.engine_correlated_total:>10,}                        │")
        print(f"│    - Session port (exact):   {self.engine_session_port_exact:>10,}                        │")
        print(f"│    - Session port (match):   {self.engine_session_port_match:>10,}                        │")
        print(f"│    - Temporal:               {self.engine_temporal:>10,}                        │")
        print(f"│  No candidates found:        {self.engine_no_candidates:>10,}                        │")
        print(f"│  Below threshold:            {self.engine_below_threshold:>10,}                        │")
        print("└────────────────────────────────────────────────────────────────────┘")

        if self.total_pcap_connections > 0:
            rate = (self.engine_correlated_total / self.total_pcap_connections) * 100
            print(f"\n  Overall correlation rate: {rate:.1f}%")

        print("\n┌─ Brute-Force Verification ────────────────────────────────────────┐")
        print(f"│  Brute-force matched:        {self.bf_matched:>10,}                        │")
        print(f"│  Brute-force no match:       {self.bf_no_match:>10,}                        │")
        print("└────────────────────────────────────────────────────────────────────┘")

        # The critical section
        print("\n" + "=" * 70)
        if self.missed_correlations:
            print(f"⚠️  MISSED CORRELATIONS DETECTED: {len(self.missed_correlations)}")
            print("=" * 70)
            print("\nThese PCAP connections SHOULD have matched telemetry but didn't:\n")
            for i, missed in enumerate(self.missed_correlations[:20]):
                print(f"  {i+1}. {missed.pcap_key}")
                print(f"      PCAP port: {missed.pcap_src_port}, times: {missed.pcap_timestamps}")
                print(f"      Anchor session_ports: {missed.anchor_session_ports}")
                print(f"      Anchor time_window: {missed.anchor_time_window}")
                print(f"      Match type: {missed.match_type}")
                print(f"      Likely cause: {missed.likely_cause}")
                print()
            if len(self.missed_correlations) > 20:
                print(f"  ... and {len(self.missed_correlations) - 20} more\n")
        else:
            print("✅ NO MISSED CORRELATIONS - Completeness verified!")
            print("=" * 70)

        if self.false_positives:
            print(f"\n⚠️  FALSE POSITIVES DETECTED: {len(self.false_positives)}")
            for i, fp in enumerate(self.false_positives[:10]):
                print(f"  {i+1}. {fp}")

        print("\n┌─ Legitimate Non-Match Reasons ────────────────────────────────────┐")
        for reason, count in sorted(self.no_match_reasons.items(), key=lambda x: -x[1]):
            print(f"│  {reason:<40} {count:>10,}         │")
        print("└────────────────────────────────────────────────────────────────────┘")


def brute_force_match(
    pcap_conn: IndexedConnection,
    anchors: List[TelemetryAnchor],
    tolerance_seconds: float = 60.0,
    pcap_time_offset: float = 0.0,
) -> Tuple[Optional[TelemetryAnchor], str, str]:
    """
    Brute-force check if this PCAP connection SHOULD match any telemetry anchor.

    This bypasses the index-based lookup to find matches that might be missed
    due to indexing bugs.

    Returns: (matching_anchor, match_type, failure_reason)
    """
    origin = pcap_conn.origin
    pcap_src_port = origin.src_port

    # Get PCAP time range
    if not pcap_conn.records:
        return None, "", "no_packets"

    pcap_first = min(p.timestamp for p in pcap_conn.records) + pcap_time_offset
    pcap_last = max(p.timestamp for p in pcap_conn.records) + pcap_time_offset

    candidates_checked = 0
    ip_matches = 0
    port_matches = 0
    protocol_matches = 0

    for anchor in anchors:
        akey = anchor.connection_key

        # Check IP match (either direction)
        forward_ip_match = (
            origin.src_ip == akey.src_ip and
            origin.dst_ip == akey.dst_ip
        )
        reverse_ip_match = (
            origin.src_ip == akey.dst_ip and
            origin.dst_ip == akey.src_ip
        )

        if not (forward_ip_match or reverse_ip_match):
            continue

        ip_matches += 1

        # Check service port match
        if forward_ip_match:
            port_match = (origin.dst_port == akey.dst_port)
        else:
            port_match = (origin.src_port == akey.dst_port)

        if not port_match:
            continue

        port_matches += 1

        # Check protocol
        if origin.protocol.lower() != akey.protocol.lower():
            continue

        protocol_matches += 1
        candidates_checked += 1

        # We have an IP/port/protocol match - now check correlation criteria

        # Check 1: Session port exact match
        if anchor.has_session_metadata():
            if pcap_src_port in anchor.session_ports:
                return anchor, "session_port_in_list", ""

        # Check 2: Temporal overlap
        first_seen, last_seen = anchor.time_window
        if first_seen is not None or last_seen is not None:
            window_start = (first_seen - tolerance_seconds) if first_seen else float("-inf")
            window_end = (last_seen + tolerance_seconds) if last_seen else float("inf")

            if pcap_last >= window_start and pcap_first <= window_end:
                return anchor, "temporal_overlap", ""

    # Build detailed reason
    if candidates_checked == 0:
        if ip_matches == 0:
            return None, "", "no_ip_match"
        elif port_matches == 0:
            return None, "", "ip_match_but_no_port_match"
        else:
            return None, "", "ip_port_match_but_protocol_mismatch"
    else:
        return None, "", "candidates_exist_but_no_temporal_or_session_match"


def diagnose_missed_correlation(
    pcap_conn: IndexedConnection,
    anchor: TelemetryAnchor,
    engine_stats_before: Dict[str, int],
    engine_stats_after: Dict[str, int],
    pcap_time_offset: float,
) -> str:
    """Try to determine WHY the engine missed this correlation."""
    origin = pcap_conn.origin
    akey = anchor.connection_key

    # Check if it was a candidate finding issue
    if engine_stats_after.get("no_candidates", 0) > engine_stats_before.get("no_candidates", 0):
        # Index lookup failed to find candidates
        # Check forward vs reverse
        forward = (origin.src_ip == akey.src_ip and origin.dst_ip == akey.dst_ip)
        if forward:
            return "INDEX_BUG: Forward lookup failed - check service_key construction"
        else:
            return "INDEX_BUG: Reverse lookup failed - check reverse_service_key construction"

    if engine_stats_after.get("below_threshold", 0) > engine_stats_before.get("below_threshold", 0):
        return "THRESHOLD: Candidates found but confidence too low"

    # Check session port issue
    if anchor.has_session_metadata():
        if origin.src_port not in anchor.session_ports:
            # Session metadata exists but port doesn't match
            pcap_first = min(p.timestamp for p in pcap_conn.records) + pcap_time_offset
            session_ts = anchor.session_timestamps[0] if anchor.session_timestamps else None
            if session_ts:
                time_diff = abs(pcap_first - session_ts)
                if time_diff > 60:
                    return f"TIMEZONE: Session port exists but timestamp diff={time_diff:.0f}s (check offset)"

    return "UNKNOWN: Need manual investigation"


def verify_completeness(
    pcap_connections: List[IndexedConnection],
    existing_connections: List[ExistingConnection],
    logged_hosts_ips: Set[str],
    known_service_ports: Set[int],
    config: CorrelationConfig,
) -> CompletenessReport:
    """
    Verify that all correlatable PCAP connections are being correlated.
    """
    report = CompletenessReport()

    # Build telemetry structures
    logger.info("Building telemetry index...")
    tele_index = TelemetryConnectionIndex(existing_connections)
    engine = CorrelationEngine(config=config)

    # Convert to anchors for brute-force checking
    anchors = [TelemetryAnchor.from_existing_connection(c) for c in existing_connections]

    report.total_telemetry_connections = len(existing_connections)
    report.telemetry_with_session_ports = sum(
        1 for a in anchors if a.has_session_metadata()
    )
    report.telemetry_with_timestamps = sum(
        1 for a in anchors if a.time_window[0] is not None or a.time_window[1] is not None
    )

    report.total_pcap_connections = len(pcap_connections)

    logger.info(f"Verifying {len(pcap_connections)} PCAP connections against {len(anchors)} telemetry anchors...")

    for i, pcap_conn in enumerate(pcap_connections):
        if (i + 1) % 1000 == 0:
            logger.info(f"  Progress: {i+1}/{len(pcap_connections)}")

        origin = pcap_conn.origin

        # Track statistics
        if pcap_conn.records:
            report.pcap_with_packets += 1

        if origin.src_ip in logged_hosts_ips:
            report.pcap_from_logged_hosts += 1

        if origin.dst_port in known_service_ports:
            report.pcap_to_known_services += 1

        # Get engine stats before
        stats_before = engine.get_statistics().copy()

        # Try correlation via normal engine
        correlated = engine.correlate(pcap_conn, tele_index)

        # Get engine stats after
        stats_after = engine.get_statistics()

        if correlated:
            report.engine_correlated_total += 1
            method = correlated.correlation_method
            if method == "session_port_exact":
                report.engine_session_port_exact += 1
            elif method == "session_port_match":
                report.engine_session_port_match += 1
            elif "temporal" in method:
                report.engine_temporal += 1
        else:
            # Track why engine failed
            if stats_after["no_candidates"] > stats_before["no_candidates"]:
                report.engine_no_candidates += 1
            elif stats_after["below_threshold"] > stats_before["below_threshold"]:
                report.engine_below_threshold += 1

        # Now do brute-force check
        bf_anchor, bf_match_type, bf_reason = brute_force_match(
            pcap_conn,
            anchors,
            config.temporal_tolerance_seconds,
            config.pcap_time_offset_seconds,
        )

        if bf_anchor is not None:
            report.bf_matched += 1

            if correlated is None:
                # MISSED CORRELATION!
                pcap_times = (
                    min(p.timestamp for p in pcap_conn.records) if pcap_conn.records else 0,
                    max(p.timestamp for p in pcap_conn.records) if pcap_conn.records else 0,
                )

                likely_cause = diagnose_missed_correlation(
                    pcap_conn, bf_anchor, stats_before, stats_after,
                    config.pcap_time_offset_seconds
                )

                report.missed_correlations.append(MissedCorrelation(
                    pcap_key=f"{origin.src_ip}:{origin.src_port} -> {origin.dst_ip}:{origin.dst_port}",
                    pcap_canonical_id=pcap_conn.canonical_id,
                    pcap_src_port=origin.src_port,
                    pcap_timestamps=pcap_times,
                    anchor_src_guid=bf_anchor.src_guid,
                    anchor_dst_guid=bf_anchor.dst_guid,
                    anchor_session_ports=list(bf_anchor.session_ports),
                    anchor_time_window=bf_anchor.time_window,
                    match_type=bf_match_type,
                    likely_cause=likely_cause,
                ))
        else:
            report.bf_no_match += 1
            report.no_match_reasons[bf_reason] += 1

            # Check for false positive (engine matched but brute-force didn't)
            if correlated is not None:
                report.false_positives.append({
                    "pcap_key": f"{origin.src_ip}:{origin.src_port} -> {origin.dst_ip}:{origin.dst_port}",
                    "engine_method": correlated.correlation_method,
                    "engine_confidence": correlated.confidence,
                })

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Verify correlation completeness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python -m network_aug.verify_completeness \\
        --base-cypher graphs/base_25-12.cypher \\
        --pcap-cache pcap_connection_index.pkl

    python -m network_aug.verify_completeness \\
        --base-cypher graphs/base_25-12.cypher \\
        --pcap-cache pcap_connection_index.pkl \\
        --tolerance 120 \\
        --pcap-offset -10800
        """
    )
    parser.add_argument(
        "--base-cypher", type=Path, required=True,
        help="Base Cypher export file with telemetry"
    )
    parser.add_argument(
        "--pcap-cache", type=Path, required=True,
        help="PCAP index cache file (pickle)"
    )
    parser.add_argument(
        "--logged-hosts", type=str, nargs="+",
        default=["192.168.42.12", "192.168.42.20", "192.168.42.21", "192.168.42.22"],
        help="IPs of hosts with telemetry (default: EWS, SCADA, HMI, HISTORIAN)"
    )
    parser.add_argument(
        "--service-ports", type=int, nargs="+",
        default=[22, 80, 443, 502, 8080, 44818],
        help="Known service ports (default: SSH, HTTP, HTTPS, Modbus, HTTP-alt, EtherNet/IP)"
    )
    parser.add_argument(
        "--tolerance", type=float, default=60.0,
        help="Temporal tolerance in seconds (default: 60)"
    )
    parser.add_argument(
        "--pcap-offset", type=float, default=0.0,
        help="PCAP timestamp offset in seconds (e.g., -10800 for UTC+3 to UTC)"
    )
    parser.add_argument(
        "--min-confidence", type=float, default=0.5,
        help="Minimum correlation confidence (default: 0.5)"
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Limit number of PCAP connections to check (for testing)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output"
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load PCAP index
    logger.info(f"Loading PCAP index from {args.pcap_cache}")
    try:
        pcap_connections = load_pcap_connections(args.pcap_cache)
    except FileNotFoundError:
        logger.error(f"PCAP cache not found: {args.pcap_cache}")
        logger.error("Run the augmentor with --cache flag first to generate it")
        return 1
    except Exception as e:
        logger.error(f"Failed to load PCAP cache: {e}")
        return 1

    logger.info(f"Loaded {len(pcap_connections)} PCAP connections")

    if args.limit:
        pcap_connections = pcap_connections[:args.limit]
        logger.info(f"Limited to {len(pcap_connections)} connections for testing")

    # Load existing connections from base Cypher
    logger.info(f"Loading telemetry from {args.base_cypher}")
    try:
        extractor = CypherConnectionExtractor(args.base_cypher)
        existing_connections = extractor.load_connections()
    except FileNotFoundError:
        logger.error(f"Base Cypher file not found: {args.base_cypher}")
        return 1

    logger.info(f"Loaded {len(existing_connections)} telemetry connections")

    # Build config
    config = CorrelationConfig(
        temporal_tolerance_seconds=args.tolerance,
        min_confidence=args.min_confidence,
        pcap_time_offset_seconds=args.pcap_offset,
    )

    logged_ips = set(args.logged_hosts)
    service_ports = set(args.service_ports)

    # Run verification
    logger.info("Starting completeness verification...")
    report = verify_completeness(
        pcap_connections,
        existing_connections,
        logged_ips,
        service_ports,
        config,
    )

    report.print_report()

    # Exit code
    if report.missed_correlations:
        logger.warning(f"Found {len(report.missed_correlations)} missed correlations!")
        return 1
    elif report.false_positives:
        logger.warning(f"Found {len(report.false_positives)} false positives!")
        return 1
    else:
        logger.info("Completeness verification passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
