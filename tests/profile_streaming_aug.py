"""Profile network_aug streaming augmentation on a small dataset.

Runs the streaming augmentor against an existing base graph and reports
per-stage wall-clock, DuckDB time, and RSS peaks. Non-invasive: monkey-patches
methods at runtime, no source changes.

Usage:
    python -m tests.profile_streaming_aug \
        --base-cypher paper_graphs_1hr/Pipedream/base_Pipedream.cypher \
        --pcap-dir   pcap_traffic/extracted_1hr/Pipedream \
        --assets     ICSGraph/Collection/assets.yaml \
        --output     /tmp/profile_pipedream_1hr.json
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List

import psutil

from network_aug.enhancer import AugmentationConfig
from network_aug import streaming as streaming_mod
from network_aug import streaming_augmentor as sa_mod
from network_aug import missing_augmentor as ma_mod
from network_aug import signal_db as sdb_mod
from network_aug.protocols import modbus_handler as modbus_mod
from network_aug.protocols import mqtt_handler as mqtt_mod
from network_aug.protocols import opcua_handler as opcua_mod
from network_aug.protocols import http_monitor_handler as http_mod


PROC = psutil.Process(os.getpid())
START = time.perf_counter()


def now_rss_mb() -> float:
    return PROC.memory_info().rss / (1024 * 1024)


class Stat:
    __slots__ = ("name", "calls", "wall", "rss_in_max", "rss_out_max")

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0
        self.wall = 0.0
        self.rss_in_max = 0.0
        self.rss_out_max = 0.0


STATS: Dict[str, Stat] = {}
TIMELINE: List[Dict[str, Any]] = []


def _record(name: str) -> Stat:
    if name not in STATS:
        STATS[name] = Stat(name)
    return STATS[name]


def time_method(label: str, log_each: bool = False):
    """Decorator to wrap a bound method or function with timing + RSS sampling."""
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            stat = _record(label)
            rss_in = now_rss_mb()
            t0 = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                dt = time.perf_counter() - t0
                rss_out = now_rss_mb()
                stat.calls += 1
                stat.wall += dt
                stat.rss_in_max = max(stat.rss_in_max, rss_in)
                stat.rss_out_max = max(stat.rss_out_max, rss_out)
                if log_each:
                    elapsed = time.perf_counter() - START
                    TIMELINE.append({
                        "t_elapsed": round(elapsed, 3),
                        "label": label,
                        "dt_s": round(dt, 4),
                        "rss_in_mb": round(rss_in, 1),
                        "rss_out_mb": round(rss_out, 1),
                    })
                    print(f"  [{elapsed:7.1f}s] {label:<50s} dt={dt:7.3f}s rss={rss_in:6.0f}->{rss_out:6.0f}MB")
        return wrapper
    return decorator


PEAK_RSS = [0.0]
PEAK_STOP = threading.Event()


def _rss_sampler() -> None:
    while not PEAK_STOP.wait(0.5):
        rss = now_rss_mb()
        if rss > PEAK_RSS[0]:
            PEAK_RSS[0] = rss


def install_patches() -> None:
    # ---- Stage 1: streaming PCAP index (Pass 1) ----
    streaming_mod.StreamingPCAPIndex.build = time_method("01_pcap_index.build")(
        streaming_mod.StreamingPCAPIndex.build
    )
    streaming_mod.StreamingPCAPIndex._run_stats_worker = time_method(
        "01a_pcap_index._run_stats_worker", log_each=True
    )(streaming_mod.StreamingPCAPIndex._run_stats_worker)
    streaming_mod.StreamingPCAPIndex._merge_file_stats = time_method(
        "01b_pcap_index._merge_file_stats"
    )(streaming_mod.StreamingPCAPIndex._merge_file_stats)

    # ---- Stage 2: candidate selection ----
    sa_mod.StreamingAugmentor._select_candidate_connection_ids = time_method(
        "02_select_candidates"
    )(sa_mod.StreamingAugmentor._select_candidate_connection_ids)

    # ---- Stage 3: candidate materialization (Pass 2) ----
    sa_mod.StreamingAugmentor._materialize_candidate_connections = time_method(
        "03_materialize_candidates"
    )(sa_mod.StreamingAugmentor._materialize_candidate_connections)
    sa_mod.StreamingAugmentor._run_materialization_worker = time_method(
        "03a_materialize_one_pcap", log_each=True
    )(sa_mod.StreamingAugmentor._run_materialization_worker)

    # ---- Stage 4: graph artifact build ----
    ma_mod.MissingTrafficAugmentor._build_artifacts = time_method(
        "04_build_artifacts"
    )(ma_mod.MissingTrafficAugmentor._build_artifacts)
    ma_mod.MissingTrafficAugmentor._augment_existing_relationships = time_method(
        "04a_augment_existing"
    )(ma_mod.MissingTrafficAugmentor._augment_existing_relationships)

    # Per-protocol handler.build_artifacts
    modbus_mod.ModbusProtocolHandler.build_artifacts = time_method(
        "04b_protocol_modbus"
    )(modbus_mod.ModbusProtocolHandler.build_artifacts)
    http_mod.HttpMonitorHandler.build_artifacts = time_method(
        "04c_protocol_http"
    )(http_mod.HttpMonitorHandler.build_artifacts)
    mqtt_mod.MqttProtocolHandler.build_artifacts = time_method(
        "04d_protocol_mqtt"
    )(mqtt_mod.MqttProtocolHandler.build_artifacts)
    opcua_mod.OpcUaProtocolHandler.build_artifacts = time_method(
        "04e_protocol_opcua"
    )(opcua_mod.OpcUaProtocolHandler.build_artifacts)

    # Modbus per-group compute (forked workers; only main-process calls counted in dict-mode)
    ma_mod.MissingTrafficAugmentor._compute_modbus_group_payload = time_method(
        "04b1_modbus_compute_group"
    )(ma_mod.MissingTrafficAugmentor._compute_modbus_group_payload)
    ma_mod.MissingTrafficAugmentor._apply_modbus_group_payload = time_method(
        "04b2_modbus_apply_group"
    )(ma_mod.MissingTrafficAugmentor._apply_modbus_group_payload)
    ma_mod.MissingTrafficAugmentor._collect_modbus_registers = time_method(
        "04b3_modbus_collect_registers"
    )(ma_mod.MissingTrafficAugmentor._collect_modbus_registers)
    ma_mod.MissingTrafficAugmentor._collect_modbus_signals = time_method(
        "04b4_modbus_collect_signals"
    )(ma_mod.MissingTrafficAugmentor._collect_modbus_signals)

    # ---- Stage 5: write output ----
    ma_mod.MissingTrafficAugmentor._write_output = time_method(
        "05_write_output"
    )(ma_mod.MissingTrafficAugmentor._write_output)

    # ---- DuckDB write hot paths ----
    sdb_mod.SignalDatabase.insert_tuples_fast = time_method(
        "duck_insert_tuples_fast"
    )(sdb_mod.SignalDatabase.insert_tuples_fast)
    sdb_mod.SignalDatabase.insert_batch = time_method(
        "duck_insert_batch"
    )(sdb_mod.SignalDatabase.insert_batch)
    sdb_mod.SignalDatabase.update_write_acknowledgment = time_method(
        "duck_update_write_ack"
    )(sdb_mod.SignalDatabase.update_write_acknowledgment)


def report(out_path: Path) -> None:
    total = sum(STATS[k].wall for k in STATS if k.startswith(("01_", "02_", "03_", "04_", "05_")))

    rows = sorted(STATS.values(), key=lambda s: s.name)
    print()
    print("=" * 100)
    print(f"{'Stage':<50s} {'Calls':>8s} {'Wall(s)':>10s} {'%':>6s} {'RSS in':>10s} {'RSS out':>10s}")
    print("-" * 100)
    for s in rows:
        pct = (s.wall / total * 100) if total > 0 else 0.0
        print(f"{s.name:<50s} {s.calls:>8d} {s.wall:>10.2f} {pct:>5.1f}% {s.rss_in_max:>9.0f}M {s.rss_out_max:>9.0f}M")
    print("-" * 100)
    print(f"{'TOTAL (top-level stages)':<50s} {'':>8s} {total:>10.2f}")
    print(f"{'Peak RSS (sampled at 0.5s)':<50s} {'':>8s} {PEAK_RSS[0]:>10.0f} MB")
    print("=" * 100)

    out_path.write_text(json.dumps({
        "total_top_level_s": total,
        "peak_rss_mb": PEAK_RSS[0],
        "stages": {
            s.name: {
                "calls": s.calls,
                "wall_s": round(s.wall, 4),
                "pct_of_total": round((s.wall / total * 100) if total > 0 else 0, 2),
                "rss_in_mb": round(s.rss_in_max, 1),
                "rss_out_mb": round(s.rss_out_max, 1),
            } for s in rows
        },
        "timeline": TIMELINE,
    }, indent=2))
    print(f"\nWrote {out_path}")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--base-cypher", required=True, type=Path)
    p.add_argument("--output-cypher", type=Path, default=Path("/tmp/profile_aug.cypher"))
    p.add_argument("--pcap-dir", required=True, type=Path)
    p.add_argument("--assets", required=True, type=Path)
    p.add_argument("--signal-db", type=Path, default=Path("/tmp/profile_signals.duckdb"))
    p.add_argument("--cache", type=Path, default=Path("/tmp/profile_pcap_index.pkl"))
    p.add_argument("--output", type=Path, default=Path("/tmp/profile_streaming_aug.json"))
    args = p.parse_args()

    # Wipe stale outputs so we measure cold runs
    for stale in (args.output_cypher, args.signal_db, Path(str(args.signal_db) + ".wal"), args.cache):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    install_patches()

    # Background RSS sampler
    sampler = threading.Thread(target=_rss_sampler, daemon=True)
    sampler.start()

    config = AugmentationConfig(
        base_cypher=args.base_cypher,
        output_cypher=args.output_cypher,
        pcap_directory=args.pcap_dir,
        asset_file=args.assets,
        cache_path=args.cache,
        force_rebuild_index=True,
        signal_db_path=args.signal_db,
    )

    print(f"[{time.perf_counter() - START:7.1f}s] Starting profiled streaming augmentation")
    print(f"  base : {args.base_cypher}")
    print(f"  pcaps: {args.pcap_dir}")
    print(f"  db   : {args.signal_db}")

    from network_aug.streaming_augmentor import StreamingAugmentor
    aug = StreamingAugmentor(config)
    nodes, rels = aug.run()

    PEAK_STOP.set()
    sampler.join(timeout=2)

    print(f"\n[{time.perf_counter() - START:7.1f}s] Done. nodes={nodes} rels={rels}")
    report(args.output)


if __name__ == "__main__":
    main()
