"""Test that StreamingPCAPIndex spill mode preserves merge semantics.

The pass-1 worker writes per-PCAP ConnectionStats to disk shards. We must
ensure that:
  - iter_merged_stats() across N shards == single-dict merge of the same
    partial_stats inputs.
  - iter_shards() yields exactly the per-PCAP dicts that were written.
  - In spill mode the index never builds self._stats (memory invariant).

The test seeds three synthetic partial_stats dicts, simulates two paths:
  1. Legacy in-memory: a fresh ConnectionStats per cid, repeatedly .merge().
  2. New on-disk: write each as a shard, call iter_merged_stats().
And asserts the produced ConnectionStats are field-equivalent.
"""
from __future__ import annotations

import pickle
import tempfile
from copy import deepcopy
from pathlib import Path

from network_aug.models import ConnectionKey, PacketRecord
from network_aug.streaming import ConnectionStats, StreamingPCAPIndex


def _make_packet(
    *,
    ts: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    pcap: str,
    payload: int = 0,
    modbus_fn: int | None = None,
    modbus_unit: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        pcap_file=pcap,
        packet_index=0,
        timestamp=ts,
        size=64 + payload,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="tcp",
        high_level_protocol="MODBUS" if modbus_fn else "UNKNOWN",
        ip_layer_index=0,
        ip_layer_count=1,
        src_mac="aa:bb:cc:dd:ee:ff",
        dst_mac="11:22:33:44:55:66",
        payload_len=payload,
        modbus_function=modbus_fn,
        modbus_unit_id=modbus_unit,
    )


def _seed_stats(canonical_id: str, packets: list[PacketRecord]) -> ConnectionStats:
    """Build a ConnectionStats by replaying packets through add_packet."""
    first = packets[0]
    key = ConnectionKey(
        src_ip=first.src_ip, src_port=first.src_port,
        dst_ip=first.dst_ip, dst_port=first.dst_port,
        protocol=first.protocol,
    )
    stats = ConnectionStats(
        canonical_id=canonical_id,
        origin=key,
        origin_timestamp=first.timestamp,
    )
    for pkt in packets:
        stats.add_packet(pkt)
    return stats


def _fields_to_compare(stats: ConnectionStats) -> dict:
    """Return a dict of comparable scalar/set fields for equivalence checks."""
    return {
        "canonical_id": stats.canonical_id,
        "packet_count": stats.packet_count,
        "forward_bytes": stats.forward_bytes,
        "reverse_bytes": stats.reverse_bytes,
        "first_seen": stats.first_seen,
        "last_seen": stats.last_seen,
        "packets_with_payload": stats.packets_with_payload,
        "total_payload_bytes": stats.total_payload_bytes,
        "protocols_seen": set(stats.protocols_seen),
        "high_level_protocol": stats.high_level_protocol,
        "modbus_function_codes": set(stats.modbus_function_codes),
        "modbus_unit_ids": set(stats.modbus_unit_ids),
        "modbus_transaction_count": stats.modbus_transaction_count,
        "client_ports_seen": set(stats.client_ports_seen),
        "pcap_files": set(stats.pcap_files),
        "origin_src_ip": stats.origin.src_ip,
        "origin_dst_ip": stats.origin.dst_ip,
        "origin_dst_port": stats.origin.dst_port,
        "origin_timestamp": stats.origin_timestamp,
    }


def test_spill_merge_matches_inmemory_merge(tmp_path: Path) -> None:
    """3 shards × 2 cids: spill-then-merge equals direct-merge in-memory."""
    cid_a = "conn_a"
    cid_b = "conn_b"

    # Shard 1: packets for both connections at t=1.0
    shard1 = {
        cid_a: _seed_stats(cid_a, [
            _make_packet(ts=1.0, src_ip="10.0.0.1", src_port=4001,
                         dst_ip="10.0.0.2", dst_port=502,
                         pcap="a.pcap", modbus_fn=3, modbus_unit=1, payload=12),
            _make_packet(ts=1.1, src_ip="10.0.0.2", src_port=502,
                         dst_ip="10.0.0.1", dst_port=4001,
                         pcap="a.pcap", payload=12),
        ]),
        cid_b: _seed_stats(cid_b, [
            _make_packet(ts=1.5, src_ip="10.0.0.1", src_port=4001,
                         dst_ip="10.0.0.3", dst_port=502,
                         pcap="a.pcap", modbus_fn=3, modbus_unit=2, payload=8),
        ]),
    }
    # Shard 2: only cid_a, later timestamps
    shard2 = {
        cid_a: _seed_stats(cid_a, [
            _make_packet(ts=2.0, src_ip="10.0.0.1", src_port=4002,
                         dst_ip="10.0.0.2", dst_port=502,
                         pcap="b.pcap", modbus_fn=6, modbus_unit=1, payload=4),
            _make_packet(ts=2.1, src_ip="10.0.0.2", src_port=502,
                         dst_ip="10.0.0.1", dst_port=4002,
                         pcap="b.pcap", payload=4),
        ]),
    }
    # Shard 3: cid_b again, even later
    shard3 = {
        cid_b: _seed_stats(cid_b, [
            _make_packet(ts=3.0, src_ip="10.0.0.1", src_port=4003,
                         dst_ip="10.0.0.3", dst_port=502,
                         pcap="c.pcap", modbus_fn=3, modbus_unit=2, payload=16),
        ]),
    }
    shards = [shard1, shard2, shard3]

    # --- Path 1: legacy in-memory merge ---
    expected: dict[str, ConnectionStats] = {}
    for shard in shards:
        for cid, partial in shard.items():
            partial_copy = deepcopy(partial)
            if cid in expected:
                expected[cid].merge(partial_copy)
            else:
                expected[cid] = partial_copy

    # --- Path 2: spill to disk, iter_merged_stats() ---
    index = StreamingPCAPIndex(tmp_path)
    index.configure_stats_spill(shard_dir=tmp_path / "spill")
    for shard in shards:
        # Bypass the worker: pretend the worker handed back this dict.
        index._merge_file_stats(deepcopy(shard), processed_packets=sum(len(s._sample_packets) for s in shard.values()))

    assert index.spill_enabled, "spill mode should be active"
    assert len(index.stats_shard_paths) == len(shards), "one shard file per call"
    assert not getattr(index, "_stats", {}), "in-memory dict must be empty in spill mode"

    actual = {stats.canonical_id: stats for stats in index.iter_merged_stats()}

    # Each cid yielded exactly once
    assert set(actual.keys()) == set(expected.keys())

    for cid in expected:
        e = _fields_to_compare(expected[cid])
        a = _fields_to_compare(actual[cid])
        assert a == e, f"{cid}: spill merge diverges from in-memory merge\nexpected={e}\nactual={a}"


def test_iter_shards_yields_each_pcap_dict(tmp_path: Path) -> None:
    """iter_shards() should yield exactly the partial_stats dicts we wrote."""
    index = StreamingPCAPIndex(tmp_path)
    index.configure_stats_spill(shard_dir=tmp_path / "spill")

    shard1 = {"conn_a": _seed_stats("conn_a", [
        _make_packet(ts=1.0, src_ip="10.0.0.1", src_port=4001,
                     dst_ip="10.0.0.2", dst_port=502, pcap="a.pcap")
    ])}
    shard2 = {"conn_b": _seed_stats("conn_b", [
        _make_packet(ts=2.0, src_ip="10.0.0.1", src_port=4002,
                     dst_ip="10.0.0.3", dst_port=502, pcap="b.pcap")
    ])}
    index._merge_file_stats(deepcopy(shard1), processed_packets=1)
    index._merge_file_stats(deepcopy(shard2), processed_packets=1)

    yielded = list(index.iter_shards())
    assert len(yielded) == 2
    assert set(yielded[0].keys()) == {"conn_a"}
    assert set(yielded[1].keys()) == {"conn_b"}


def test_legacy_fallback_when_spill_not_configured(tmp_path: Path) -> None:
    """Without configure_stats_spill the index keeps the legacy in-memory dict."""
    index = StreamingPCAPIndex(tmp_path)
    assert not index.spill_enabled

    shard = {"conn_a": _seed_stats("conn_a", [
        _make_packet(ts=1.0, src_ip="10.0.0.1", src_port=4001,
                     dst_ip="10.0.0.2", dst_port=502, pcap="a.pcap")
    ])}
    index._merge_file_stats(shard, processed_packets=1)

    assert len(index._stats) == 1
    assert "conn_a" in index._stats
    # iter_stats and iter_merged_stats both work in fallback mode
    assert len(list(index.iter_stats())) == 1
    assert len(list(index.iter_merged_stats())) == 1
