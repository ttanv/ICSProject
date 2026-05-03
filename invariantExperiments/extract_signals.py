"""Standalone script: extract Modbus signal observations from PCAPs into DuckDB.

Bypasses the full graph augmentation pipeline — only needs pcap files and duckdb.
Uses assets.yaml for IP-to-hostname resolution to produce GUIDs consistent with
the full pipeline.
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path
from typing import Dict

import yaml

from network_aug.pcap_index_fast import FastPCAPConnectionIndex
from network_aug.signal_db import SignalDatabase


def _load_ip_to_hostname(assets_path: Path) -> Dict[str, str]:
    """Build IP -> hostname lookup from assets.yaml."""
    mapping: Dict[str, str] = {}
    if not assets_path.exists():
        return mapping
    with open(assets_path) as f:
        data = yaml.safe_load(f)
    for host_info in (data.get("hosts") or {}).values():
        hostname = host_info.get("hostname", "")
        if "ip_address" in host_info:
            mapping[host_info["ip_address"]] = hostname
        for ip in host_info.get("ip_addresses", []):
            mapping[ip] = hostname
    return mapping


def _generate_guid(client_host: str, register_address: int, unit_id: int | None) -> str:
    """Match the GUID scheme from network_aug.missing_augmentor._generate_node_guid."""
    components = ["SignalContainer", client_host] + [
        str(v) for v in (register_address, unit_id) if v not in (None, "")
    ]
    combined = "|".join(components).lower()
    guid = uuid.UUID(bytes=hashlib.md5(combined.encode("utf-8")).digest())
    return f"{{{guid}}}"


def extract(pcap_dir: Path, db_path: Path, assets_path: Path | None = None) -> None:
    ip_to_host = _load_ip_to_hostname(assets_path) if assets_path else {}
    if ip_to_host:
        print(f"Loaded {len(ip_to_host)} IP->hostname mappings from {assets_path}")

    index = FastPCAPConnectionIndex(
        pcap_directory=pcap_dir,
        cache_path=pcap_dir / "_signal_extract_cache.pkl",
    )
    index.build(force_rebuild=True)

    db = SignalDatabase(db_path)
    observations: list = []
    total = 0

    for conn in index.iter_connections():
        for pkt in conn.records:
            if pkt.modbus_function is None:
                continue

            fc = pkt.modbus_function
            unit_id = pkt.modbus_unit_id
            ts = pkt.timestamp

            if pkt.dst_port == 502:
                client_ip, server_ip = pkt.src_ip, pkt.dst_ip
            elif pkt.src_port == 502:
                client_ip, server_ip = pkt.dst_ip, pkt.src_ip
            else:
                continue

            client_host = ip_to_host.get(client_ip, client_ip)
            server_host = ip_to_host.get(server_ip, server_ip)
            pcap_file = pkt.pcap_file

            # Collect (address, value, access_type) tuples
            reg_values: list[tuple[int, int, str]] = []
            read_regs = pkt.modbus_read_registers or ()
            write_regs = pkt.modbus_write_registers or ()
            values = pkt.modbus_register_values or ()

            if read_regs and values and len(read_regs) == len(values):
                for addr, val in zip(read_regs, values):
                    reg_values.append((addr, val, "read"))
            elif write_regs and values and len(write_regs) == len(values):
                for addr, val in zip(write_regs, values):
                    reg_values.append((addr, val, "write"))
            elif pkt.modbus_registers and values and len(pkt.modbus_registers) == len(values):
                access = "write" if fc in (5, 6, 15, 16, 23) else "read"
                for addr, val in zip(pkt.modbus_registers, values):
                    reg_values.append((addr, val, access))

            for addr, val, access_type in reg_values:
                guid = _generate_guid(client_host, addr, unit_id)
                observations.append((
                    ts, addr, val, access_type, fc, unit_id,
                    client_host, server_host, client_ip, server_ip,
                    pkt.modbus_transaction_id, None, None, None,
                    guid, pcap_file,
                ))

            if len(observations) >= 100_000:
                db.insert_tuples_fast(observations)
                total += len(observations)
                print(f"  Flushed {total:,} observations...", end="\r")
                observations.clear()

    if observations:
        db.insert_tuples_fast(observations)
        total += len(observations)

    db.close()
    print(f"\nDone. Inserted {total:,} observations into {db_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: python -m invariantExperiments.extract_signals <pcap_dir> <output.duckdb> [assets.yaml]")
        sys.exit(1)
    pcap_dir = Path(sys.argv[1])
    db_path = Path(sys.argv[2])
    assets_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    if db_path.exists():
        db_path.unlink()
    extract(pcap_dir, db_path, assets_path)
