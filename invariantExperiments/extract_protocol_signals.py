"""Standalone MQTT and OPC UA signal extraction from PCAPs into DuckDB.

This bypasses graph augmentation entirely. It scans the PCAP directory once and
optionally writes separate MQTT and OPC UA DuckDB files.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterator, Optional

import dpkt
import yaml
from tqdm import tqdm

from network_aug.pcap_index_fast import _parse_packet_fast
from network_aug.protocol_signal_db import MqttSignalDatabase, OpcUaSignalDatabase
from network_aug.protocol_signal_extractors import (
    MqttSignalStreamExtractor,
    OpcUaSignalStreamExtractor,
)

_BATCH_SIZE = 100_000


def _load_ip_to_hostname(assets_path: Optional[Path]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if assets_path is None or not assets_path.exists():
        return mapping

    with assets_path.open() as f:
        data = yaml.safe_load(f) or {}

    for host_info in (data.get("hosts") or {}).values():
        hostname = host_info.get("hostname", "")
        if not hostname:
            continue
        if "ip_address" in host_info:
            mapping[host_info["ip_address"]] = hostname
        for ip in host_info.get("ip_addresses", []):
            mapping[ip] = hostname
    return mapping


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract standalone MQTT and OPC UA signal observations from PCAPs."
    )
    parser.add_argument("pcap_dir", type=Path, help="Directory containing PCAP or PCAPNG files.")
    parser.add_argument("--mqtt-db", type=Path, default=None, help="Output DuckDB path for MQTT observations.")
    parser.add_argument("--opcua-db", type=Path, default=None, help="Output DuckDB path for OPC UA observations.")
    parser.add_argument("--assets", type=Path, default=None, help="Optional assets.yaml for IP-to-hostname resolution.")
    parser.add_argument(
        "--cache",
        type=Path,
        default=None,
        help="Optional cache file for the PCAP index. Defaults to <pcap_dir>/_protocol_signal_extract_cache.pkl.",
    )
    parser.add_argument("--packet-limit", type=int, default=None, help="Optional cap on packets to process.")
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Force rebuilding the PCAP index even if the cache exists.",
    )
    args = parser.parse_args()

    if args.mqtt_db is None and args.opcua_db is None:
        parser.error("at least one of --mqtt-db or --opcua-db is required")

    return args


def _prepare_output(path: Optional[Path]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()


def _iter_packet_records(
    pcap_file: Path,
    *,
    packet_limit: Optional[int],
    ignored_ips: set[str],
) -> Iterator[object]:
    with pcap_file.open("rb") as f:
        try:
            pcap_reader = dpkt.pcapng.Reader(f)
        except ValueError:
            f.seek(0)
            pcap_reader = dpkt.pcap.Reader(f)

        packet_iter = enumerate(pcap_reader)
        packet_bar = tqdm(
            packet_iter,
            desc=f"Packets ({pcap_file.name})",
            unit="pkt",
            total=packet_limit,
            leave=False,
        )
        try:
            for packet_index, (ts, buf) in packet_bar:
                if packet_limit is not None and packet_index >= packet_limit:
                    break
                record = _parse_packet_fast(
                    buf, ts, pcap_file.name, packet_index, ignored_ips
                )
                if record is not None:
                    yield record
        finally:
            packet_bar.close()


def main() -> None:
    args = parse_args()
    ip_to_host = _load_ip_to_hostname(args.assets)
    if ip_to_host and args.assets is not None:
        print(f"Loaded {len(ip_to_host)} IP->hostname mappings from {args.assets}")

    _prepare_output(args.mqtt_db)
    _prepare_output(args.opcua_db)

    mqtt_db = MqttSignalDatabase(args.mqtt_db) if args.mqtt_db else None
    opcua_db = OpcUaSignalDatabase(args.opcua_db) if args.opcua_db else None

    mqtt_buffer = []
    opcua_buffer = []
    mqtt_total = 0
    opcua_total = 0
    ignored_ips = {"172.16.142.250"}

    try:
        pcap_files = sorted(
            path for path in args.pcap_dir.iterdir() if path.suffix in {".pcap", ".pcapng"}
        )
        if not pcap_files:
            raise FileNotFoundError(f"No PCAP files found in {args.pcap_dir}")

        for pcap_file in tqdm(pcap_files, desc="Processing PCAP files", unit="file"):
            mqtt_extractors: Dict[str, MqttSignalStreamExtractor] = {}
            opcua_extractors: Dict[str, OpcUaSignalStreamExtractor] = {}

            for record in _iter_packet_records(
                pcap_file, packet_limit=args.packet_limit, ignored_ips=ignored_ips
            ):
                conn_id = record.connection_key().bidirectional_id()

                if mqtt_db and (
                    record.high_level_protocol == "MQTT"
                    or record.mqtt_packet_type_code is not None
                    or record.src_port in {1883, 8883}
                    or record.dst_port in {1883, 8883}
                ):
                    extractor = mqtt_extractors.get(conn_id)
                    if extractor is None:
                        extractor = MqttSignalStreamExtractor(ip_to_host=ip_to_host)
                        mqtt_extractors[conn_id] = extractor
                    mqtt_buffer.extend(extractor.consume(record))
                    if len(mqtt_buffer) >= _BATCH_SIZE:
                        mqtt_total += mqtt_db.insert_tuples_fast(mqtt_buffer)
                        print(f"  Flushed {mqtt_total:,} MQTT observations...", end="\r")
                        mqtt_buffer = []

                if opcua_db and (
                    record.high_level_protocol == "OPCUA"
                    or record.opcua_message_type is not None
                    or record.src_port == 4840
                    or record.dst_port == 4840
                ):
                    extractor = opcua_extractors.get(conn_id)
                    if extractor is None:
                        extractor = OpcUaSignalStreamExtractor(ip_to_host=ip_to_host)
                        opcua_extractors[conn_id] = extractor
                    opcua_buffer.extend(extractor.consume(record))
                    if len(opcua_buffer) >= _BATCH_SIZE:
                        opcua_total += opcua_db.insert_tuples_fast(opcua_buffer)
                        print(f"  Flushed {opcua_total:,} OPC UA observations...", end="\r")
                        opcua_buffer = []

            if mqtt_db:
                for extractor in mqtt_extractors.values():
                    mqtt_buffer.extend(extractor.finish())
                    if len(mqtt_buffer) >= _BATCH_SIZE:
                        mqtt_total += mqtt_db.insert_tuples_fast(mqtt_buffer)
                        print(f"  Flushed {mqtt_total:,} MQTT observations...", end="\r")
                        mqtt_buffer = []

            if opcua_db:
                for extractor in opcua_extractors.values():
                    opcua_buffer.extend(extractor.finish())
                    if len(opcua_buffer) >= _BATCH_SIZE:
                        opcua_total += opcua_db.insert_tuples_fast(opcua_buffer)
                        print(f"  Flushed {opcua_total:,} OPC UA observations...", end="\r")
                        opcua_buffer = []

        if mqtt_db and mqtt_buffer:
            mqtt_total += mqtt_db.insert_tuples_fast(mqtt_buffer)
        if opcua_db and opcua_buffer:
            opcua_total += opcua_db.insert_tuples_fast(opcua_buffer)
    finally:
        if mqtt_db is not None:
            mqtt_db.close()
        if opcua_db is not None:
            opcua_db.close()

    if mqtt_db is not None:
        print(f"MQTT extraction complete. Inserted {mqtt_total:,} observations into {args.mqtt_db}")
    if opcua_db is not None:
        print(f"OPC UA extraction complete. Inserted {opcua_total:,} observations into {args.opcua_db}")


if __name__ == "__main__":
    main()
