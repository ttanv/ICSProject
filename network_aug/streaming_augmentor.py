"""Streaming augmentor for memory-efficient processing of large PCAP datasets.

This module provides a complete augmentation pipeline that uses the streaming
PCAP index, processing files one at a time to handle multi-GB captures without
running out of memory.

It keeps the streaming memory profile while emitting non-streaming-compatible
Modbus signal artifacts:
- ICSSignal nodes with EXPOSED_ON edges
- READ_SIGNAL / WRITE_SIGNAL process attribution edges
- SDT-based register summary properties
"""

from __future__ import annotations

import gc
import multiprocessing
import hashlib
import pickle
import tempfile
import traceback
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from tqdm import tqdm

from . import cypher_emit
from .correlation import (
    CorrelatedConnection,
    CorrelationConfig,
    CorrelationEngine,
    ProcessContext,
    TelemetryAnchor,
    TelemetryConnectionIndex,
)
from .cypher_reader import CypherConnectionExtractor, ExistingConnection
from .enhancer import (
    AugmentationConfig,
    _SDTCompressor,
)
from .features import (
    PreSortedPackets,
    average_packet_size,
    count_tcp_retransmits,
    directional_totals,
    directionality_ratio,
    dominant_protocol,
    duration_seconds,
    extract_http_features,
    extract_mqtt_features,
    extract_opcua_features,
    extract_tls_sni,
    mean_interarrival_time,
    mean_rtt_ms,
    resolve_mac_addresses,
)
from .orientation import oriented_connection_key
from .models import ConnectionKey, IndexedConnection, PacketRecord
from . import protocol_utils
from .streaming import (
    ConnectionStats,
    StreamingPCAPIndex,
    _iter_packet_records_for_backend,
    _parser_backend_candidates,
    describe_streaming_worker_failure,
    resolve_streaming_parser_backend,
)


def _generate_node_guid(node_type: str, hostname: str, *identifiers: object) -> str:
    """Replicate the GUID scheme used by the base provenance notebook.

    Must match the batch augmentor's _generate_node_guid exactly:
    pipe-separated, lowercased, brace-wrapped.
    """
    return _generate_node_guid_v2_braced(node_type, hostname, *identifiers)


def _generate_node_guid_v2(node_type: str, hostname: str, *identifiers: object) -> str:
    """Replicate the GUID scheme used by the base provenance notebook."""
    components = [node_type, hostname] + [str(value) for value in identifiers if value not in (None, "")]
    combined = "|".join(components).lower()
    digest = hashlib.md5(combined.encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest))


def _generate_node_guid_v2_braced(node_type: str, hostname: str, *identifiers: object) -> str:
    """Generate a deterministic GUID compatible with brace-wrapped base exports."""
    return f"{{{_generate_node_guid_v2(node_type, hostname, *identifiers)}}}"


def _normalize_transport_protocol(protocol: object) -> str:
    """Normalize transport protocol values used for service identity."""
    normalized = str(protocol or "").strip().lower()
    return normalized or "tcp"


def _generate_network_service_guid(hostname: str, port: int, protocol: object) -> str:
    """Generate a NetworkService GUID matching the base graph: (type, host, port) only."""
    normalized_port = port if port and port >= 0 else 0
    return _generate_node_guid_v2_braced("NetworkService", hostname, normalized_port)


@dataclass
class _StagedConnectEdge:
    """Internal staging container used to merge duplicate CONNECT_TO emissions."""
    source_guid: str
    dest_guid: str
    relationship_name: str
    source_label: str
    dest_label: str
    properties: Dict[str, object]
    statement_index: int
    source_ports: Set[int] = field(default_factory=set)
    protocol_values: Set[str] = field(default_factory=set)


@dataclass
class CorrelationStats:
    """Statistics about the correlation process."""
    total_pcap_connections: int = 0
    correlation_attempts: int = 0
    successful_correlations: int = 0
    session_port_matches: int = 0
    pcap_only_connections: int = 0
    process_attributed_registers: int = 0


class _SpooledPacketRecords:
    """Lazy packet sequence backed by a spill file on disk.

    Streaming mode uses this to keep exact packet fidelity without retaining all
    candidate packet lists in RAM at once.
    """

    def __init__(self, path: Path, packet_count: int) -> None:
        self._path = Path(path)
        self._packet_count = packet_count

    def __len__(self) -> int:
        return self._packet_count

    def __bool__(self) -> bool:
        return self._packet_count > 0 and self._path.exists()

    def __iter__(self) -> Iterator[PacketRecord]:
        if not self._path.exists():
            return iter(())
        return self._iter_packets()

    def __getitem__(self, index: int) -> PacketRecord:
        return list(self)[index]

    def _iter_packets(self) -> Iterator[PacketRecord]:
        with self._path.open("rb") as handle:
            while True:
                try:
                    chunk = pickle.load(handle)
                except EOFError:
                    break
                for packet in chunk:
                    yield packet


def _spool_path_for_connection(spool_dir: Path, canonical_id: str) -> Path:
    digest = hashlib.md5(canonical_id.encode("utf-8")).hexdigest()
    return spool_dir / digest[:2] / f"{digest}.pkl"


def _flush_spooled_records_to_dir(
    spool_dir: Path,
    buffered_records: Dict[str, List[PacketRecord]],
) -> None:
    for cid, records in buffered_records.items():
        if not records:
            continue
        record_path = _spool_path_for_connection(spool_dir, cid)
        record_path.parent.mkdir(parents=True, exist_ok=True)
        with record_path.open("ab") as handle:
            pickle.dump(records, handle, protocol=pickle.HIGHEST_PROTOCOL)
    buffered_records.clear()


def _materialize_candidate_file_worker(
    pcap_path_str: str,
    candidate_ids: Tuple[str, ...],
    spool_dir_str: str,
    packet_limit: Optional[int],
    backend: str,
    ignored_ips: Tuple[str, ...],
    flush_packet_limit: int,
    result_path_str: str,
) -> None:
    """Worker that spills candidate packet records for one PCAP file."""
    result_path = Path(result_path_str)
    try:
        candidate_id_set = set(candidate_ids)
        spool_dir = Path(spool_dir_str)
        buffered_records: Dict[str, List[PacketRecord]] = defaultdict(list)
        buffered_packet_count = 0

        for record in _iter_packet_records_for_backend(
            Path(pcap_path_str),
            packet_limit=packet_limit,
            backend=backend,
            ignored_ips=ignored_ips,
        ):
            cid = record.connection_key().bidirectional_id()
            if cid not in candidate_id_set:
                continue
            buffered_records[cid].append(record)
            buffered_packet_count += 1
            if buffered_packet_count >= flush_packet_limit:
                _flush_spooled_records_to_dir(spool_dir, buffered_records)
                buffered_packet_count = 0

        if buffered_records:
            _flush_spooled_records_to_dir(spool_dir, buffered_records)

        with result_path.open("wb") as handle:
            pickle.dump({"ok": True}, handle, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        with result_path.open("wb") as handle:
            pickle.dump(
                {
                    "ok": False,
                    "error": traceback.format_exc(),
                },
                handle,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        raise


class StreamingAugmentor:
    """Memory-efficient augmentor for large PCAP datasets with full correlation support.

    Unlike the original streaming augmentor which only added new edges,
    this version also:
    - Correlates PCAP connections to existing telemetry
    - Enriches existing edges with PCAP-derived metrics
    - Creates ICSSignal nodes and READ/WRITE_SIGNAL relationships for Modbus
    """

    def __init__(self, config: AugmentationConfig) -> None:
        self.config = config
        self._parser_backend = resolve_streaming_parser_backend()
        self._asset_ip_map = self._load_asset_lookup()
        self._asset_metadata: Dict[str, "AssetMetadata"] = {}
        self._ip_to_hostname: Dict[str, str] = {}
        self._placeholder_processes: Dict[str, str] = {}
        self._staged_connect_edges: Dict[Tuple[str, str, str], "_StagedConnectEdge"] = {}
        self._correlation_stats = CorrelationStats()
        self._load_asset_metadata()

        # Build set of all known hostnames for placeholder-process gating
        # (must match MissingTrafficAugmentor exactly)
        self._known_hostnames: Set[str] = (
            set(self._asset_metadata.keys())
            | set(self._asset_ip_map.values())
            | set(self.config.ip_hostname_map.values())
        )

        # Initialize DuckDB connection for signal storage
        self._signal_db = None
        if config.signal_db_path:
            from .signal_db import SignalDatabase
            self._signal_db = SignalDatabase(config.signal_db_path)

        self._materialization_flush_packet_limit = 100_000

    def _load_asset_lookup(self) -> Dict[str, str]:
        """Parse the base Cypher export to map IP addresses to hostnames (matches batch)."""
        from .cypher_reader import _consume_brace_block, _parse_property_block

        lookup: Dict[str, str] = {}
        path = Path(self.config.base_cypher)
        if not path.exists():
            return lookup

        text = path.read_text(encoding="utf-8")
        cursor = 0
        token = ":NetworkEndpoint"
        while True:
            idx = text.find(token, cursor)
            if idx == -1:
                break
            brace_start = text.find("{", idx)
            if brace_start == -1:
                break
            block, brace_end = _consume_brace_block(text, brace_start)
            if brace_end == -1:
                break
            properties = _parse_property_block(block)
            hostname = str(properties.get("hostname") or "")
            ip_addresses = properties.get("ipAddresses") or properties.get("ip_addresses")
            if isinstance(ip_addresses, list):
                for ip in ip_addresses:
                    ip_address = str(ip or "").strip()
                    if hostname and ip_address:
                        lookup[ip_address] = hostname
            else:
                ip_address = str(properties.get("ipAddress") or "")
                if hostname and ip_address:
                    lookup[ip_address] = hostname
            cursor = brace_end + 1
        return lookup

    def _load_asset_metadata(self) -> None:
        """Load extended asset metadata from assets.yaml (matches batch augmentor)."""
        from .enhancer import AssetMetadata
        import yaml

        asset_file = self.config.asset_file
        candidates = []
        if asset_file:
            candidates.append(Path(asset_file))
        candidates.append(Path(self.config.base_cypher).parent / "assets.yaml")
        candidates.append(Path.cwd() / "assets.yaml")

        asset_path = next((p for p in candidates if p.exists()), None)
        if not asset_path:
            return

        try:
            with asset_path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle) or {}
        except Exception:
            return

        hosts = data.get("hosts", {}) if isinstance(data, dict) else {}
        for hostname, details in hosts.items():
            if not isinstance(details, dict):
                continue
            ip_addresses: List[str] = []
            ip_list = details.get("ip_addresses")
            if isinstance(ip_list, list):
                for ip in ip_list:
                    ip_str = str(ip or "").strip()
                    if ip_str:
                        ip_addresses.append(ip_str)
            else:
                ip = details.get("ip_address") or details.get("ip")
                ip_str = str(ip or "").strip()
                if ip_str:
                    ip_addresses.append(ip_str)

            role = str(details.get("role") or "")
            is_managed = bool(details.get("is_managed", details.get("has_logs", True)))

            metadata = AssetMetadata(
                hostname=hostname,
                ip_addresses=ip_addresses,
                role=role,
                has_logs=is_managed,
            )
            self._asset_metadata[hostname] = metadata
            for ip in ip_addresses:
                self._ip_to_hostname[ip] = hostname

    def _resolve_host(self, ip: str) -> Tuple[str, str]:
        """Return (hostname, ip_address) using config overrides (matches batch)."""
        hostname = self._asset_ip_map.get(ip)
        if hostname:
            return hostname, ip
        hostname = self.config.ip_hostname_map.get(ip)
        if hostname:
            return hostname, ip
        return ip, ip

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP to hostname, or return IP if unknown."""
        return self._asset_ip_map.get(ip, self.config.ip_hostname_map.get(ip, ip))

    def _is_known_host(self, ip: str) -> bool:
        """Return True if the IP is a known asset in the inventory."""
        return ip in self._asset_ip_map or ip in self.config.ip_hostname_map

    def _load_existing_connections(self) -> Tuple[Set[str], List[ExistingConnection]]:
        """Load existing connection identifiers from the base Cypher file."""
        # Resolve asset file path (same logic as non-streaming version)
        asset_file = self.config.asset_file
        if asset_file and not asset_file.is_absolute():
            cwd_candidate = Path.cwd() / asset_file
            if cwd_candidate.exists():
                asset_file = cwd_candidate.resolve()
            else:
                asset_file = (self.config.base_cypher.parent / asset_file).resolve()
        if asset_file is None:
            cwd_candidate = Path.cwd() / "assets.yaml"
            cypher_candidate = self.config.base_cypher.parent / "assets.yaml"
            if cwd_candidate.exists():
                asset_file = cwd_candidate
            elif cypher_candidate.exists():
                asset_file = cypher_candidate

        extractor = CypherConnectionExtractor(self.config.base_cypher, asset_file=asset_file)
        existing = extractor.load_connections()

        # Build asset-IP set for scope filtering.
        # Batch includes both discovered asset IPs and configured host/IP
        # overrides, so streaming must treat the same IPs as in-scope.
        self._asset_ips: Set[str] = set(self._asset_ip_map.keys()) | set(self.config.ip_hostname_map.keys())

        # Filter for target relationship type
        target_rels = {self.config.relationship_name.upper()}
        filtered = [conn for conn in existing if conn.rel_type in target_rels]
        existing_ids = {conn.key.bidirectional_id() for conn in filtered}
        return existing_ids, filtered

    @staticmethod
    def _oriented_stats_key(stats: ConnectionStats) -> Optional[ConnectionKey]:
        """Return a client->server key for sampled packets, or None if ambiguous."""
        if not stats._sample_packets:
            return None
        return oriented_connection_key(stats.origin, stats._sample_packets)

    def _is_in_scope(self, stats: ConnectionStats) -> bool:
        if not getattr(self, "_asset_ips", None):
            return True
        return stats.origin.src_ip in self._asset_ips or stats.origin.dst_ip in self._asset_ips

    def _should_materialize_stats(self, stats: ConnectionStats) -> bool:
        if stats.packet_count <= 0:
            return False
        if stats._sample_packets and self.config.policy.is_interesting(stats.origin, stats._sample_packets):
            return True
        if stats.packet_count >= self.config.policy.min_packet_threshold:
            return True

        important_ports = {502, 8080, 1883, 8883, 4840}
        if stats.origin.src_port in important_ports or stats.origin.dst_port in important_ports:
            return True
        if 0 < stats.origin.src_port < 1024 or 0 < stats.origin.dst_port < 1024:
            return True
        if stats.modbus_function_codes or stats.http_methods_seen:
            return True
        if stats.mqtt_packet_type_codes_seen or stats.opcua_message_types_seen:
            return True
        if stats.client_ports_seen:
            return True
        return False

    def _select_candidate_connection_ids(
        self,
        stats_iter: Sequence[ConnectionStats],
        telemetry_index: TelemetryConnectionIndex,
    ) -> Tuple[Set[str], Dict[str, int]]:
        correlation_config = CorrelationConfig(
            min_confidence=self.config.min_correlation_confidence,
            temporal_tolerance_seconds=self.config.temporal_tolerance_seconds,
            pcap_time_offset_seconds=self.config.pcap_time_offset_seconds,
        )
        correlation_engine = CorrelationEngine(config=correlation_config)

        candidate_ids: Set[str] = set()
        in_scope_connections = 0
        selected_by_correlation = 0
        selected_by_policy = 0

        for stats in stats_iter:
            if not self._is_in_scope(stats):
                continue
            in_scope_connections += 1

            correlated = correlation_engine.correlate(stats.to_indexed_connection(), telemetry_index)
            if correlated is not None:
                candidate_ids.add(stats.canonical_id)
                selected_by_correlation += 1
                continue

            if self._should_materialize_stats(stats):
                candidate_ids.add(stats.canonical_id)
                selected_by_policy += 1

        selection_stats = correlation_engine.get_statistics()
        selection_stats["in_scope_connections"] = in_scope_connections
        selection_stats["selected_by_correlation"] = selected_by_correlation
        selection_stats["selected_by_policy"] = selected_by_policy
        return candidate_ids, selection_stats

    def _materialize_candidate_connections(
        self,
        candidate_ids: Set[str],
        stats_by_cid: Dict[str, ConnectionStats],
        spool_dir: Path,
    ) -> List[IndexedConnection]:
        if not candidate_ids:
            return []

        ignored_ips = set(StreamingPCAPIndex._IGNORED_IPS)
        pcap_files = sorted(
            p for p in self.config.pcap_directory.iterdir()
            if p.suffix in {".pcap", ".pcapng"}
        )

        for pcap_path in tqdm(pcap_files, desc="Materializing candidate connections", unit="file"):
            self._materialize_candidate_file_isolated(
                pcap_path=pcap_path,
                candidate_ids=candidate_ids,
                spool_dir=spool_dir,
                ignored_ips=tuple(ignored_ips),
            )

        connections: List[IndexedConnection] = []
        for cid, stats in stats_by_cid.items():
            if cid not in candidate_ids:
                continue
            record_path = self._spool_path(spool_dir, cid)
            if not record_path.exists():
                continue
            connections.append(
                IndexedConnection(
                    canonical_id=cid,
                    origin=stats.origin,
                    records=_SpooledPacketRecords(record_path, stats.packet_count),
                    origin_timestamp=stats.origin_timestamp,
                )
            )
        return connections

    def _spool_path(self, spool_dir: Path, canonical_id: str) -> Path:
        return _spool_path_for_connection(spool_dir, canonical_id)

    def _flush_spooled_records(
        self,
        spool_dir: Path,
        buffered_records: Dict[str, List[PacketRecord]],
    ) -> None:
        _flush_spooled_records_to_dir(spool_dir, buffered_records)

    @staticmethod
    def _read_worker_payload(result_path: Path) -> Dict[str, object]:
        if not result_path.exists() or result_path.stat().st_size == 0:
            return {}
        with result_path.open("rb") as handle:
            payload = pickle.load(handle)
        if not isinstance(payload, dict):
            return {}
        return payload

    def _materialize_candidate_file_isolated(
        self,
        *,
        pcap_path: Path,
        candidate_ids: Set[str],
        spool_dir: Path,
        ignored_ips: Tuple[str, ...],
    ) -> None:
        backends = _parser_backend_candidates(self._parser_backend)
        candidate_id_values = tuple(candidate_ids)

        for index, backend in enumerate(backends):
            try:
                self._run_materialization_worker(
                    pcap_path=pcap_path,
                    candidate_ids=candidate_id_values,
                    spool_dir=spool_dir,
                    ignored_ips=ignored_ips,
                    backend=backend,
                )
                if backend != self._parser_backend:
                    print(
                        f"Recovered materialization for {pcap_path.name} with parser backend '{backend}' "
                        f"after primary backend '{self._parser_backend}' failed."
                    )
                return
            except RuntimeError as exc:
                if index + 1 < len(backends):
                    print(str(exc))
                    print(f"Retrying materialization for {pcap_path.name} with parser backend '{backends[index + 1]}'...")
                    continue
                raise

    def _run_materialization_worker(
        self,
        *,
        pcap_path: Path,
        candidate_ids: Tuple[str, ...],
        spool_dir: Path,
        ignored_ips: Tuple[str, ...],
        backend: str,
    ) -> None:
        with tempfile.NamedTemporaryFile(prefix="stream_materialize_", suffix=".pkl", delete=False) as handle:
            result_path = Path(handle.name)

        ctx = multiprocessing.get_context("spawn")
        process = ctx.Process(
            target=_materialize_candidate_file_worker,
            args=(
                str(pcap_path),
                candidate_ids,
                str(spool_dir),
                self.config.packet_limit,
                backend,
                ignored_ips,
                self._materialization_flush_packet_limit,
                str(result_path),
            ),
        )
        process.start()
        process.join()

        payload = self._read_worker_payload(result_path)
        try:
            if process.exitcode == 0:
                if payload.get("ok"):
                    return
                raise RuntimeError(
                    describe_streaming_worker_failure(
                        pcap_path=pcap_path,
                        backend=backend,
                        phase="Candidate materialization",
                        exitcode=process.exitcode,
                        error_message=payload.get("error", "worker completed without a result payload"),
                    )
                )

            raise RuntimeError(
                describe_streaming_worker_failure(
                    pcap_path=pcap_path,
                    backend=backend,
                    phase="Candidate materialization",
                    exitcode=process.exitcode or 1,
                    error_message=payload.get("error"),
                )
            )
        finally:
            result_path.unlink(missing_ok=True)

    def _load_modbus_shards(self, batch_aug: object, shard_dir: Path) -> None:
        """Bulk-load per-PCAP Modbus shards into the signal database.

        Replaces the apply-time ``_collect_modbus_signals`` calls with a single
        SQL statement that streams every shard into ``signal_observations``.
        Sets the ``_modbus_signals_preloaded`` flag so the apply phase skips
        redundant per-group inserts.
        """
        signal_db = getattr(batch_aug, "_signal_db", None)
        if signal_db is None:
            return
        shards = sorted(p for p in shard_dir.glob("*.parquet"))
        if not shards:
            return
        glob = str(shard_dir / "*.parquet")
        # DuckDB streams Parquet files without materializing them in RAM.
        signal_db._conn.execute(
            f"INSERT INTO signal_observations SELECT * FROM read_parquet('{glob}')"
        )
        # Mark the augmentor so apply-phase callers skip the redundant inserts.
        batch_aug._modbus_signals_preloaded = True
        print(
            f"Loaded {len(shards)} Modbus shard(s) into signal database from {shard_dir}"
        )

    def run(self) -> Tuple[int, int]:
        """Execute streaming augmentation with targeted full-packet materialization."""
        if self._signal_db is not None:
            self._signal_db.close()
            self._signal_db = None

        from .missing_augmentor import MissingTrafficAugmentor

        print("Loading base graph...")
        batch_aug = MissingTrafficAugmentor(self.config)
        base_connection_ids, existing_connections = batch_aug._load_existing_connections()
        self._asset_ips = set(getattr(batch_aug, "_asset_ips", set()))
        print(f"Found {len(base_connection_ids)} existing connections in base graph")

        print("Building telemetry index for candidate selection...")
        telemetry_index = TelemetryConnectionIndex(
            existing_connections,
            ip_to_hostname=getattr(batch_aug, "_ip_to_hostname", {}),
        )
        print(f"  - {telemetry_index.anchor_count} anchors indexed")

        print("Processing PCAP files in streaming mode...")
        pcap_index = StreamingPCAPIndex(
            self.config.pcap_directory,
            packet_limit_per_file=self.config.packet_limit,
            parser_backend=self._parser_backend,
        )

        # Inline Modbus signal extraction: have each pass-1 worker also write
        # a Parquet shard with fully-resolved Modbus observations so the apply
        # phase can skip the expensive packet re-iteration.
        modbus_extract_dir: Optional[Path] = None
        if batch_aug._signal_db is not None:
            modbus_extract_dir = Path(tempfile.mkdtemp(prefix="network_aug_modbus_shards_"))
            asset_map = {**self._asset_ip_map, **self.config.ip_hostname_map}
            pcap_index.configure_modbus_extraction(
                shard_dir=modbus_extract_dir,
                asset_ip_to_hostname=asset_map,
                modbus_server_ports=(502,),
                asset_ips=tuple(self._asset_ips) if self._asset_ips else (),
            )

        try:
            pcap_index.build()

            if modbus_extract_dir is not None and pcap_index.modbus_shard_paths:
                self._load_modbus_shards(batch_aug, modbus_extract_dir)
        finally:
            if modbus_extract_dir is not None:
                # Shards were ingested into DuckDB; drop the staging dir.
                import shutil
                shutil.rmtree(modbus_extract_dir, ignore_errors=True)

        stats_by_cid = {stats.canonical_id: stats for stats in pcap_index.iter_stats()}

        candidate_ids, selection_stats = self._select_candidate_connection_ids(
            list(stats_by_cid.values()),
            telemetry_index,
        )
        in_scope_connections = selection_stats.get("in_scope_connections", 0)
        print(
            f"Selected {len(candidate_ids)} candidate connections from {in_scope_connections} in-scope connections"
        )

        # Sample packets are only consulted during candidate selection
        # (orientation + policy heuristics). After this point pass 2 reads
        # full packet records back from the PCAPs, so the retained samples
        # are dead weight — ~40 KB per connection × hundreds of thousands
        # of connections at 24h+ scale.
        sample_drop_count = 0
        for stats in stats_by_cid.values():
            if stats._sample_packets:
                sample_drop_count += len(stats._sample_packets)
                stats._sample_packets.clear()
        if sample_drop_count:
            print(f"Released {sample_drop_count:,} sample packets after candidate selection")
            gc.collect()
        print(
            f"  - sample correlations: {selection_stats.get('successful_correlations', 0)}/"
            f"{selection_stats.get('total_attempts', 0)}"
        )
        print(f"  - selected by policy/protocol heuristics: {selection_stats.get('selected_by_policy', 0)}")

        with tempfile.TemporaryDirectory(prefix="network_aug_spool_") as spool_dir_raw:
            spool_dir = Path(spool_dir_raw)
            print(
                "Materializing candidate connections into spill files for exact artifact generation..."
            )
            materialized_connections = self._materialize_candidate_connections(
                candidate_ids,
                stats_by_cid,
                spool_dir,
            )
            print(
                f"Materialized {len(materialized_connections)} full connections "
                f"using spill storage under {spool_dir}"
            )

            # The first streaming pass keeps lightweight per-connection samples
            # for candidate selection only. Drop them before grouped artifact
            # generation so large scenarios do not carry both the first-pass
            # samples and the spill-backed materialized views at once.
            pcap_index = None
            stats_by_cid.clear()
            del stats_by_cid
            del candidate_ids
            gc.collect()

            artifacts = batch_aug._build_artifacts(
                materialized_connections,
                base_connection_ids=base_connection_ids,
                existing_connections=existing_connections,
                show_progress=True,
            )

        ordered_assets = [artifacts.asset_statements[key] for key in sorted(artifacts.asset_statements)]
        ordered_services = [artifacts.service_statements[key] for key in sorted(artifacts.service_statements)]
        ordered_hosts = [artifacts.host_statements[key] for key in sorted(artifacts.host_statements)]
        ordered_registers = [artifacts.register_statements[key] for key in sorted(artifacts.register_statements)]
        ordered_signals = [artifacts.signal_statements[key] for key in sorted(artifacts.signal_statements)]
        ordered_processes = [artifacts.process_statements[key] for key in sorted(artifacts.process_statements)]
        ordered_runs = [artifacts.runs_statements[key] for key in sorted(artifacts.runs_statements)]
        all_relationships = (
            artifacts.existing_relationship_updates
            + artifacts.relationship_statements
            + artifacts.process_register_statements
            + artifacts.process_signal_statements
        )
        batch_aug._write_output(
            ordered_assets,
            ordered_services,
            ordered_hosts,
            ordered_registers,
            ordered_signals,
            ordered_processes,
            ordered_runs,
            all_relationships,
        )

        node_count = (
            len(artifacts.asset_statements)
            + len(artifacts.service_statements)
            + len(artifacts.host_statements)
            + len(artifacts.register_statements)
            + len(artifacts.signal_statements)
            + len(artifacts.process_statements)
        )
        relationship_count = len(all_relationships) + len(artifacts.runs_statements)

        if batch_aug._signal_db:
            stats = batch_aug._signal_db.get_statistics()
            print(
                f"Signal database: {stats.get('total', 0)} observations "
                f"({stats.get('access_read', 0)} reads, {stats.get('access_write', 0)} writes), "
                f"{stats.get('unique_registers', 0)} unique registers"
            )
            batch_aug._signal_db.close()

        return node_count, relationship_count

    def _relationship_properties(
        self,
        connection: ConnectionKey,
        packets: Sequence[PacketRecord],
    ) -> Dict[str, object]:
        """Compute relationship properties from packets."""
        sorted_packets = PreSortedPackets.from_packets(packets)
        timestamps = [pkt.timestamp for pkt in sorted_packets]
        bytes_out, bytes_in, _, _ = directional_totals(connection, sorted_packets)
        dir_index = directionality_ratio(bytes_out, bytes_in)
        inter_arrival = mean_interarrival_time(sorted_packets)
        retransmits = count_tcp_retransmits(sorted_packets)
        src_mac, dst_mac = resolve_mac_addresses(connection, sorted_packets)
        http_features = extract_http_features(sorted_packets)
        mqtt_features = extract_mqtt_features(sorted_packets)
        opcua_features = extract_opcua_features(sorted_packets)
        tls_sni = extract_tls_sni(sorted_packets)
        rtt_ms = mean_rtt_ms(connection, sorted_packets)

        return {
            "SourceIp": connection.src_ip,
            "SourcePort": connection.src_port,
            "DestinationIp": connection.dst_ip,
            "DestinationPort": connection.dst_port,
            "Protocol": connection.protocol.lower(),
            "inferredFrom": "pcap",
            "pcapAugmented": True,
            "note": "Observed in PCAP but missing from host telemetry",
            "packetCount": len(sorted_packets),
            "durationSeconds": duration_seconds(sorted_packets),
            "avgPacketSize": round(average_packet_size(sorted_packets), 2),
            "highLevelProtocol": dominant_protocol(sorted_packets),
            "firstSeen": min(timestamps) if timestamps else None,
            "lastSeen": max(timestamps) if timestamps else None,
            "srcMac": src_mac or None,
            "dstMac": dst_mac or None,
            "bytesOut": bytes_out,
            "bytesIn": bytes_in,
            "directionalityIndex": round(dir_index, 6) if dir_index is not None else None,
            "meanInterArrivalPacketTime": round(inter_arrival, 6),
            "retransmits": retransmits,
            "tlsSNI": tls_sni or None,
            "httpMethod": http_features.get("method"),
            "httpStatus": http_features.get("status"),
            "httpContent": http_features.get("content"),
            "mqttPacketTypes": mqtt_features.get("packetTypes"),
            "mqttTopics": mqtt_features.get("topics"),
            "mqttClientIds": mqtt_features.get("clientIds"),
            "mqttQosLevels": mqtt_features.get("qosLevels"),
            "mqttPublishCount": mqtt_features.get("publishCount"),
            "mqttSubscribeCount": mqtt_features.get("subscribeCount"),
            "mqttRetainSeen": mqtt_features.get("retainSeen"),
            "opcuaMessageTypes": opcua_features.get("messageTypes"),
            "opcuaChunkTypes": opcua_features.get("chunkTypes"),
            "opcuaEndpointUrls": opcua_features.get("endpointUrls"),
            "opcuaSecurityPolicies": opcua_features.get("securityPolicies"),
            "opcuaSecureChannelIds": opcua_features.get("secureChannelIds"),
            "opcuaOpenCount": opcua_features.get("openCount"),
            "opcuaMsgCount": opcua_features.get("msgCount"),
            "opcuaCloseCount": opcua_features.get("closeCount"),
            "rttMs": round(rtt_ms, 3) if rtt_ms > 0.0 else None,
        }

    def _is_interesting(self, stats: ConnectionStats) -> bool:
        """Check if a connection is interesting using the configured policy.

        Bridges the gap between ConnectionStats (which has a real packet_count
        but only ~100 sample packets) and AugmentationPolicy.is_interesting
        (which checks ``len(packets) < min_packet_threshold``).  We verify the
        packet-count threshold against the *real* count, then pass the sample
        packets through for all other policy checks (broadcast, GRE, ports, etc.).
        """
        policy = self.config.policy
        # Real packet count check (samples would under-count)
        if stats.packet_count < policy.min_packet_threshold:
            return False
        # Delegate everything else (broadcast, outer prefix, GRE, port checks)
        # to the shared policy using the sample packets.
        return policy.is_interesting(stats.origin, stats._sample_packets)

    # ------------------------------------------------------------------
    # Signal database: targeted second pass over PCAPs
    # ------------------------------------------------------------------

    def _signal_db_second_pass(
        self,
        modbus_connections: List[Tuple[str, str, int]],
    ) -> None:
        """Re-read PCAP files and insert ALL Modbus observations into DuckDB.

        Unlike the first pass (which only keeps ~100 sample packets per
        connection), this pass processes every packet but only extracts Modbus
        fields for known connections and streams them directly into DuckDB.
        No packet storage — parse, insert, discard.
        """
        import gc
        try:
            import dpkt
        except ImportError:
            return

        # Build lookup: bidirectional connection ID -> (client_ip, server_ip, port)
        modbus_lookup: Dict[str, Tuple[str, str, int]] = {}
        for client_ip, server_ip, port in modbus_connections:
            # Both directions of the connection
            fwd = f"{client_ip}:{0}-{server_ip}:{port}"
            rev = f"{server_ip}:{port}-{client_ip}:{0}"
            # Use the same bidirectional ID logic as ConnectionKey
            fwd_key = ConnectionKey(client_ip, 0, server_ip, port, "tcp").bidirectional_id()
            modbus_lookup[fwd_key] = (client_ip, server_ip, port)

        # For port-502 connections, also index by any ephemeral port combo
        modbus_server_endpoints: Set[Tuple[str, int]] = set()
        for _, server_ip, port in modbus_connections:
            modbus_server_endpoints.add((server_ip, port))

        # Hostname resolution cache
        hostname_cache: Dict[str, str] = {}
        def _hostname(ip: str) -> str:
            if ip not in hostname_cache:
                hostname_cache[ip] = self._resolve_host(ip)[0]
            return hostname_cache[ip]

        pcap_files = sorted(
            f for f in self.config.pcap_directory.iterdir()
            if f.suffix in {".pcap", ".pcapng"}
        )

        print(f"Signal DB: Second pass over {len(pcap_files)} PCAP files for {len(modbus_connections)} Modbus connections...")

        from .pcap_index_fast import _parse_packet_fast

        # Per-connection packet buffers — flush to DuckDB periodically
        conn_packets: Dict[Tuple[str, str, int], List[PacketRecord]] = defaultdict(list)
        FLUSH_THRESHOLD = 50_000
        total_flushed = 0

        def _flush_all() -> int:
            nonlocal total_flushed
            count = 0
            for (c_ip, s_ip, s_port), packets in conn_packets.items():
                if not packets:
                    continue
                protocol_utils.collect_modbus_signals(
                    packets=packets,
                    client_ip=c_ip, server_ip=s_ip, server_port=s_port,
                    client_hostname=_hostname(c_ip), server_hostname=_hostname(s_ip),
                    signal_db=self._signal_db,
                )
                count += len(packets)
            conn_packets.clear()
            total_flushed += count
            return count

        for pcap_path in tqdm(pcap_files, desc="Signal DB pass", unit="file"):
            try:
                with open(pcap_path, "rb") as f:
                    try:
                        reader = dpkt.pcapng.Reader(f)
                    except ValueError:
                        f.seek(0)
                        reader = dpkt.pcap.Reader(f)

                    packet_count = 0
                    for packet_index, (ts, buf) in enumerate(reader):
                        record = _parse_packet_fast(buf, ts, pcap_path.name, packet_index, set())
                        if record is None:
                            continue
                        if record.modbus_function is None:
                            continue

                        # Check if this packet belongs to a known Modbus server
                        matched = None
                        if (record.dst_ip, record.dst_port) in modbus_server_endpoints:
                            matched = (record.src_ip, record.dst_ip, record.dst_port)
                        elif (record.src_ip, record.src_port) in modbus_server_endpoints:
                            matched = (record.dst_ip, record.src_ip, record.src_port)

                        if matched is None:
                            continue

                        conn_packets[matched].append(record)
                        packet_count += 1

                        if packet_count >= FLUSH_THRESHOLD:
                            _flush_all()
                            packet_count = 0

            except Exception as e:
                print(f"  Warning: error reading {pcap_path.name}: {e}")

            _flush_all()
            gc.collect()

        print(f"Signal DB: Inserted {total_flushed:,} Modbus observations from full PCAP pass")

    # ------------------------------------------------------------------
    # CONNECT_TO edge deduplication (ported from MissingTrafficAugmentor)
    # ------------------------------------------------------------------

    @staticmethod
    def _as_number(value: object) -> Optional[float]:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        try:
            return float(text)
        except ValueError:
            return None

    def _combined_bytes(self, properties: Dict[str, object]) -> Optional[int]:
        total = 0
        seen = False
        for key in ("bytesOut", "bytesIn"):
            value = self._as_number(properties.get(key))
            if value is None:
                continue
            total += int(value)
            seen = True
        return total if seen else None

    def _extract_source_ports_from_properties(self, properties: Dict[str, object]) -> Set[int]:
        ports: Set[int] = set()
        source_port = properties.get("SourcePort")
        source_port_num = self._as_number(source_port)
        if source_port_num is not None and int(source_port_num) > 0:
            ports.add(int(source_port_num))
        source_port_set = properties.get("sourcePortSet")
        if isinstance(source_port_set, str):
            for candidate in source_port_set.split(","):
                candidate = candidate.strip()
                if not candidate:
                    continue
                num = self._as_number(candidate)
                if num is not None and int(num) > 0:
                    ports.add(int(num))
        return ports

    def _extract_protocol_values(self, properties: Dict[str, object]) -> Set[str]:
        protocols: Set[str] = set()
        protocol = str(properties.get("Protocol") or "").strip().lower()
        if protocol and protocol != "mixed":
            protocols.add(protocol)
        protocol_set = properties.get("protocolSet")
        if isinstance(protocol_set, str):
            for candidate in protocol_set.split(","):
                normalized = candidate.strip().lower()
                if normalized and normalized != "mixed":
                    protocols.add(normalized)
        return protocols

    def _merge_connect_properties(
        self,
        existing: Dict[str, object],
        incoming: Dict[str, object],
    ) -> Dict[str, object]:
        merged = dict(existing)
        sum_fields = {"packetCount", "bytesIn", "bytesOut", "canonicalCount"}
        min_fields = {"firstSeen"}
        max_fields = {"lastSeen"}
        or_boolean_fields = {"telemetryCorrelated", "correlatedFromTelemetry"}
        for key, value in incoming.items():
            if value is None:
                continue
            if key in sum_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None and new_num is None:
                    continue
                if old_num is None:
                    merged[key] = int(new_num) if new_num is not None else value
                elif new_num is None:
                    continue
                else:
                    merged[key] = int(old_num + new_num)
                continue
            if key in min_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None:
                    merged[key] = value
                elif new_num is not None:
                    merged[key] = min(old_num, new_num)
                continue
            if key in max_fields:
                old_num = self._as_number(merged.get(key))
                new_num = self._as_number(value)
                if old_num is None:
                    merged[key] = value
                elif new_num is not None:
                    merged[key] = max(old_num, new_num)
                continue
            if key in or_boolean_fields:
                merged[key] = bool(merged.get(key)) or bool(value)
                continue
            merged[key] = value
        return merged

    def _normalize_staged_connect_edge(self, edge: "_StagedConnectEdge") -> None:
        props = edge.properties
        if edge.source_ports:
            sorted_ports = sorted(edge.source_ports)
            props["uniqueSourcePorts"] = len(sorted_ports)
            props["sourcePortMin"] = sorted_ports[0]
            props["sourcePortMax"] = sorted_ports[-1]
            if len(sorted_ports) == 1:
                props["SourcePort"] = sorted_ports[0]
                props.pop("sourcePortSet", None)
            else:
                props["SourcePort"] = "aggregated"
                if len(sorted_ports) <= 8:
                    props["sourcePortSet"] = ",".join(str(port) for port in sorted_ports)
                else:
                    props.pop("sourcePortSet", None)
        if edge.protocol_values:
            protocols = sorted(edge.protocol_values)
            if len(protocols) == 1:
                props["Protocol"] = protocols[0]
                props.pop("protocolSet", None)
            else:
                props["Protocol"] = "mixed"
                props["protocolSet"] = ",".join(protocols)
        first_seen = self._as_number(props.get("firstSeen"))
        last_seen = self._as_number(props.get("lastSeen"))
        if first_seen is not None and last_seen is not None and last_seen >= first_seen:
            props["durationSeconds"] = last_seen - first_seen
        total_bytes_value = self._combined_bytes(props)
        packet_count_value = self._as_number(props.get("packetCount"))
        if total_bytes_value is not None and packet_count_value is not None and packet_count_value > 0:
            props["avgPacketSize"] = round(total_bytes_value / packet_count_value, 2)
        canonical_count = self._as_number(props.get("canonicalCount"))
        if total_bytes_value is not None and canonical_count is not None and canonical_count > 0:
            props["meanBytesPerConnection"] = round(total_bytes_value / canonical_count, 2)
        bytes_out_value = self._as_number(props.get("bytesOut"))
        bytes_in_value = self._as_number(props.get("bytesIn"))
        if bytes_out_value is not None and bytes_in_value is not None:
            ratio = directionality_ratio(int(bytes_out_value), int(bytes_in_value))
            props["directionalityIndex"] = round(ratio, 6) if ratio is not None else None
        props["pcapAugmented"] = True

    def _stage_connect_relationship(
        self,
        *,
        relationship_statements: List[str],
        source_guid: str,
        dest_guid: str,
        properties: Dict[str, object],
        relationship_name: str = "CONNECT_TO",
        source_label: str = "Process",
        dest_label: str = "NetworkService",
        source_ports: Optional[Sequence[int]] = None,
    ) -> bool:
        """Stage and merge CONNECT_TO statements so each process/service pair is emitted once."""
        key = (source_guid, dest_guid, relationship_name)
        incoming_properties = {name: value for name, value in properties.items() if value is not None}

        observed_ports: Set[int] = set()
        if source_ports:
            for port in source_ports:
                numeric = self._as_number(port)
                if numeric is not None and int(numeric) > 0:
                    observed_ports.add(int(numeric))
        if not observed_ports:
            observed_ports.update(self._extract_source_ports_from_properties(incoming_properties))

        observed_protocols = self._extract_protocol_values(incoming_properties)

        staged = self._staged_connect_edges.get(key)
        if staged is None:
            staged = _StagedConnectEdge(
                source_guid=source_guid,
                dest_guid=dest_guid,
                relationship_name=relationship_name,
                source_label=source_label,
                dest_label=dest_label,
                properties=incoming_properties,
                statement_index=len(relationship_statements),
            )
            staged.source_ports.update(observed_ports)
            staged.protocol_values.update(observed_protocols)
            self._normalize_staged_connect_edge(staged)
            relationship_statements.append(
                cypher_emit.create_connection_statement(
                    staged.source_guid,
                    staged.dest_guid,
                    staged.properties,
                    relationship_name=staged.relationship_name,
                    source_label=staged.source_label,
                    dest_label=staged.dest_label,
                )
            )
            self._staged_connect_edges[key] = staged
            return True

        staged.source_ports.update(observed_ports)
        staged.protocol_values.update(observed_protocols)
        staged.properties = self._merge_connect_properties(staged.properties, incoming_properties)
        self._normalize_staged_connect_edge(staged)
        relationship_statements[staged.statement_index] = cypher_emit.create_connection_statement(
            staged.source_guid,
            staged.dest_guid,
            staged.properties,
            relationship_name=staged.relationship_name,
            source_label=staged.source_label,
            dest_label=staged.dest_label,
        )
        return False

    def _emit_connection(
        self,
        stats: ConnectionStats,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        ownership_statements: Dict[str, str],
        relationship_statements: List[str],
    ) -> bool:
        """Emit Cypher statements for a single connection. Returns True if a new edge was created."""
        oriented_key = self._oriented_stats_key(stats)
        if oriented_key is None:
            return False

        client_ip = oriented_key.src_ip
        server_ip, server_port = oriented_key.dst_ip, oriented_key.dst_port

        client_hostname, client_ip_addr = self._resolve_host(client_ip)
        client_asset_guid = self._ensure_asset_node(client_hostname, client_ip_addr, asset_statements)
        src_node_id = self._ensure_placeholder_process(
            client_hostname, client_asset_guid,
            process_statements, ownership_statements,
        )

        dst_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=server_port,
            protocol=oriented_key.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            ownership_statements=ownership_statements,
        )

        if not src_node_id or not dst_node_id:
            return False

        if server_port == 502:
            server_hostname, server_ip_addr = self._resolve_host(server_ip)
            server_asset_guid = self._ensure_asset_node(
                server_hostname, server_ip_addr, asset_statements,
            )
            register_summaries = stats.get_register_summaries()
            for (address, unit_id, register_type), summary in register_summaries.items():
                self._ensure_register_node(
                    host=server_hostname,
                    port=server_port,
                    asset_guid=server_asset_guid,
                    register_address=address,
                    unit_id=unit_id,
                    register_type=register_type,
                    register_statements=register_statements,
                    register_summary=summary,
                )

        rel_props = stats.to_properties(oriented_key)
        client_port = oriented_key.src_port

        return self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=src_node_id,
            dest_guid=dst_node_id,
            properties=rel_props,
            relationship_name=self.config.relationship_name,
            source_label="Process",
            dest_label="NetworkService",
            source_ports=[client_port] if client_port > 0 else None,
        )

    def _emit_aggregated_group(
        self,
        group_stats: List[ConnectionStats],
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        ownership_statements: Dict[str, str],
        relationship_statements: List[str],
    ) -> bool:
        """Emit Cypher for an aggregated group of connections. Returns True if a new edge was created."""
        if not group_stats:
            return False

        first = group_stats[0]
        first_key = self._oriented_stats_key(first)
        if first_key is None:
            return self._emit_connection(
                first,
                asset_statements,
                service_statements,
                register_statements,
                process_statements,
                ownership_statements,
                relationship_statements,
            )

        server_ip, server_port = first_key.dst_ip, first_key.dst_port
        client_ip = first_key.src_ip

        client_ips: Set[str] = set()
        for stats in group_stats:
            oriented_key = self._oriented_stats_key(stats)
            if oriented_key is None or oriented_key.dst_port != server_port or oriented_key.dst_ip != server_ip:
                continue
            client_ips.add(oriented_key.src_ip)

        if len(client_ips) > 1:
            client_groups: Dict[str, List[ConnectionStats]] = defaultdict(list)
            for stats in group_stats:
                oriented_key = self._oriented_stats_key(stats)
                if oriented_key is None or oriented_key.dst_port != server_port or oriented_key.dst_ip != server_ip:
                    continue
                client_groups[oriented_key.src_ip].append(stats)

            first_client = next(iter(client_groups.keys()))
            group_stats = client_groups[first_client]
            client_ip = first_client

        total_packets = sum(s.packet_count for s in group_stats)
        first_seen = min(s.first_seen for s in group_stats if s.first_seen != float('inf'))
        last_seen = max(s.last_seen for s in group_stats if s.last_seen > 0)
        unique_client_ports = len(set().union(*(s.client_ports_seen for s in group_stats)))
        bytes_out = 0
        bytes_in = 0

        all_function_codes: Set[int] = set()
        all_unit_ids: Set[int] = set()
        all_registers: Set[int] = set()
        total_transactions = 0
        for stats in group_stats:
            oriented_key = self._oriented_stats_key(stats)
            if oriented_key is not None:
                conn_bytes_out, conn_bytes_in = stats.directional_bytes(oriented_key)
                bytes_out += conn_bytes_out
                bytes_in += conn_bytes_in
            all_function_codes.update(stats.modbus_function_codes)
            all_unit_ids.update(stats.modbus_unit_ids)
            all_registers.update(stats.modbus_registers_seen)
            total_transactions += stats.modbus_transaction_count

        protocols: Dict[str, int] = defaultdict(int)
        for stats in group_stats:
            protocols[stats.high_level_protocol] += stats.packet_count
        dominant_protocol = max(protocols.keys(), key=lambda p: protocols[p]) if protocols else "UNKNOWN"

        client_hostname, client_ip_addr = self._resolve_host(client_ip)
        client_asset_guid = self._ensure_asset_node(client_hostname, client_ip_addr, asset_statements)
        src_node_id = self._ensure_placeholder_process(
            client_hostname, client_asset_guid,
            process_statements, ownership_statements,
        )

        dst_node_id = self._ensure_network_service_node(
            ip=server_ip,
            port=server_port,
            protocol=first.origin.protocol,
            asset_statements=asset_statements,
            service_statements=service_statements,
            process_statements=process_statements,
            ownership_statements=ownership_statements,
        )

        if not src_node_id or not dst_node_id:
            return False

        if server_port == 502:
            server_hostname, server_ip_addr = self._resolve_host(server_ip)
            server_asset_guid = self._ensure_asset_node(
                server_hostname, server_ip_addr, asset_statements,
            )
            register_summaries = self._merge_register_summaries(
                [stats.get_register_summaries() for stats in group_stats]
            )
            for (address, unit_id, register_type), summary in register_summaries.items():
                self._ensure_register_node(
                    host=server_hostname,
                    port=server_port,
                    asset_guid=server_asset_guid,
                    register_address=address,
                    unit_id=unit_id,
                    register_type=register_type,
                    register_statements=register_statements,
                    register_summary=summary,
                )

        rel_props: Dict[str, object] = {
            "pcapAugmented": True,
            "aggregatedConnections": len(group_stats),
            "uniqueClientPorts": unique_client_ports,
            "packetCount": total_packets,
            "bytesOut": bytes_out,
            "bytesIn": bytes_in,
        }

        if total_packets > 0 and (bytes_out > 0 or bytes_in > 0):
            rel_props["avgPacketSize"] = round((bytes_out + bytes_in) / total_packets, 2)

        if first_seen != float('inf') and last_seen > 0:
            rel_props["durationSeconds"] = round(last_seen - first_seen, 3)
            rel_props["firstPacketTime"] = round(first_seen, 3)
            rel_props["lastPacketTime"] = round(last_seen, 3)

        if dominant_protocol != "UNKNOWN":
            rel_props["dominantProtocol"] = dominant_protocol

        if all_function_codes:
            rel_props["modbusFunctionCodes"] = ",".join(str(fc) for fc in sorted(all_function_codes))
        if all_unit_ids:
            rel_props["modbusUnitIds"] = ",".join(str(uid) for uid in sorted(all_unit_ids))
        if all_registers:
            rel_props["modbusRegisterCount"] = len(all_registers)
        if total_transactions > 0:
            rel_props["modbusTransactions"] = total_transactions

        all_client_ports = sorted(set().union(*(s.client_ports_seen for s in group_stats)))
        return self._stage_connect_relationship(
            relationship_statements=relationship_statements,
            source_guid=src_node_id,
            dest_guid=dst_node_id,
            properties=rel_props,
            relationship_name=self.config.relationship_name,
            source_label="Process",
            dest_label="NetworkService",
            source_ports=all_client_ports if all_client_ports else None,
        )

    def _merge_register_summaries(
        self,
        summary_maps: Sequence[Dict[Tuple[int, Optional[int], str], Dict[str, object]]],
    ) -> Dict[Tuple[int, Optional[int], str], Dict[str, object]]:
        """Merge per-connection register summaries into one map."""
        merged: Dict[Tuple[int, Optional[int], str], Dict[str, object]] = {}
        timeline_source_score: Dict[Tuple[int, Optional[int], str], Tuple[int, int, int, int]] = {}
        timeline_points_by_key: Dict[Tuple[int, Optional[int], str], List[Tuple[float, int]]] = defaultdict(list)
        timeline_tolerance_by_key: Dict[Tuple[int, Optional[int], str], List[float]] = defaultdict(list)

        def _to_int(props: Dict[str, object], key: str) -> int:
            value = props.get(key)
            if value in (None, ""):
                return 0
            try:
                return int(value)
            except (TypeError, ValueError):
                try:
                    return int(float(str(value)))
                except (TypeError, ValueError):
                    return 0

        def _to_float(props: Dict[str, object], key: str) -> Optional[float]:
            value = props.get(key)
            if value in (None, ""):
                return None
            try:
                return float(value)
            except (TypeError, ValueError):
                return None

        def _parse_top_values(encoded: object) -> Dict[int, int]:
            if not encoded:
                return {}
            result: Dict[int, int] = {}
            for token in str(encoded).split(","):
                if ":" not in token:
                    continue
                value_raw, count_raw = token.split(":", 1)
                try:
                    result[int(value_raw)] = result.get(int(value_raw), 0) + int(count_raw)
                except (TypeError, ValueError):
                    continue
            return result

        def _parse_function_codes(encoded: object) -> Set[int]:
            if not encoded:
                return set()
            parsed: Set[int] = set()
            for token in str(encoded).split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    parsed.add(int(token))
                except ValueError:
                    continue
            return parsed

        def _summary_score(props: Dict[str, object]) -> Tuple[int, int, int, int]:
            """Rank compressed summaries by detail richness.

            Prefer summaries with:
            1) more SDT points,
            2) more distinct values,
            3) more RLE runs,
            4) more samples.
            """
            return (
                _to_int(props, "timelinePoints"),
                _to_int(props, "distinctValues"),
                _to_int(props, "rleRuns"),
                _to_int(props, "valueSamples"),
            )

        def _parse_timeline(encoded: object) -> List[Tuple[float, int]]:
            if not encoded:
                return []
            text = str(encoded).strip()
            if not text.startswith("@") or "|" not in text:
                return []

            try:
                base_raw, points_raw = text[1:].split("|", 1)
                base_ts = float(base_raw)
            except (TypeError, ValueError):
                return []

            parsed: List[Tuple[float, int]] = []
            for token in points_raw.split(","):
                if ":" not in token:
                    continue
                dt_raw, value_raw = token.split(":", 1)
                try:
                    ts = base_ts + float(dt_raw)
                    value = int(float(value_raw))
                except (TypeError, ValueError):
                    continue
                parsed.append((ts, value))
            return parsed

        for summary_map in summary_maps:
            for key, incoming in summary_map.items():
                incoming_dict = dict(incoming)
                incoming_samples = _to_int(incoming_dict, "valueSamples")
                incoming_last_seen = _to_float(incoming_dict, "lastSeenAt")
                incoming_last_write = _to_float(incoming_dict, "lastWriteAt")
                incoming_tolerance = _to_float(incoming_dict, "sdtTolerance")
                parsed_timeline = _parse_timeline(incoming_dict.get("valueTimeline"))
                if parsed_timeline:
                    timeline_points_by_key[key].extend(parsed_timeline)
                if incoming_tolerance is not None and incoming_tolerance > 0:
                    timeline_tolerance_by_key[key].append(incoming_tolerance)

                if key not in merged:
                    merged[key] = incoming_dict
                    timeline_source_score[key] = _summary_score(incoming_dict)
                    continue

                current = merged[key]
                current_samples = _to_int(current, "valueSamples")
                current_mean = _to_float(current, "meanValue") or 0.0
                incoming_mean = _to_float(incoming_dict, "meanValue") or 0.0
                combined_samples = current_samples + incoming_samples

                for field in ("readCount", "writeCount", "valueSamples", "stateChanges"):
                    total = _to_int(current, field) + _to_int(incoming_dict, field)
                    if total > 0:
                        current[field] = total

                if combined_samples > 0:
                    weighted_mean = (
                        (current_mean * current_samples) + (incoming_mean * incoming_samples)
                    ) / combined_samples
                    current["meanValue"] = round(weighted_mean, 3)

                current_min = _to_float(current, "minValue")
                incoming_min = _to_float(incoming_dict, "minValue")
                if incoming_min is not None and (current_min is None or incoming_min < current_min):
                    current["minValue"] = int(incoming_min)

                current_max = _to_float(current, "maxValue")
                incoming_max = _to_float(incoming_dict, "maxValue")
                if incoming_max is not None and (current_max is None or incoming_max > current_max):
                    current["maxValue"] = int(incoming_max)

                current["distinctValues"] = max(
                    _to_int(current, "distinctValues"),
                    _to_int(incoming_dict, "distinctValues"),
                )

                current_last_seen = _to_float(current, "lastSeenAt")
                if incoming_last_seen is not None and (
                    current_last_seen is None or incoming_last_seen > current_last_seen
                ):
                    current["lastSeenAt"] = round(incoming_last_seen, 3)
                    if "lastValue" in incoming_dict:
                        current["lastValue"] = incoming_dict["lastValue"]
                    if "lastFunctionCode" in incoming_dict:
                        current["lastFunctionCode"] = incoming_dict["lastFunctionCode"]

                current_last_write = _to_float(current, "lastWriteAt")
                if incoming_last_write is not None and (
                    current_last_write is None or incoming_last_write > current_last_write
                ):
                    current["lastWriteAt"] = round(incoming_last_write, 3)

                current_funcs = _parse_function_codes(current.get("observedFunctions"))
                incoming_funcs = _parse_function_codes(incoming_dict.get("observedFunctions"))
                all_funcs = sorted(current_funcs | incoming_funcs)
                if all_funcs:
                    current["observedFunctions"] = ",".join(str(code) for code in all_funcs)

                top_values = _parse_top_values(current.get("topValues"))
                for value, count in _parse_top_values(incoming_dict.get("topValues")).items():
                    top_values[value] = top_values.get(value, 0) + count
                if top_values:
                    ordered = sorted(top_values.items(), key=lambda item: (-item[1], item[0]))[:4]
                    current["topValues"] = ",".join(f"{value}:{count}" for value, count in ordered)

                # Preserve truncation signal if any contributing chunk was truncated.
                if current.get("rleTruncated") or incoming_dict.get("rleTruncated"):
                    current["rleTruncated"] = True

                # Keep compressed timeline fields from the most informative summary.
                incoming_score = _summary_score(incoming_dict)
                if incoming_score > timeline_source_score.get(key, (0, 0, 0, 0)):
                    for field in (
                        "valueRLE",
                        "rleRuns",
                        "rleCompressionRatio",
                        "rleTruncated",
                        "valueTimeline",
                        "timelinePoints",
                        "compressionRatio",
                        "sdtTolerance",
                        "sdtRecompressions",
                    ):
                        if field in incoming_dict:
                            current[field] = incoming_dict[field]
                    timeline_source_score[key] = incoming_score

        # Rebuild SDT timelines from all contributing timeline points per register.
        for key, summary in merged.items():
            points = timeline_points_by_key.get(key) or []
            if not points:
                continue

            points.sort(key=lambda item: item[0])
            deduped: List[Tuple[float, int]] = []
            for ts, val in points:
                if not deduped or deduped[-1] != (ts, val):
                    deduped.append((ts, val))

            tolerances = timeline_tolerance_by_key.get(key) or []
            seed_tolerance = min(tolerances) if tolerances else 1.0
            sdt = _SDTCompressor(tolerance=seed_tolerance, max_points=100)
            for ts, val in deduped:
                sdt.add(ts, val)
            timeline = sdt.encode_timeline()
            if timeline:
                summary["valueTimeline"] = timeline
                summary["timelinePoints"] = len(sdt.points)
                summary["sdtTolerance"] = sdt.tolerance
                if sdt.recompression_count > 0:
                    summary["sdtRecompressions"] = sdt.recompression_count
                elif "sdtRecompressions" in summary:
                    del summary["sdtRecompressions"]

        # Recompute ratios against merged sample counts to keep fields consistent.
        for summary in merged.values():
            samples = _to_int(summary, "valueSamples")
            rle_runs = _to_int(summary, "rleRuns")
            timeline_points = _to_int(summary, "timelinePoints")

            if samples > 0 and rle_runs > 0:
                summary["rleCompressionRatio"] = round(samples / rle_runs, 2)
            if samples > 0 and timeline_points > 0:
                summary["compressionRatio"] = round(samples / timeline_points, 2)

        return merged

    def _generate_process_register_access(
        self,
        process_context: ProcessContext,
        register_summaries: Dict[Tuple[int, Optional[int], str], Dict[str, object]],
        server_hostname: str,
        server_port: int,
        correlation_confidence: float,
    ) -> Tuple[List[str], int]:
        """Generate READ/WRITE_SIGNAL relationship statements for process attribution."""
        statements: List[str] = []
        edge_count = 0
        if not register_summaries:
            return [], 0

        proc_guid_escaped = cypher_emit.escape_cypher_string(process_context.process_guid)
        for (register_address, unit_id, register_type), summary in register_summaries.items():
            register_guid = _generate_node_guid_v2_braced(
                "Register",
                server_hostname,
                server_port,
                unit_id,
                register_address,
                register_type,
            )
            register_guid_escaped = cypher_emit.escape_cypher_string(register_guid)

            read_count = int(summary.get("readCount") or 0)
            write_count = int(summary.get("writeCount") or 0)

            common_props: Dict[str, object] = {
                "correlationConfidence": round(correlation_confidence, 4),
                "inferredFrom": "pcap",
                "pcapAugmented": True,
                "processImage": process_context.process_image,
                "processId": process_context.process_id,
            }

            if read_count > 0:
                read_props = {**common_props, "readCount": read_count}
                if "lastSeenAt" in summary:
                    read_props["lastSeenAt"] = summary["lastSeenAt"]
                cypher_props = cypher_emit.format_properties(read_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:ICSSignal {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:READ_SIGNAL]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true;"
                )
                edge_count += 1

            if write_count > 0:
                write_props = {**common_props, "writeCount": write_count}
                if "lastWriteAt" in summary:
                    write_props["lastWriteAt"] = summary["lastWriteAt"]
                cypher_props = cypher_emit.format_properties(write_props)
                statements.append(
                    f"MATCH (proc:Process {{guid: '{proc_guid_escaped}'}})\n"
                    f"MATCH (reg:ICSSignal {{guid: '{register_guid_escaped}'}})\n"
                    f"MERGE (proc)-[acc:WRITE_SIGNAL]->(reg)\n"
                    f"SET acc += {cypher_props}\n"
                    f"SET acc.pcapAugmented = true;"
                )
                edge_count += 1

        return statements, edge_count

    def _ensure_asset_node(
        self,
        hostname: str,
        ip_address: str,
        asset_statements: Dict[str, str],
    ) -> str:
        """Ensure a NetworkEndpoint MERGE statement exists for the given host (matches batch)."""
        guid = _generate_node_guid("NetworkEndpoint", hostname)
        known = self._is_known_host(ip_address)
        if ip_address and ip_address not in self._asset_ip_map:
            self._asset_ip_map[ip_address] = hostname
        if guid not in asset_statements:
            props = {
                "guid": guid,
                "hostname": hostname,
                "ipAddress": ip_address,
                "ipAddresses": [ip_address] if ip_address else [],
                "isExternal": not known,
                "isManaged": known,
                "source": "pcap",
            }
            asset_statements[guid] = cypher_emit.create_asset_statement(guid, props)
        return guid

    def _ensure_register_node(
        self,
        host: str,
        port: int,
        asset_guid: str,
        register_address: int,
        unit_id: Optional[int],
        register_type: str,
        register_statements: Dict[str, str],
        register_summary: Optional[Dict[str, object]] = None,
    ) -> None:
        """Ensure a Modbus ICSSignal node and ownership edges exist in output (matches batch)."""
        if not asset_guid:
            return
        signal_key = protocol_utils.generate_signal_key(
            "modbus", host, port,
            unit_id if unit_id is not None else "none",
            register_type, register_address,
        )
        register_guid = protocol_utils.generate_signal_guid(
            "modbus", host, port,
            unit_id, register_type, register_address,
        )
        if register_guid in register_statements:
            return
        props: Dict[str, object] = {
            "guid": register_guid,
            "signalKey": signal_key,
            "protocol": "modbus",
            "host": host,
            "address": register_address,
            "port": port,
            "source": "pcap",
            "signalKind": "register",
        }
        if unit_id is not None:
            props["unitId"] = unit_id
        props["registerType"] = register_type
        props["modbusAddress"] = register_address
        props["modbusRegisterType"] = register_type
        if unit_id is not None:
            props["modbusUnitId"] = unit_id
        if register_summary:
            props.update(register_summary)
        register_statements[register_guid] = cypher_emit.create_ics_signal_statement(
            signal_guid=register_guid,
            properties=props,
            endpoint_guid=asset_guid,
        )

    def _ensure_placeholder_process(
        self,
        hostname: str,
        asset_guid: str,
        process_statements: Dict[str, str],
        ownership_statements: Dict[str, str],
    ) -> Optional[str]:
        """Create/return placeholder Process node for PLC/RTU (matches batch)."""
        if hostname not in self._known_hostnames:
            return None
        # Skip runtime for managed hosts that have Sysmon/log telemetry
        metadata = self._asset_metadata.get(hostname)
        if metadata and metadata.has_logs:
            return None
        if hostname in self._placeholder_processes:
            return self._placeholder_processes[hostname]

        process_guid = f"runtime://{hostname}"
        if process_guid not in process_statements:
            process_props = {
                "guid": process_guid,
                "image": f"{hostname} Runtime",
                "processName": f"{hostname} Runtime",
                "type": "Virtual Process",
                "computer": hostname,
                "host": hostname,
                "source": "pcap",
                "note": f"Placeholder process for {hostname} (no host telemetry available)",
            }
            process_statements[process_guid] = cypher_emit.create_virtual_process_statement(
                process_guid,
                process_props,
            )

        run_on_key = f"{asset_guid}|{process_guid}"
        if run_on_key not in ownership_statements:
            ownership_statements[run_on_key] = cypher_emit.create_run_on_relationship_statement(
                asset_guid,
                process_guid,
            )

        self._placeholder_processes[hostname] = process_guid
        return process_guid

    def _service_name_for_port(self, port: int) -> str:
        if port <= 0:
            return "Ephemeral Service"
        return self.config.service_map.get(port, f"Port {port}")

    def _ensure_network_service_node(
        self,
        ip: str,
        port: int,
        protocol: str,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        process_statements: Optional[Dict[str, str]] = None,
        ownership_statements: Optional[Dict[str, str]] = None,
        service_name: Optional[str] = None,
        aggregation: Optional[str] = None,
        note: Optional[str] = None,
    ) -> str:
        """Ensure a NetworkService MERGE statement exists and return its guid (matches batch)."""
        hostname, ip_address = self._resolve_host(ip)
        asset_guid = self._ensure_asset_node(hostname, ip_address, asset_statements)
        normalized_port = port if port and port >= 0 else 0
        normalized_protocol = _normalize_transport_protocol(protocol)
        service_guid = _generate_network_service_guid(hostname, normalized_port, normalized_protocol)

        if service_guid not in service_statements:
            props: Dict[str, object] = {
                "guid": service_guid,
                "host": hostname,
                "port": normalized_port,
                "protocol": normalized_protocol.upper(),
                "serviceName": service_name or self._service_name_for_port(normalized_port),
                "ipAddress": ip_address,
                "source": "pcap",
            }
            if aggregation:
                props["aggregation"] = aggregation
            if note:
                props["note"] = note

            service_statements[service_guid] = cypher_emit.create_network_service_statement(
                service_guid,
                props,
                asset_guid,
            )

        if process_statements is not None and ownership_statements is not None:
            owner_guid = self._ensure_placeholder_process(
                hostname,
                asset_guid,
                process_statements,
                ownership_statements,
            )
            if owner_guid is not None:
                binds_key = f"{owner_guid}|{service_guid}|BINDS"
                if binds_key not in ownership_statements:
                    ownership_statements[binds_key] = cypher_emit.create_binds_relationship_statement(
                        owner_guid,
                        service_guid,
                    )

        return service_guid

    def _write_output(
        self,
        asset_statements: Dict[str, str],
        service_statements: Dict[str, str],
        register_statements: Dict[str, str],
        process_statements: Dict[str, str],
        ownership_statements: Dict[str, str],
        relationship_statements: List[str],
        edge_update_statements: List[str],
        process_register_statements: List[str],
    ) -> None:
        """Write augmented Cypher to output file."""
        import shutil
        shutil.copy(self.config.base_cypher, self.config.output_cypher)

        with open(self.config.output_cypher, "a") as f:
            f.write("\n// === PCAP Augmentation (Streaming Mode with Correlation) ===\n\n")

            # Edge updates for correlated connections
            if edge_update_statements:
                f.write("// Edge updates for correlated telemetry connections\n")
                for stmt in edge_update_statements:
                    f.write(stmt + "\n")
                f.write("\n")

            # Process-to-signal relationships
            if process_register_statements:
                f.write("// READ/WRITE_SIGNAL relationships for process attribution\n")
                for stmt in process_register_statements:
                    f.write(stmt + "\n")
                f.write("\n")

            # New nodes for PCAP-only connections
            if asset_statements:
                f.write("// NetworkEndpoint nodes for PCAP-only connections\n")
                for stmt in sorted(asset_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if service_statements:
                f.write("// NetworkService nodes for PCAP-only connections\n")
                for stmt in sorted(service_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if register_statements:
                f.write("// PCAP-Inferred ICSSignal Nodes\n")
                for stmt in sorted(register_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if process_statements:
                f.write("// Virtual Process Nodes for inferred services\n")
                for stmt in sorted(process_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            if ownership_statements:
                f.write("// Process Ownership Relationships (RUN_ON/BINDS)\n")
                for stmt in sorted(ownership_statements.values()):
                    f.write(stmt + "\n")
                f.write("\n")

            # New relationships for PCAP-only connections
            if relationship_statements:
                f.write("// New relationships for PCAP-only connections\n")
                for stmt in relationship_statements:
                    f.write(stmt + "\n")

    def _print_summary(self) -> None:
        """Print correlation statistics summary."""
        print("\n=== Streaming Augmentation Summary ===")
        print(f"Total PCAP connections: {self._correlation_stats.total_pcap_connections}")
        print(f"Correlation attempts: {self._correlation_stats.correlation_attempts}")
        if self._correlation_stats.correlation_attempts > 0:
            rate = 100.0 * self._correlation_stats.successful_correlations / self._correlation_stats.correlation_attempts
            print(f"Successful correlations: {self._correlation_stats.successful_correlations} ({rate:.1f}%)")
        else:
            print(f"Successful correlations: {self._correlation_stats.successful_correlations}")
        print(f"  - Session port matches: {self._correlation_stats.session_port_matches}")
        print(f"PCAP-only connections: {self._correlation_stats.pcap_only_connections}")
        print(f"Process-attributed signals: {self._correlation_stats.process_attributed_registers}")
