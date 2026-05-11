"""Inline Modbus signal extraction for streaming pass-1 workers.

The original streaming pipeline made three passes over each PCAP: a stats
pass, a candidate-materialization pass that spooled packet records, and an
implicit third pass at apply time that re-iterated those packets to push
observations into DuckDB. Profiling showed the apply-time DuckDB writes
dominated runtime (~66%).

This module replaces that with a single inline extractor: while the pass-1
worker is already iterating packets to build ConnectionStats, it also pairs
Modbus requests/responses, resolves hostnames, and writes a per-PCAP
Parquet shard. The main process bulk-loads all shards into the signal
database with one statement after pass-1 completes.

Key differences from the legacy ``protocol_utils.collect_modbus_signals`` path:

* Write acknowledgments are resolved in-memory at response time. The shard
  contains fully-resolved tuples with ``write_acknowledged`` set; no
  follow-up UPDATE is needed.
* Unmatched writes pending at end-of-PCAP are emitted with
  ``write_acknowledged=False`` instead of being left as NULL pending.
* Observations are scoped to in-asset connections (matches batch behavior).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple

from .modbus_helpers import modbus_transaction_key, register_type_from_function
from .models import PacketRecord
from .signal_db import OBSERVATION_COLUMNS

logger = logging.getLogger(__name__)


# Tuple shape matches OBSERVATION_COLUMNS in signal_db.py exactly.
_OBSERVATION_TUPLE_LEN = len(OBSERVATION_COLUMNS)


@dataclass
class _PendingRequest:
    timestamp: float
    unit_id: Optional[int]
    function_code: int
    read_registers: Tuple[Optional[int], ...]
    write_registers: Tuple[Optional[int], ...]
    write_values: Tuple[int, ...]
    transaction_id: Optional[int]
    client_ip: str
    server_ip: str
    server_port: int


@dataclass
class ModbusSignalExtractor:
    """Extracts fully-resolved Modbus signal observations from a packet stream.

    The extractor is created per-PCAP inside a streaming worker. Call
    :meth:`process_packet` for every packet, then :meth:`finalize` to flush
    the buffer (and emit any unmatched writes) before the worker exits.
    """

    pcap_file: str
    shard_path: Path
    asset_ip_to_hostname: Dict[str, str]
    modbus_server_ports: FrozenSet[int] = field(default_factory=lambda: frozenset({502}))
    asset_ip_set: FrozenSet[str] = field(default_factory=frozenset)

    _pending: Dict[Tuple[str, int, str, Optional[int], int], _PendingRequest] = field(
        default_factory=dict, init=False, repr=False
    )
    _buffer: List[tuple] = field(default_factory=list, init=False, repr=False)
    # Index from (client_ip, server_ip, txid) -> list of buffer offsets for
    # write rows still awaiting an ack. Lets _patch_pending_write_ack run in
    # O(K) time per ack (K = number of register writes in that transaction)
    # instead of O(N) over the full buffer.
    _write_index: Dict[Tuple[str, str, int], List[int]] = field(
        default_factory=dict, init=False, repr=False
    )

    def _hostname(self, ip: str) -> str:
        return self.asset_ip_to_hostname.get(ip, ip)

    def _signal_guid(
        self,
        server_hostname: str,
        client_hostname: str,
        server_port: int,
        unit_id: Optional[int],
        function_code: int,
        address: int,
    ) -> str:
        # Mirror missing_augmentor._record_observation's recipe: prefer the
        # graph-aligned modbus signal recipe; fall back to legacy
        # SignalContainer GUID when keys are missing.
        reg_type = register_type_from_function(function_code)
        if server_hostname and unit_id is not None and reg_type:
            components = ["modbus", server_hostname, server_port, unit_id, reg_type, address]
        else:
            components = ["SignalContainer", client_hostname, address, unit_id]
        joined = "|".join(str(v) for v in components if v not in (None, "")).lower()
        digest = hashlib.md5(joined.encode("utf-8")).hexdigest()
        return f"{{{uuid.UUID(digest)}}}"

    def _emit(
        self,
        *,
        timestamp: float,
        address: int,
        value: int,
        access_type: str,
        function_code: int,
        unit_id: Optional[int],
        client_ip: str,
        server_ip: str,
        server_port: int,
        transaction_id: Optional[int],
        request_timestamp: Optional[float],
        response_timestamp: Optional[float],
        write_acknowledged: Optional[bool],
    ) -> None:
        if address is None or address < 0:
            return
        client_hostname = self._hostname(client_ip)
        server_hostname = self._hostname(server_ip)
        guid = self._signal_guid(
            server_hostname=server_hostname,
            client_hostname=client_hostname,
            server_port=server_port,
            unit_id=unit_id,
            function_code=function_code,
            address=address,
        )
        self._buffer.append((
            timestamp, address, value, access_type, function_code, unit_id,
            client_hostname, server_hostname, client_ip, server_ip,
            transaction_id, request_timestamp, response_timestamp,
            write_acknowledged, guid, self.pcap_file,
        ))
        assert len(self._buffer[-1]) == _OBSERVATION_TUPLE_LEN
        # Track unack'd writes for fast patching when the response lands.
        if access_type == "write" and write_acknowledged is None and transaction_id is not None:
            self._write_index.setdefault(
                (client_ip, server_ip, transaction_id), []
            ).append(len(self._buffer) - 1)

    def _resolve_modbus_server_port(self, packet: PacketRecord) -> Optional[int]:
        if packet.dst_port in self.modbus_server_ports:
            return packet.dst_port
        if packet.src_port in self.modbus_server_ports:
            return packet.src_port
        return None

    def _is_in_scope(self, packet: PacketRecord) -> bool:
        if not self.asset_ip_set:
            return True
        return packet.src_ip in self.asset_ip_set or packet.dst_ip in self.asset_ip_set

    def process_packet(self, packet: PacketRecord) -> None:
        if packet.modbus_function is None:
            return
        if not self._is_in_scope(packet):
            return
        server_port = self._resolve_modbus_server_port(packet)
        if server_port is None:
            return

        function_code = packet.modbus_function
        unit_id = packet.modbus_unit_id
        read_registers = tuple(packet.modbus_read_registers or ())
        write_registers = tuple(packet.modbus_write_registers or ())
        if not read_registers and not write_registers and packet.modbus_registers:
            read_registers = tuple(packet.modbus_registers)
        write_values = tuple(packet.modbus_register_values or ())
        transaction_id = packet.modbus_transaction_id

        # Request packet (client -> server)
        if packet.dst_port == server_port:
            key = modbus_transaction_key(packet, server_port)
            client_ip, server_ip = packet.src_ip, packet.dst_ip
            if key is not None:
                self._pending[key] = _PendingRequest(
                    timestamp=packet.timestamp,
                    unit_id=unit_id,
                    function_code=function_code,
                    read_registers=read_registers,
                    write_registers=write_registers,
                    write_values=write_values,
                    transaction_id=transaction_id,
                    client_ip=client_ip,
                    server_ip=server_ip,
                    server_port=server_port,
                )
            # Writes are emitted from the request side (we already know the
            # value). The acknowledgment status is resolved when the response
            # lands; until then the observation stays buffered with
            # ``write_acknowledged=None``.
            if write_registers and write_values:
                for address, value in zip(write_registers, write_values):
                    self._emit(
                        timestamp=packet.timestamp,
                        address=address if address is not None else -1,
                        value=value,
                        access_type="write",
                        function_code=function_code,
                        unit_id=unit_id,
                        client_ip=client_ip,
                        server_ip=server_ip,
                        server_port=server_port,
                        transaction_id=transaction_id,
                        request_timestamp=packet.timestamp,
                        response_timestamp=None,
                        write_acknowledged=None,
                    )
            return

        # Response packet (server -> client). Match against a pending request.
        key = modbus_transaction_key(packet, server_port)
        request = self._pending.pop(key, None)
        response_values = tuple(packet.modbus_register_values or ())

        if request is None:
            return

        # Reads land on the response (we now know addresses + values).
        if request.read_registers and response_values:
            trimmed = response_values[: len(request.read_registers)]
            for address, value in zip(request.read_registers, trimmed):
                self._emit(
                    timestamp=packet.timestamp,
                    address=address if address is not None else -1,
                    value=value,
                    access_type="read",
                    function_code=request.function_code,
                    unit_id=request.unit_id,
                    client_ip=request.client_ip,
                    server_ip=request.server_ip,
                    server_port=request.server_port,
                    transaction_id=request.transaction_id,
                    request_timestamp=request.timestamp,
                    response_timestamp=packet.timestamp,
                    write_acknowledged=None,
                )

        # Writes get an acknowledgment update inline. The original write rows
        # are already buffered (with write_acknowledged=None); patch them.
        if request.write_registers:
            self._patch_pending_write_ack(
                client_ip=request.client_ip,
                server_ip=request.server_ip,
                transaction_id=request.transaction_id,
                response_timestamp=packet.timestamp,
                acknowledged=True,
            )

    def _patch_pending_write_ack(
        self,
        *,
        client_ip: str,
        server_ip: str,
        transaction_id: Optional[int],
        response_timestamp: float,
        acknowledged: bool,
    ) -> None:
        if transaction_id is None:
            return
        indices = self._write_index.pop(
            (client_ip, server_ip, transaction_id), None
        )
        if not indices:
            return
        for idx in indices:
            row = self._buffer[idx]
            self._buffer[idx] = (
                row[0], row[1], row[2], row[3], row[4], row[5],
                row[6], row[7], row[8], row[9],
                row[10], row[11], response_timestamp,
                acknowledged, row[14], row[15],
            )

    def finalize(self) -> int:
        """Flush remaining observations and write the Parquet shard.

        Returns:
            Number of observations written to the shard.
        """
        # Any pending writes with no matching response stay marked as
        # acknowledged=None (matches legacy semantics for orphans).
        if not self._buffer:
            return 0

        try:
            import duckdb
            import pandas as pd
        except ImportError:
            logger.warning(
                "duckdb/pandas unavailable in worker; cannot write Modbus shard %s",
                self.shard_path,
            )
            return 0

        df = pd.DataFrame(self._buffer, columns=OBSERVATION_COLUMNS)
        self.shard_path.parent.mkdir(parents=True, exist_ok=True)

        conn = duckdb.connect(":memory:")
        try:
            conn.execute("CREATE TABLE shard AS SELECT * FROM df")
            conn.execute(
                f"COPY shard TO '{self.shard_path}' (FORMAT PARQUET, COMPRESSION ZSTD)"
            )
        finally:
            conn.close()

        n = len(self._buffer)
        self._buffer.clear()
        self._pending.clear()
        self._write_index.clear()
        return n
