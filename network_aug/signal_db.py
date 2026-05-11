"""DuckDB storage for raw signal observations.

This module provides storage for Modbus signal observations in DuckDB,
replacing the compressed in-Neo4j storage (SDT/RLE/duty cycle).
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
import logging

logger = logging.getLogger(__name__)

# Column names in order - used for fast pandas insertion
OBSERVATION_COLUMNS = (
    "timestamp",
    "register_address",
    "value",
    "access_type",
    "function_code",
    "unit_id",
    "client_host",
    "server_host",
    "client_ip",
    "server_ip",
    "transaction_id",
    "request_timestamp",
    "response_timestamp",
    "write_acknowledged",
    "signal_container_guid",
    "pcap_file",
)

# Type alias for observation tuples (matches OBSERVATION_COLUMNS order)
ObservationTuple = Tuple[
    float,  # timestamp
    int,  # register_address
    int,  # value
    str,  # access_type
    int,  # function_code
    Optional[int],  # unit_id
    str,  # client_host
    str,  # server_host
    str,  # client_ip
    str,  # server_ip
    Optional[int],  # transaction_id
    Optional[float],  # request_timestamp
    Optional[float],  # response_timestamp
    Optional[bool],  # write_acknowledged
    str,  # signal_container_guid
    str,  # pcap_file
]


@dataclass
class SignalObservation:
    """Single signal observation for DuckDB storage."""

    timestamp: float
    """Observation timestamp (Unix epoch seconds)."""

    register_address: int
    """Modbus register address (e.g., 40001)."""

    value: int
    """Observed register value."""

    access_type: str
    """Access type: 'read' or 'write'."""

    function_code: int
    """Modbus function code (1-6, 15, 16, 23)."""

    unit_id: Optional[int]
    """Modbus unit ID."""

    client_host: str
    """Hostname of the client (requester)."""

    server_host: str
    """Hostname of the server (responder)."""

    client_ip: str
    """IP address of the client."""

    server_ip: str
    """IP address of the server."""

    transaction_id: Optional[int]
    """Modbus transaction ID for request/response correlation."""

    request_timestamp: Optional[float]
    """Timestamp of the request packet."""

    response_timestamp: Optional[float]
    """Timestamp of the response packet (NULL if write not acknowledged)."""

    write_acknowledged: Optional[bool]
    """For writes: True if acknowledged, False if not, None if pending. NULL for reads."""

    signal_container_guid: str
    """GUID of the Neo4j SignalContainer reference node."""

    pcap_file: str
    """Source PCAP file name."""


class SignalDatabase:
    """Manages DuckDB connection and signal observation storage."""

    TABLE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS signal_observations (
        timestamp DOUBLE NOT NULL,
        register_address INTEGER NOT NULL,
        value INTEGER NOT NULL,
        access_type VARCHAR NOT NULL,
        function_code INTEGER NOT NULL,
        unit_id INTEGER,
        client_host VARCHAR NOT NULL,
        server_host VARCHAR NOT NULL,
        client_ip VARCHAR NOT NULL,
        server_ip VARCHAR NOT NULL,
        transaction_id INTEGER,
        request_timestamp DOUBLE,
        response_timestamp DOUBLE,
        write_acknowledged BOOLEAN,
        signal_container_guid VARCHAR NOT NULL,
        pcap_file VARCHAR NOT NULL
    );
    """

    # Indexes are dropped during bulk load and recreated on close() / first read.
    # Each insert otherwise pays O(log N) per index — five indexes × tens-of-millions
    # of rows is the dominant cost in the profile (~26% of total).
    INDEX_DEFS: Tuple[Tuple[str, str], ...] = (
        ("idx_signal_container", "signal_observations(signal_container_guid)"),
        ("idx_register", "signal_observations(register_address, unit_id)"),
        ("idx_timestamp", "signal_observations(timestamp)"),
        ("idx_access_type", "signal_observations(access_type)"),
        ("idx_transaction", "signal_observations(transaction_id)"),
    )

    PENDING_ACK_SCHEMA = """
    DROP TABLE IF EXISTS _pending_write_acks;
    CREATE TABLE _pending_write_acks (
        client_ip VARCHAR NOT NULL,
        server_ip VARCHAR NOT NULL,
        transaction_id INTEGER NOT NULL,
        response_timestamp DOUBLE NOT NULL,
        acknowledged BOOLEAN NOT NULL
    );
    """

    # Buffer ack rows in Python and ship to DuckDB in batches; avoids the
    # one-INSERT-per-call overhead that the per-row UPDATE used to have.
    _ACK_BUFFER_FLUSH = 50_000

    def __init__(self, db_path: Path) -> None:
        """Initialize DuckDB connection and create schema if needed.

        Args:
            db_path: Path to the DuckDB database file.
        """
        try:
            import duckdb
        except ImportError as e:
            raise ImportError(
                "DuckDB is required for signal storage. "
                "Install it with: pip install duckdb"
            ) from e

        self._db_path = Path(db_path)
        self._conn = duckdb.connect(str(self._db_path))
        self._pending_writes: Dict[tuple, int] = {}  # (client_ip, server_ip, transaction_id) -> row_id
        # In-memory ack buffer; flushed into _pending_write_acks in batches.
        self._ack_buffer: List[Tuple[str, str, int, float, bool]] = []
        self._pending_ack_count: int = 0
        # Indexes are absent during bulk-load and rebuilt on close()/first read.
        self._indexes_built: bool = False
        self._create_schema()
        logger.info("Opened signal database at %s", self._db_path)

    def _create_schema(self) -> None:
        """Create the table and ack staging table; defer index creation to close()."""
        self._conn.execute(self.TABLE_SCHEMA)
        self._conn.execute(self.PENDING_ACK_SCHEMA)
        # If reopening a populated DB the indexes may already exist — keep them so
        # downstream readers (geco/invariants) keep working without a rebuild.
        existing = {
            row[0] for row in self._conn.execute(
                "SELECT index_name FROM duckdb_indexes() WHERE table_name = 'signal_observations'"
            ).fetchall()
        }
        wanted = {name for name, _ in self.INDEX_DEFS}
        self._indexes_built = wanted.issubset(existing)
        if not self._indexes_built and existing & wanted:
            # Partial state from a crashed run — rebuild from scratch on close().
            for name in existing & wanted:
                self._conn.execute(f"DROP INDEX IF EXISTS {name}")
        logger.debug(
            "Signal database schema ready (indexes_built=%s)", self._indexes_built
        )

    def _ensure_indexes(self) -> None:
        """Create the read indexes if they aren't already present."""
        if self._indexes_built:
            return
        for name, definition in self.INDEX_DEFS:
            self._conn.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {definition}")
        self._indexes_built = True
        logger.info("Built %d signal_observations indexes", len(self.INDEX_DEFS))

    def insert_observation(self, observation: SignalObservation) -> int:
        """Insert a single signal observation.

        Args:
            observation: The observation to insert.

        Returns:
            The row ID of the inserted observation.
        """
        result = self._conn.execute(
            """
            INSERT INTO signal_observations (
                timestamp, register_address, value, access_type, function_code,
                unit_id, client_host, server_host, client_ip, server_ip,
                transaction_id, request_timestamp, response_timestamp,
                write_acknowledged, signal_container_guid, pcap_file
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
            """,
            [
                observation.timestamp,
                observation.register_address,
                observation.value,
                observation.access_type,
                observation.function_code,
                observation.unit_id,
                observation.client_host,
                observation.server_host,
                observation.client_ip,
                observation.server_ip,
                observation.transaction_id,
                observation.request_timestamp,
                observation.response_timestamp,
                observation.write_acknowledged,
                observation.signal_container_guid,
                observation.pcap_file,
            ],
        )
        row_id = result.fetchone()[0]
        return row_id

    def insert_batch(self, observations: Sequence[SignalObservation]) -> int:
        """Bulk insert observations for performance.

        Args:
            observations: List of observations to insert.

        Returns:
            Number of observations inserted.
        """
        if not observations:
            return 0

        # Convert to list of tuples for batch insert
        values = [
            (
                obs.timestamp,
                obs.register_address,
                obs.value,
                obs.access_type,
                obs.function_code,
                obs.unit_id,
                obs.client_host,
                obs.server_host,
                obs.client_ip,
                obs.server_ip,
                obs.transaction_id,
                obs.request_timestamp,
                obs.response_timestamp,
                obs.write_acknowledged,
                obs.signal_container_guid,
                obs.pcap_file,
            )
            for obs in observations
        ]

        self._conn.executemany(
            """
            INSERT INTO signal_observations (
                timestamp, register_address, value, access_type, function_code,
                unit_id, client_host, server_host, client_ip, server_ip,
                transaction_id, request_timestamp, response_timestamp,
                write_acknowledged, signal_container_guid, pcap_file
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )

        logger.debug("Inserted %d signal observations", len(observations))
        return len(observations)

    def insert_tuples_fast(self, tuples: Sequence[ObservationTuple]) -> int:
        """Bulk insert observation tuples via DuckDB's pandas replacement scan.

        Indexes are *not* maintained during this call — they are built once at
        :meth:`close` (or on first read). This avoids paying O(log N) per index
        per row during ingest, which dominated the original profile.

        Args:
            tuples: List of tuples matching OBSERVATION_COLUMNS order.

        Returns:
            Number of observations inserted.
        """
        if not tuples:
            return 0

        try:
            import pandas as pd
        except ImportError as e:
            logger.warning("pandas not available, falling back to slow insert")
            observations = [SignalObservation(*t) for t in tuples]
            return self.insert_batch(observations)

        df = pd.DataFrame(tuples, columns=OBSERVATION_COLUMNS)
        self._conn.execute("INSERT INTO signal_observations SELECT * FROM df")

        logger.debug("Fast-inserted %d signal observations", len(tuples))
        return len(tuples)

    def update_write_acknowledgment(
        self,
        client_ip: str,
        server_ip: str,
        transaction_id: int,
        response_timestamp: float,
        acknowledged: bool = True,
    ) -> int:
        """Buffer a write-ack for later bulk application.

        Originally ran an UPDATE per call, which triggered a full index scan on
        every Modbus write response and dominated runtime at scale (912k UPDATEs
        = 760s of the 2461s Pipedream 1hr profile). We now buffer acks in
        memory, ship them to a staging table in batches, and resolve them in
        one UPDATE FROM during :meth:`flush_write_acks` — called automatically
        from :meth:`close` and any read accessor.

        Returns:
            Always 0 — actual row counts are only known after flush.
        """
        self._ack_buffer.append(
            (client_ip, server_ip, transaction_id, response_timestamp, acknowledged)
        )
        if len(self._ack_buffer) >= self._ACK_BUFFER_FLUSH:
            self._spill_ack_buffer()
        return 0

    def _spill_ack_buffer(self) -> None:
        """Move the in-memory ack buffer into the DuckDB staging table."""
        if not self._ack_buffer:
            return
        try:
            import pandas as pd
        except ImportError:
            # Fallback: row-by-row INSERT — slow, but correctness preserved.
            self._conn.executemany(
                "INSERT INTO _pending_write_acks VALUES (?, ?, ?, ?, ?)",
                self._ack_buffer,
            )
        else:
            df = pd.DataFrame(
                self._ack_buffer,
                columns=("client_ip", "server_ip", "transaction_id",
                         "response_timestamp", "acknowledged"),
            )
            self._conn.execute("INSERT INTO _pending_write_acks SELECT * FROM df")
        self._pending_ack_count += len(self._ack_buffer)
        self._ack_buffer.clear()

    def flush_write_acks(self) -> int:
        """Apply all buffered write acks to signal_observations in one UPDATE.

        Returns:
            Number of staged ack rows that were applied. Note: this is the
            staging-row count, not the count of signal_observations rows
            actually updated (which may differ if some txids never had a
            matching write in the table).
        """
        self._spill_ack_buffer()
        if self._pending_ack_count == 0:
            return 0

        staged = self._pending_ack_count
        # UPDATE FROM pattern: one statement does the join+update for every
        # buffered ack; replaces 912k row-by-row UPDATEs in the original code.
        self._conn.execute(
            """
            UPDATE signal_observations AS s
            SET write_acknowledged = a.acknowledged,
                response_timestamp = a.response_timestamp
            FROM _pending_write_acks AS a
            WHERE s.client_ip = a.client_ip
              AND s.server_ip = a.server_ip
              AND s.transaction_id = a.transaction_id
              AND s.access_type = 'write'
              AND s.write_acknowledged IS NULL
            """
        )
        self._conn.execute("DELETE FROM _pending_write_acks")
        self._pending_ack_count = 0
        logger.info("Flushed %d staged write acks", staged)
        return staged

    def get_observation_count(self) -> int:
        """Return total number of observations in the database."""
        if self._ack_buffer or self._pending_ack_count:
            self.flush_write_acks()
        self._ensure_indexes()
        result = self._conn.execute("SELECT COUNT(*) FROM signal_observations")
        return result.fetchone()[0]

    def get_statistics(self) -> Dict[str, int]:
        """Return statistics about stored observations."""
        if self._ack_buffer or self._pending_ack_count:
            self.flush_write_acks()
        self._ensure_indexes()
        stats = {}

        # Total count
        stats["total"] = self.get_observation_count()

        # By access type
        result = self._conn.execute(
            """
            SELECT access_type, COUNT(*)
            FROM signal_observations
            GROUP BY access_type
            """
        )
        for row in result.fetchall():
            stats[f"access_{row[0]}"] = row[1]

        # Write acknowledgment stats
        result = self._conn.execute(
            """
            SELECT write_acknowledged, COUNT(*)
            FROM signal_observations
            WHERE access_type = 'write'
            GROUP BY write_acknowledged
            """
        )
        for row in result.fetchall():
            if row[0] is None:
                stats["writes_pending"] = row[1]
            elif row[0]:
                stats["writes_acknowledged"] = row[1]
            else:
                stats["writes_unacknowledged"] = row[1]

        # Unique registers
        result = self._conn.execute(
            "SELECT COUNT(DISTINCT register_address) FROM signal_observations"
        )
        stats["unique_registers"] = result.fetchone()[0]

        # Unique signal containers
        result = self._conn.execute(
            "SELECT COUNT(DISTINCT signal_container_guid) FROM signal_observations"
        )
        stats["unique_signals"] = result.fetchone()[0]

        return stats

    def close(self) -> None:
        """Flush pending acks, build indexes, and close the database connection."""
        if self._conn:
            try:
                if self._pending_ack_count:
                    self.flush_write_acks()
                self._conn.execute("DROP TABLE IF EXISTS _pending_write_acks")
                self._ensure_indexes()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to finalize signal DB during close: %s", exc)
            self._conn.close()
            logger.info("Closed signal database at %s", self._db_path)
            self._conn = None

    def __enter__(self) -> "SignalDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
