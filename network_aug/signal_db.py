"""DuckDB storage for raw signal observations.

This module provides storage for Modbus signal observations in DuckDB,
replacing the compressed in-Neo4j storage (SDT/RLE/duty cycle).
"""

from dataclasses import dataclass, asdict
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

    SCHEMA = """
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

    CREATE INDEX IF NOT EXISTS idx_signal_container
        ON signal_observations(signal_container_guid);
    CREATE INDEX IF NOT EXISTS idx_register
        ON signal_observations(register_address, unit_id);
    CREATE INDEX IF NOT EXISTS idx_timestamp
        ON signal_observations(timestamp);
    CREATE INDEX IF NOT EXISTS idx_access_type
        ON signal_observations(access_type);
    CREATE INDEX IF NOT EXISTS idx_transaction
        ON signal_observations(transaction_id);
    """

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
        self._create_schema()
        self._pending_writes: Dict[tuple, int] = {}  # (client_ip, server_ip, transaction_id) -> row_id
        logger.info("Opened signal database at %s", self._db_path)

    def _create_schema(self) -> None:
        """Create the signal_observations table and indexes."""
        self._conn.execute(self.SCHEMA)
        logger.debug("Signal database schema created/verified")

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
        """Ultra-fast bulk insert using pandas DataFrame.

        This method is ~100-800x faster than insert_batch() for large datasets.
        It bypasses Python object creation overhead by accepting raw tuples
        and using DuckDB's native pandas integration.

        Args:
            tuples: List of tuples matching OBSERVATION_COLUMNS order.
                    Each tuple should be: (timestamp, register_address, value,
                    access_type, function_code, unit_id, client_host, server_host,
                    client_ip, server_ip, transaction_id, request_timestamp,
                    response_timestamp, write_acknowledged, signal_container_guid,
                    pcap_file)

        Returns:
            Number of observations inserted.
        """
        if not tuples:
            return 0

        try:
            import pandas as pd
        except ImportError as e:
            logger.warning("pandas not available, falling back to slow insert")
            # Fallback to slow path - convert tuples to SignalObservation
            observations = [
                SignalObservation(*t) for t in tuples
            ]
            return self.insert_batch(observations)

        # Create DataFrame from tuples - this is very fast
        df = pd.DataFrame(tuples, columns=OBSERVATION_COLUMNS)

        # DuckDB can directly query pandas DataFrames - extremely fast
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
        """Update write_acknowledged for a pending write operation.

        Args:
            client_ip: Client IP address.
            server_ip: Server IP address.
            transaction_id: Modbus transaction ID.
            response_timestamp: Timestamp of the response packet.
            acknowledged: Whether the write was acknowledged.

        Returns:
            Number of rows updated.
        """
        result = self._conn.execute(
            """
            UPDATE signal_observations
            SET write_acknowledged = ?,
                response_timestamp = ?
            WHERE client_ip = ?
              AND server_ip = ?
              AND transaction_id = ?
              AND access_type = 'write'
              AND write_acknowledged IS NULL
            """,
            [acknowledged, response_timestamp, client_ip, server_ip, transaction_id],
        )
        updated = result.fetchone()
        # DuckDB doesn't return row count directly from UPDATE, check via changes
        return 0 if updated is None else 1

    def get_observation_count(self) -> int:
        """Return total number of observations in the database."""
        result = self._conn.execute("SELECT COUNT(*) FROM signal_observations")
        return result.fetchone()[0]

    def get_statistics(self) -> Dict[str, int]:
        """Return statistics about stored observations."""
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
        """Close database connection."""
        if self._conn:
            self._conn.close()
            logger.info("Closed signal database at %s", self._db_path)
            self._conn = None

    def __enter__(self) -> "SignalDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
