"""DuckDB storage for standalone MQTT and OPC UA signal extraction."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


class _BaseSignalDatabase:
    """Shared DuckDB insert helpers for protocol-specific signal databases."""

    OBSERVATION_COLUMNS: Tuple[str, ...] = ()
    SCHEMA: str = ""

    def __init__(self, db_path: Path) -> None:
        try:
            import duckdb
        except ImportError as e:
            raise ImportError(
                "DuckDB is required for signal storage. "
                "Install it with: pip install duckdb"
            ) from e

        self._db_path = Path(db_path)
        self._conn = duckdb.connect(str(self._db_path))
        self._conn.execute(self.SCHEMA)
        logger.info("Opened protocol signal database at %s", self._db_path)

    def insert_tuples_fast(self, tuples: Sequence[Tuple[object, ...]]) -> int:
        """Bulk insert observations using pandas when available."""
        if not tuples:
            return 0

        try:
            import pandas as pd
        except ImportError:
            placeholders = ", ".join("?" for _ in self.OBSERVATION_COLUMNS)
            column_list = ", ".join(self.OBSERVATION_COLUMNS)
            self._conn.executemany(
                f"INSERT INTO signal_observations ({column_list}) VALUES ({placeholders})",
                tuples,
            )
            return len(tuples)

        df = pd.DataFrame(tuples, columns=self.OBSERVATION_COLUMNS)
        self._conn.execute("INSERT INTO signal_observations SELECT * FROM df")
        return len(tuples)

    def get_statistics(self) -> Dict[str, int]:
        """Return a minimal row-count summary."""
        result = self._conn.execute("SELECT COUNT(*) FROM signal_observations")
        total = result.fetchone()[0]
        return {"total": int(total)}

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            logger.info("Closed protocol signal database at %s", self._db_path)
            self._conn = None

    def __enter__(self) -> "_BaseSignalDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class MqttSignalDatabase(_BaseSignalDatabase):
    """Stores raw numeric MQTT signal observations."""

    OBSERVATION_COLUMNS = (
        "timestamp",
        "topic",
        "field_name",
        "signal_name",
        "value",
        "access_type",
        "client_host",
        "server_host",
        "client_ip",
        "server_ip",
        "packet_id",
        "qos",
        "retain",
        "dup",
        "client_id",
        "signal_guid",
        "pcap_file",
    )

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS signal_observations (
        timestamp DOUBLE NOT NULL,
        topic VARCHAR NOT NULL,
        field_name VARCHAR NOT NULL,
        signal_name VARCHAR NOT NULL,
        value DOUBLE NOT NULL,
        access_type VARCHAR NOT NULL,
        client_host VARCHAR NOT NULL,
        server_host VARCHAR NOT NULL,
        client_ip VARCHAR NOT NULL,
        server_ip VARCHAR NOT NULL,
        packet_id INTEGER,
        qos INTEGER,
        retain BOOLEAN,
        dup BOOLEAN,
        client_id VARCHAR,
        signal_guid VARCHAR NOT NULL,
        pcap_file VARCHAR NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_mqtt_signal_guid
        ON signal_observations(signal_guid);
    CREATE INDEX IF NOT EXISTS idx_mqtt_topic
        ON signal_observations(topic, field_name);
    CREATE INDEX IF NOT EXISTS idx_mqtt_timestamp
        ON signal_observations(timestamp);
    CREATE INDEX IF NOT EXISTS idx_mqtt_access_type
        ON signal_observations(access_type);
    """


class OpcUaSignalDatabase(_BaseSignalDatabase):
    """Stores raw numeric OPC UA signal observations."""

    OBSERVATION_COLUMNS = (
        "timestamp",
        "node_id",
        "display_name",
        "value",
        "access_type",
        "message_type",
        "service_type",
        "client_host",
        "server_host",
        "client_ip",
        "server_ip",
        "request_id",
        "secure_channel_id",
        "signal_guid",
        "pcap_file",
    )

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS signal_observations (
        timestamp DOUBLE NOT NULL,
        node_id VARCHAR NOT NULL,
        display_name VARCHAR NOT NULL,
        value DOUBLE NOT NULL,
        access_type VARCHAR NOT NULL,
        message_type VARCHAR,
        service_type VARCHAR,
        client_host VARCHAR NOT NULL,
        server_host VARCHAR NOT NULL,
        client_ip VARCHAR NOT NULL,
        server_ip VARCHAR NOT NULL,
        request_id INTEGER,
        secure_channel_id INTEGER,
        signal_guid VARCHAR NOT NULL,
        pcap_file VARCHAR NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_opcua_signal_guid
        ON signal_observations(signal_guid);
    CREATE INDEX IF NOT EXISTS idx_opcua_node
        ON signal_observations(node_id);
    CREATE INDEX IF NOT EXISTS idx_opcua_timestamp
        ON signal_observations(timestamp);
    CREATE INDEX IF NOT EXISTS idx_opcua_access_type
        ON signal_observations(access_type);
    CREATE INDEX IF NOT EXISTS idx_opcua_request
        ON signal_observations(request_id, secure_channel_id);
    """
