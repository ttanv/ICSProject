"""Tests for the invariant extraction module."""

from __future__ import annotations

import json
import math
from pathlib import Path

import duckdb
import pytest

from network_aug.invariants import InvariantConfig, mine_invariants
from network_aug.invariants.miners import (
    mine_all,
    mine_inter_register_correlations,
    mine_value_ranges,
)
from network_aug.invariants.models import Invariant, InvariantSet
from network_aug.invariants.st_parser import parse_st_file, _parse_with_regex


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signal_db():
    """In-memory DuckDB with known signal patterns for testing."""
    conn = duckdb.connect(":memory:")
    conn.execute("""
        CREATE TABLE signal_observations (
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
        )
    """)

    # Register 1: values in [100, 200], Register 2: values = 2 * register_1
    # Both on same server/unit — should correlate
    base_ts = 1000.0
    rows = []
    for i in range(200):
        ts = base_ts + i * 0.5
        val1 = 100 + (i % 101)  # 100..200
        val2 = val1 * 2          # 200..400
        for reg, val, guid in [
            (1, val1, "guid-server2-unit1-reg1"),
            (2, val2, "guid-server2-unit1-reg2"),
        ]:
            rows.append((
                ts, reg, val, "read", 3, 1,
                "client", "server-a", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, guid, "test.pcap",
            ))

    # Register 3: different unit_id, constant value
    for i in range(50):
        ts = base_ts + i * 0.5
        rows.append((
            ts, 3, 42, "read", 3, 2,
            "client", "server-b", "10.0.0.1", "10.0.0.3",
            1000 + i, ts, ts + 0.01, None, "guid-server3-unit2-reg3", "test.pcap",
        ))

    conn.executemany(
        """INSERT INTO signal_observations VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )""",
        rows,
    )
    yield conn
    conn.close()


@pytest.fixture
def payload_st_path():
    """Path to the real Stuxnet payload.st file."""
    p = Path(__file__).resolve().parent.parent / (
        "ICS-Project/Attacks/stuxnet/plc_dropper/payloads/payload.st"
    )
    if not p.exists():
        pytest.skip("payload.st not found")
    return p


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class TestModels:
    def test_invariant_to_dict(self):
        inv = Invariant(
            type="value_range",
            registers=[1],
            unit_id=1,
            confidence=0.95,
            observation_count=95,
            parameters={"min": 100, "max": 200},
        )
        d = inv.to_dict()
        assert d["type"] == "value_range"
        assert d["registers"] == [1]
        assert d["parameters"]["min"] == 100

    def test_invariant_set_json(self):
        inv_set = InvariantSet(
            generated_at="2025-01-01T00:00:00Z",
            signal_db_path="/tmp/test.duckdb",
            invariants=[
                Invariant(
                    type="value_range",
                    registers=[1],
                    unit_id=1,
                    parameters={"min": 0, "max": 100},
                )
            ],
        )
        j = inv_set.to_json()
        parsed = json.loads(j)
        assert len(parsed["invariants"]) == 1
        assert parsed["signal_db_path"] == "/tmp/test.duckdb"
        assert "correlation_graph" in parsed

    def test_correlation_graph_structure(self):
        """correlation_graph should have nodes from value_range and edges from inter_register."""
        inv_set = InvariantSet(
            generated_at="2025-01-01T00:00:00Z",
            signal_db_path="/tmp/test.duckdb",
            invariants=[
                Invariant(
                    type="value_range",
                    registers=[1],
                    unit_id=1,
                    signal_container_guid="guid-a",
                    parameters={"min": 0, "max": 100, "variable_name": "temp"},
                ),
                Invariant(
                    type="value_range",
                    registers=[2],
                    unit_id=1,
                    signal_container_guid="guid-b",
                    parameters={"min": 0, "max": 200, "variable_name": "pressure"},
                ),
                Invariant(
                    type="inter_register",
                    registers=[1, 2],
                    unit_id=1,
                    parameters={
                        "register_a": 1,
                        "register_b": 2,
                        "signal_guid_a": "guid-a",
                        "signal_guid_b": "guid-b",
                        "pearson_r": 0.95,
                        "slope": 2.0,
                        "intercept": 0.0,
                        "relationship": "positive",
                    },
                ),
            ],
        )
        graph = inv_set._build_correlation_graph()
        assert "guid-a" in graph["nodes"]
        assert "guid-b" in graph["nodes"]
        assert graph["nodes"]["guid-a"]["variable_name"] == "temp"
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["pearson_r"] == 0.95


# ---------------------------------------------------------------------------
# Miner tests
# ---------------------------------------------------------------------------

class TestMiners:
    def test_value_range_basic(self, signal_db):
        invariants = mine_value_ranges(signal_db, 0.0, 2000.0, min_observations=10)
        assert len(invariants) >= 2

        # Find register 1 invariant
        reg1 = [inv for inv in invariants if inv.registers == [1] and inv.unit_id == 1]
        assert len(reg1) == 1
        assert reg1[0].parameters["min"] == 100
        assert reg1[0].parameters["max"] == 200
        assert reg1[0].observation_count == 200

        # Find register 2 invariant
        reg2 = [inv for inv in invariants if inv.registers == [2] and inv.unit_id == 1]
        assert len(reg2) == 1
        assert reg2[0].parameters["min"] == 200
        assert reg2[0].parameters["max"] == 400

    def test_value_range_confidence(self, signal_db):
        invariants = mine_value_ranges(signal_db, 0.0, 2000.0, min_observations=10)
        reg1 = [inv for inv in invariants if inv.registers == [1]][0]
        # 200 observations -> confidence = min(1.0, 200/100) = 1.0
        assert reg1.confidence == 1.0

        reg3 = [inv for inv in invariants if inv.registers == [3]][0]
        # 50 observations -> confidence = 0.5
        assert reg3.confidence == 0.5

    def test_value_range_constant_register(self, signal_db):
        invariants = mine_value_ranges(signal_db, 0.0, 2000.0, min_observations=10)
        reg3 = [inv for inv in invariants if inv.registers == [3]][0]
        assert reg3.parameters["min"] == 42
        assert reg3.parameters["max"] == 42
        assert reg3.parameters["stddev"] == 0.0

    def test_correlation_detection(self, signal_db):
        invariants = mine_inter_register_correlations(
            signal_db, 0.0, 2000.0, min_observations=10, correlation_threshold=0.7
        )
        # Register 1 and 2 should be positively correlated (val2 = 2*val1)
        corr = [
            inv for inv in invariants
            if set(inv.registers) == {1, 2}
        ]
        assert len(corr) == 1
        assert corr[0].parameters["relationship"] == "positive"
        assert corr[0].parameters["pearson_r"] > 0.99

    def test_mine_all_returns_both_types(self, signal_db):
        invariants = mine_all(signal_db, 0.0, 2000.0, min_observations=10)
        types = {inv.type for inv in invariants}
        assert "value_range" in types
        assert "inter_register" in types

    def test_min_observations_filter(self, signal_db):
        # Require more observations than register 3 has
        invariants = mine_value_ranges(signal_db, 0.0, 2000.0, min_observations=100)
        reg3 = [inv for inv in invariants if inv.registers == [3]]
        assert len(reg3) == 0  # Only 50 observations, should be filtered

    def test_cross_server_isolation(self):
        """Registers with same address/unit_id on different servers must not merge."""
        conn = duckdb.connect(":memory:")
        conn.execute("""
            CREATE TABLE signal_observations (
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
            )
        """)
        rows = []
        # Same register_address=1, unit_id=1 on TWO different servers
        # Server A: values ~100, Server B: values ~50000
        for i in range(100):
            ts = 1000.0 + i * 0.5
            rows.append((
                ts, 1, 100 + i, "read", 3, 1,
                "client", "plc-a", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, "guid-plc-a-reg1", "test.pcap",
            ))
            rows.append((
                ts, 1, 50000 + i, "read", 3, 1,
                "client", "plc-b", "10.0.0.1", "10.0.0.3",
                i, ts, ts + 0.01, None, "guid-plc-b-reg1", "test.pcap",
            ))
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        invariants = mine_value_ranges(conn, 0.0, 2000.0, min_observations=10)
        # Should produce TWO separate invariants, not one merged range
        reg1_invs = [inv for inv in invariants if inv.registers == [1]]
        assert len(reg1_invs) == 2

        ranges = sorted((inv.parameters["min"], inv.parameters["max"]) for inv in reg1_invs)
        assert ranges[0][1] < 300    # Server A: 100..199
        assert ranges[1][0] >= 50000  # Server B: 50000..50099

        conn.close()

    def test_shared_guid_across_servers_does_not_conflate_value_ranges(self):
        """Reproduce the production bug condition: signal_container_guid is generated from
        client_hostname (see protocol_utils._generate_node_guid_for_signal_container), so
        when one polling client polls the same Modbus address on multiple RTUs, all those
        RTUs share the same GUID. The miner must NOT collapse them via GROUP BY guid alone.
        """
        conn = duckdb.connect(":memory:")
        conn.execute("""
            CREATE TABLE signal_observations (
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
            )
        """)
        rows = []
        # Same GUID, two different servers, very different value ranges.
        # On the buggy code the conflation would produce min=10, max=50099.
        shared_guid = "guid-shared-because-client-host-only"
        for i in range(100):
            ts = 1000.0 + i * 0.5
            # RTU-A: values 10..29 (small range)
            rows.append((
                ts, 1, 10 + (i % 20), "read", 3, 1,
                "PLC-03", "RTU-A", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, shared_guid, "test.pcap",
            ))
            # RTU-B: values 50000..50099 (very different range)
            rows.append((
                ts, 1, 50000 + i, "read", 3, 1,
                "PLC-03", "RTU-B", "10.0.0.1", "10.0.0.3",
                i, ts, ts + 0.01, None, shared_guid, "test.pcap",
            ))
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        invariants = mine_value_ranges(conn, 0.0, 2000.0, min_observations=10)
        # Should produce TWO separate invariants (one per server), NOT one merged 10..50099 range.
        reg1_invs = [inv for inv in invariants if inv.registers == [1]]
        assert len(reg1_invs) == 2, (
            f"Expected 2 invariants (one per server) but got {len(reg1_invs)}. "
            "Likely cause: miner is grouping by signal_container_guid only and "
            "conflating physically-distinct signals."
        )

        # Each invariant must report its own server's range, not the conflated union.
        by_server = {inv.server_host: inv for inv in reg1_invs}
        assert by_server["RTU-A"].parameters["min"] == 10
        assert by_server["RTU-A"].parameters["max"] == 29
        assert by_server["RTU-B"].parameters["min"] == 50000
        assert by_server["RTU-B"].parameters["max"] == 50099

        conn.close()

    def test_shared_guid_across_servers_does_not_create_phantom_correlation(self):
        """If two registers each share GUIDs across servers but are uncorrelated within
        any single server, the miner must not invent a cross-server correlation."""
        conn = duckdb.connect(":memory:")
        conn.execute("""
            CREATE TABLE signal_observations (
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
            )
        """)
        rows = []
        guid_r1 = "guid-shared-reg1"
        guid_r2 = "guid-shared-reg2"
        # RTU-A: reg1 varies 0..99, reg2 constant 5
        # RTU-B: reg1 constant 200, reg2 varies 1000..1099
        # Within either server, reg1 and reg2 do NOT correlate.
        # But concatenated across both servers, they would appear correlated
        # (low reg1 with low reg2 on RTU-A, high reg1 with high reg2 on RTU-B).
        for i in range(100):
            ts = 1000.0 + i * 0.5
            rows.append((
                ts, 1, i, "read", 3, 1,
                "PLC-03", "RTU-A", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, guid_r1, "test.pcap",
            ))
            rows.append((
                ts, 2, 5, "read", 3, 1,
                "PLC-03", "RTU-A", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, guid_r2, "test.pcap",
            ))
            rows.append((
                ts, 1, 200, "read", 3, 1,
                "PLC-03", "RTU-B", "10.0.0.1", "10.0.0.3",
                i, ts, ts + 0.01, None, guid_r1, "test.pcap",
            ))
            rows.append((
                ts, 2, 1000 + i, "read", 3, 1,
                "PLC-03", "RTU-B", "10.0.0.1", "10.0.0.3",
                i, ts, ts + 0.01, None, guid_r2, "test.pcap",
            ))
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        invariants = mine_inter_register_correlations(
            conn, 0.0, 2000.0, min_observations=10, correlation_threshold=0.7
        )
        # Within RTU-A, reg2 is constant → no correlation. Within RTU-B, reg1 is constant → no correlation.
        # The miner must scope per-server, so total correlations should be 0.
        assert len(invariants) == 0, (
            f"Expected 0 correlations but got {len(invariants)}. "
            "Likely cause: miner is filtering observations by signal_container_guid "
            "alone and pulling rows from both servers into the correlation calculation."
        )

        conn.close()

    def test_cross_server_no_correlation(self):
        """Registers on different servers should not be correlated even if values track."""
        conn = duckdb.connect(":memory:")
        conn.execute("""
            CREATE TABLE signal_observations (
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
            )
        """)
        rows = []
        # Two registers with identical values but on different servers
        for i in range(100):
            ts = 1000.0 + i * 0.5
            val = 100 + i
            rows.append((
                ts, 1, val, "read", 3, 1,
                "client", "plc-a", "10.0.0.1", "10.0.0.2",
                i, ts, ts + 0.01, None, "guid-plc-a-reg1", "test.pcap",
            ))
            rows.append((
                ts, 2, val * 2, "read", 3, 1,
                "client", "plc-b", "10.0.0.1", "10.0.0.3",
                i, ts, ts + 0.01, None, "guid-plc-b-reg2", "test.pcap",
            ))
        conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

        invariants = mine_inter_register_correlations(
            conn, 0.0, 2000.0, min_observations=10, correlation_threshold=0.7
        )
        # Should find NO correlations — registers are on different servers
        assert len(invariants) == 0

        conn.close()


# ---------------------------------------------------------------------------
# ST Parser tests
# ---------------------------------------------------------------------------

class TestSTParser:
    def test_parse_payload_st_variables(self, payload_st_path):
        info = _parse_with_regex(
            payload_st_path.read_text(), register_offset=0
        )
        # The payload.st has AT-addressed variables in PROGRAM main
        assert len(info.variables) > 0

        # Check specific known variables
        names = {v.name for v in info.variables}
        assert "flow_set" in names
        assert "pressure" in names
        assert "f1_valve_sp" in names
        assert "run_bit" in names

        # Verify AT types
        by_name = {v.name: v for v in info.variables}
        assert by_name["flow_set"].at_type == "MW"
        assert by_name["flow_set"].at_address == 0
        assert by_name["pressure"].at_type == "IW"
        assert by_name["pressure"].at_address == 8
        assert by_name["f1_valve_sp"].at_type == "QW"
        assert by_name["f1_valve_sp"].at_address == 100
        assert by_name["run_bit"].at_type == "QX"
        assert by_name["run_bit"].at_bit == 0

    def test_parse_payload_st_limits(self, payload_st_path):
        info = _parse_with_regex(
            payload_st_path.read_text(), register_offset=0
        )
        assert len(info.limit_bounds) > 0

        # Check that we found LIMIT calls with resolved bounds
        has_resolved = any(
            lb.low is not None and lb.high is not None
            for lb in info.limit_bounds
        )
        assert has_resolved

    def test_parse_payload_st_no_fsm(self, payload_st_path):
        info = _parse_with_regex(
            payload_st_path.read_text(), register_offset=0
        )
        assert info.has_fsm is False

    def test_parse_payload_st_via_file(self, payload_st_path):
        info = parse_st_file(payload_st_path, register_offset=0)
        assert len(info.variables) > 0
        assert info.has_fsm is False

    def test_register_offset(self, payload_st_path):
        info = _parse_with_regex(
            payload_st_path.read_text(), register_offset=40000
        )
        by_name = {v.name: v for v in info.variables}
        assert by_name["flow_set"].resolved_register == 40000
        assert by_name["pressure"].resolved_register == 40008

    def test_qx_coil_resolution(self):
        source = "run_bit AT %QX5.0 : BOOL;"
        info = _parse_with_regex(source, register_offset=0)
        assert len(info.variables) == 1
        v = info.variables[0]
        assert v.at_type == "QX"
        assert v.at_address == 5
        assert v.at_bit == 0
        assert v.resolved_register == 40  # 5*8 + 0

    def test_case_fsm_extraction(self):
        source = """
        PROGRAM main
        VAR
            state AT %MW10 : INT;
        END_VAR
        CASE state OF
            0: (* idle *)
                output := 0;
            1: (* running *)
                output := 100;
            2: (* stopping *)
                output := 50;
        END_CASE
        END_PROGRAM
        """
        info = _parse_with_regex(source, register_offset=0)
        assert info.has_fsm is True
        assert info.fsm.state_variable == "state"
        assert info.fsm.state_register == 10
        assert info.fsm.state_ids == [0, 1, 2]


# ---------------------------------------------------------------------------
# End-to-end pipeline test
# ---------------------------------------------------------------------------

class TestPipeline:
    def test_mine_invariants_in_memory(self, signal_db, tmp_path):
        db_path = tmp_path / "test_signals.duckdb"
        file_conn = duckdb.connect(str(db_path))
        file_conn.execute("""
            CREATE TABLE signal_observations (
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
            )
        """)

        base_ts = 1000.0
        rows = []
        for i in range(200):
            ts = base_ts + i * 0.5
            val1 = 100 + (i % 101)
            val2 = val1 * 2
            for reg, val, guid in [
                (1, val1, "guid-reg1"),
                (2, val2, "guid-reg2"),
            ]:
                rows.append((
                    ts, reg, val, "read", 3, 1,
                    "client", "server", "10.0.0.1", "10.0.0.2",
                    i, ts, ts + 0.01, None, guid, "test.pcap",
                ))
        file_conn.executemany(
            "INSERT INTO signal_observations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        file_conn.close()

        config = InvariantConfig(
            signal_db=db_path,
            output=tmp_path / "invariants.json",
        )
        result = mine_invariants(config)

        assert result.total_observations_used == 400
        assert len(result.invariants) > 0

        # Write and verify JSON output
        config.output.write_text(result.to_json())
        parsed = json.loads(config.output.read_text())
        assert "invariants" in parsed
        assert len(parsed["invariants"]) > 0
        # correlation_graph should be present with nodes and edges
        assert "correlation_graph" in parsed
        graph = parsed["correlation_graph"]
        assert len(graph["nodes"]) >= 2  # reg 1 and reg 2
        assert len(graph["edges"]) >= 1  # they correlate
