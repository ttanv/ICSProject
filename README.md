# ICSProject

PCAP-to-graph augmentation pipeline for ICS provenance analysis.

This repository enriches a base Neo4j Cypher export (from host telemetry) with network evidence from PCAP files, including:
- missing network connections,
- protocol-aware metadata (for example Modbus/HTTP/TLS/MQTT fields),
- correlation of PCAP flows to telemetry connections,
- optional process-to-register attribution,
- optional raw signal persistence in DuckDB.

## What This Produces

Given a base `neo4j_export.cypher` and a PCAP directory, the tool writes an augmented Cypher file with additional nodes/relationships such as:
- `NetworkEndpoint`
- `NetworkService`
- `ICSSignal` (Modbus/MQTT/OPC UA observations)
- enriched `CONNECT_TO` relationships (including updates to existing telemetry edges)

## Main Entry Point

Run the augmenter via:

```bash
python -m network_aug --base-cypher <base.cypher> --output-cypher <augmented.cypher> --pcap-dir <pcap_dir>
```

## Requirements

- Python 3.10+
- PCAP files (`.pcap` / `.pcapng`)
- Base Cypher export file

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Notes:
- `dpkt` is used by default for fast parsing.
- `scapy` is used as fallback (or forced via environment variable).
- `duckdb` is required when using `--signal-db` or invariant/GECO tools.
- `pandas` is optional at runtime but used for faster DuckDB bulk loads and by
  maintenance scripts.

## Quick Start

1. Prepare inputs:
- base graph export, e.g. `graphs/base_25-12.cypher`
- packet captures, e.g. `pcap_traffic/`
- optional `assets.yaml` (host/IP metadata)

2. Run augmentation:

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher augmented_output.cypher \
  --pcap-dir pcap_traffic \
  --assets assets.yaml
```

3. Import resulting Cypher into Neo4j using your existing import workflow.

## Common Modes

### 1) Summary only (no file write)

Use this to estimate graph size impact before writing output:

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher /tmp/unused.cypher \
  --pcap-dir pcap_traffic \
  --summary-only --summary-progress
```

For faster summary on large captures:

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher /tmp/unused.cypher \
  --pcap-dir pcap_traffic \
  --summary-only --summary-fast
```

### 2) Streaming mode (large PCAP datasets)

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher augmented_streaming.cypher \
  --pcap-dir pcap_traffic \
  --streaming
```

Streaming mode now emits the same Modbus register artifacts as non-streaming:
- `ICSSignal` nodes + `EXPOSED_ON`
- process attribution via `READ_SIGNAL` / `WRITE_SIGNAL`
- SDT/RLE register summary fields (for example `valueTimeline`, `sdtTolerance`)

### 3) Rebuild PCAP index cache

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher augmented_output.cypher \
  --pcap-dir pcap_traffic \
  --cache pcap_connection_index.pkl \
  --force-rebuild
```

### 4) Time alignment + stricter correlation

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher augmented_output.cypher \
  --pcap-dir pcap_traffic \
  --pcap-time-offset -3 \
  --min-correlation-confidence 0.7 \
  --require-temporal-overlap
```

### 5) Persist raw signals into DuckDB (optional)

```bash
python -m network_aug \
  --base-cypher graphs/base_25-12.cypher \
  --output-cypher augmented_output.cypher \
  --pcap-dir pcap_traffic \
  --signal-db signals.duckdb
```

## Important CLI Options

- `--packet-limit N`: limit packets per PCAP file for fast iteration.
- `--min-aggregation-threshold N`: minimum ephemeral-port fanout to aggregate connections.
- `--disable-process-attribution`: disable `Process` to signal attribution edges.
- `--telemetry-attribution-only`: only attribute when telemetry evidence exists.

## Parser Backend Selection

By default, the package uses the fast `dpkt` backend when available.

Force Scapy backend:

```bash
USE_SCAPY_PARSER=1 python -m network_aug ...
```

## Correlation Verification Utility

The repo includes a completeness checker:

```bash
python -m network_aug.verify_completeness \
  --base-cypher graphs/base_25-12.cypher \
  --pcap-cache pcap_connection_index.pkl \
  --logged-hosts 192.168.42.12 192.168.42.20 192.168.42.21
```

## Project Layout

- `network_aug/`: augmentation engine, indexing, grouping, correlation, Cypher emission
- `assets.yaml`: ICS host and zone metadata
- `docs/`: architecture and design notes
- `graphs/`: example/base Cypher artifacts
- `pcap_traffic/`: packet capture inputs

## Operational Notes

- Large cache files (`*.pkl`) are expected for big PCAP sets.
- If `assets.yaml` is not provided, the tool attempts auto-discovery in the working directory and next to the base Cypher.
- If no `dpkt` is installed, parser fallback to Scapy can be slower.

## Related Docs

- `docs/architecture-overview.md`
- `docs/register_summarization_analysis.md`
- `GROUNDTRUTH.md`

## Invariant Extraction

There are currently three invariant extraction paths:

- Modbus register invariants, using the existing Modbus-oriented
  `signal_observations` schema.
- OPC UA tag invariants, using the standalone OPC UA signal DuckDB schema.
- MQTT topic/field invariants, using the standalone MQTT signal DuckDB schema.

### Modbus Signals and Invariants

If you already have a Modbus signal DuckDB from augmentation, use it directly:

```bash
python -m network_aug.invariants \
  --signal-db signals.duckdb \
  --output invariants.json \
  --min-observations 10 \
  --correlation-threshold 0.7
```

To extract Modbus signal observations directly from PCAPs first:

```bash
python -m invariantExperiments.extract_signals \
  pcap_traffic \
  modbus_signals.duckdb \
  assets.yaml
```

Then mine invariants:

```bash
python -m network_aug.invariants \
  --signal-db modbus_signals.duckdb \
  --output modbus_invariants.json
```

Optional state-aware/ST enrichment:

```bash
python -m network_aug.invariants \
  --signal-db modbus_signals.duckdb \
  --st-file invariantExperiments/simplified_te.st \
  --register-offset 0 \
  --output modbus_invariants_with_st.json
```

Validate benign Modbus invariants against another run:

```bash
python -m invariantExperiments.validate_invariants \
  modbus_invariants.json \
  attack_modbus_signals.duckdb
```

### OPC UA Signals and Invariants

Extract OPC UA numeric signal observations from PCAPs:

```bash
python -m invariantExperiments.extract_protocol_signals \
  pcap_traffic \
  --opcua-db opcua_signals.duckdb \
  --assets assets.yaml \
  --force-rebuild
```

Mine OPC UA invariants from that DuckDB:

```bash
python -m invariantExperiments.extract_opcua_invariants \
  opcua_signals.duckdb \
  --output opcua_invariants.json \
  --min-observations 10 \
  --correlation-threshold 0.7
```

The OPC UA extractor intentionally runs in parallel to the Modbus invariant
pipeline. It uses OPC UA identities (`signal_guid`, `node_id`, `display_name`,
`server_host`) rather than mapping tags into fake register addresses.

Useful OPC UA options:

```bash
# Value ranges only, no inter-signal correlations.
python -m invariantExperiments.extract_opcua_invariants \
  opcua_signals.duckdb \
  --output opcua_value_ranges.json \
  --skip-correlations

# Use only the first 2 hours as the benign baseline.
python -m invariantExperiments.extract_opcua_invariants \
  opcua_signals.duckdb \
  --output opcua_baseline_2h_invariants.json \
  --baseline-hours 2

# Drop 0/1-only tags from value-range output.
python -m invariantExperiments.extract_opcua_invariants \
  opcua_signals.duckdb \
  --output opcua_non_binary_invariants.json \
  --exclude-binary-value-ranges
```

Example using a locally generated BlackEnergy OPC UA sample:

```bash
python -m invariantExperiments.extract_opcua_invariants \
  paper_graphs_v1/BlackEnergy_opcua_signals.duckdb \
  --output paper_graphs_v1/BlackEnergy_opcua_invariants.json \
  --min-observations 10 \
  --correlation-threshold 0.7
```

That output includes:

- `value_range` invariants for individual OPC UA tags,
- `inter_signal` correlations between tags on the same OPC UA server,
- a `correlation_graph` section for downstream story/violation analysis,
- `signal_summary` counts that make it easy to sanity-check the mined set.

### MQTT Signals and Invariants

Extract MQTT numeric signal observations from PCAPs:

```bash
python -m invariantExperiments.extract_protocol_signals \
  pcap_traffic \
  --mqtt-db mqtt_signals.duckdb \
  --assets assets.yaml \
  --force-rebuild
```

You can extract MQTT and OPC UA in one pass by providing both outputs:

```bash
python -m invariantExperiments.extract_protocol_signals \
  pcap_traffic \
  --mqtt-db mqtt_signals.duckdb \
  --opcua-db opcua_signals.duckdb \
  --assets assets.yaml \
  --force-rebuild
```

Mine MQTT invariants from the MQTT DuckDB:

```bash
python -m invariantExperiments.extract_mqtt_invariants \
  mqtt_signals.duckdb \
  --output mqtt_invariants.json \
  --min-observations 10 \
  --correlation-threshold 0.7
```

The MQTT extractor uses MQTT identities (`signal_guid`, `topic`, `field_name`,
`signal_name`, `server_host`) rather than mapping topics into registers or
OPC UA node IDs.

Useful MQTT options:

```bash
# Value ranges only, no inter-signal correlations.
python -m invariantExperiments.extract_mqtt_invariants \
  mqtt_signals.duckdb \
  --output mqtt_value_ranges.json \
  --skip-correlations

# Use only the first 2 hours as the benign baseline.
python -m invariantExperiments.extract_mqtt_invariants \
  mqtt_signals.duckdb \
  --output mqtt_baseline_2h_invariants.json \
  --baseline-hours 2

# Drop 0/1-only topics from value-range output.
python -m invariantExperiments.extract_mqtt_invariants \
  mqtt_signals.duckdb \
  --output mqtt_non_binary_invariants.json \
  --exclude-binary-value-ranges
```

Example using a locally generated BlackEnergy MQTT sample:

```bash
python -m invariantExperiments.extract_mqtt_invariants \
  paper_graphs_v1/BlackEnergy_mqtt_signals.duckdb \
  --output paper_graphs_v1/BlackEnergy_mqtt_invariants.json \
  --min-observations 10 \
  --correlation-threshold 0.7
```

That output includes:

- `value_range` invariants for individual MQTT topic fields,
- `inter_signal` correlations between topic fields on the same MQTT broker,
- a `correlation_graph` section for downstream story/violation analysis,
- `signal_summary` counts including top topics and broker-level counts.

## Downstream GECO Analysis

The repo includes an optional downstream detector inspired by the GECO paper.
It is intentionally separate from augmentation. There are two parallel
implementations, one per signal schema:

- `network_aug.geco` — consumes the Modbus-oriented `signal_observations` table
  used by `network_aug.invariants`.
- `network_aug.geco_opcua` — consumes the standalone OPC UA signal DuckDB
  schema (`signal_guid`, `node_id`, `display_name`, `server_host`) produced by
  `invariantExperiments.extract_protocol_signals`.

Both share the same `train`/`score` subcommand layout and CUSUM thresholds; only
the identity columns differ.

### Modbus GECO

Train on benign/baseline data:

```bash
python -m network_aug.geco train \
  --signal-db baseline.duckdb \
  --output geco_model.json
```

Score another run:

```bash
python -m network_aug.geco score \
  --signal-db attack.duckdb \
  --model geco_model.json \
  --output geco_alerts.json \
  --emit-cypher geco_alerts.cypher
```

### OPC UA GECO

Train against an OPC UA `*_signals.duckdb`:

```bash
python -m network_aug.geco_opcua train \
  --signal-db opcua_signals.duckdb \
  --output opcua_geco_model.json
```

Score another OPC UA run:

```bash
python -m network_aug.geco_opcua score \
  --signal-db attack_opcua_signals.duckdb \
  --model opcua_geco_model.json \
  --output opcua_geco_alerts.json \
  --emit-cypher opcua_geco_alerts.cypher
```

Example using a locally generated BlackEnergy OPC UA sample, training on the first
3 hours and scoring the full capture:

```bash
python -m network_aug.geco_opcua train \
  --signal-db paper_graphs_v1/BlackEnergy_opcua_signals.duckdb \
  --output paper_graphs_v1/BlackEnergy_opcua_geco_model.json \
  --baseline-hours 3.0

python -m network_aug.geco_opcua score \
  --signal-db paper_graphs_v1/BlackEnergy_opcua_signals.duckdb \
  --model paper_graphs_v1/BlackEnergy_opcua_geco_model.json \
  --output paper_graphs_v1/BlackEnergy_opcua_geco_alerts.json
```

Train and score on the same window will (correctly) produce 0 alerts because
the threshold is calibrated on the same residuals it is later compared against;
use `--baseline-hours` or two separate DuckDB files to get an honest evaluation.

Notes:
- Both modules share the same `train`/`score` subcommand structure, so flags
  carry over between them.
- `--candidate-invariants <invariants.json>` can be used during training to
  prioritize predictor search from a previously mined correlation graph
  (Modbus `network_aug.invariants` output for the Modbus module, OPC UA
  `invariantExperiments.extract_opcua_invariants` output for the OPC UA module).
- Cypher export links `GECOAlert` nodes to `SignalContainer` nodes via the
  raw signal GUID (`signal_container_guid` for Modbus, `signal_guid` for OPC UA);
  alerts emitted by the OPC UA module also carry `protocol: 'opcua'`,
  `nodeId`, and `displayName` properties for downstream querying.
