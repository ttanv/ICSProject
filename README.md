# ICSProject

PCAP-to-graph augmentation pipeline for ICS provenance analysis.

This repository enriches a base Neo4j Cypher export (from host telemetry) with network evidence from PCAP files, including:
- missing network connections,
- protocol-aware metadata (for example Modbus/HTTP/TLS fields),
- correlation of PCAP flows to telemetry connections,
- optional process-to-register attribution,
- optional raw signal persistence in DuckDB.

## What This Produces

Given a base `neo4j_export.cypher` and a PCAP directory, the tool writes an augmented Cypher file with additional nodes/relationships such as:
- `Asset`
- `NetworkService`
- `Register` (Modbus)
- enriched connection relationships (including updates to existing telemetry edges)

## Main Entry Point

Run the augmenter via:

```bash
python -m network_aug --base-cypher <base.cypher> --output-cypher <augmented.cypher> --pcap-dir <pcap_dir>
```

## Requirements

- Python 3.10+
- PCAP files (`.pcap` / `.pcapng`)
- Base Cypher export file

Install Python dependencies (no pinned requirements file is currently included):

```bash
pip install tqdm pyyaml dpkt scapy duckdb
```

Notes:
- `dpkt` is used by default for fast parsing.
- `scapy` is used as fallback (or forced via environment variable).
- `duckdb` is only required when using `--signal-db`.

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
- `--disable-process-attribution`: disable `Process` to register attribution edges.
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
