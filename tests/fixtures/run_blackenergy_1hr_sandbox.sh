#!/usr/bin/env bash
# BlackEnergy 1hr pipeline run into a sandbox dir for GUID-parity testing.
# Reads from the canonical pcap/log dirs but writes only into the sandbox.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1

LOG_DIR="logs/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)"
PCAP_DIR="pcap_traffic/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)"
ASSETS="ICSGraph/Collection/assets.yaml"

OUT_DIR="${1:-tests/fixtures/guid_parity_sandbox/step4_source_fixed}"
TMP_DIR="$OUT_DIR/tmp"
RUN_LOG="$OUT_DIR/run.log"

BASE_CYPHER="$OUT_DIR/base_BlackEnergy.cypher"
AUG_CYPHER="$OUT_DIR/augmented_BlackEnergy.cypher"
MAIN_DB="$OUT_DIR/BlackEnergy_signals.duckdb"
MQTT_DB="$OUT_DIR/BlackEnergy_mqtt_signals.duckdb"
OPCUA_DB="$OUT_DIR/BlackEnergy_opcua_signals.duckdb"
CACHE="$OUT_DIR/BlackEnergy_pcap_index.pkl"
PROTOCOL_CACHE="$OUT_DIR/BlackEnergy_protocol_signal_extract_cache.pkl"

log() { printf '[%s] %s\n' "$(date -Is)" "$*"; }

mkdir -p "$OUT_DIR" "$TMP_DIR"
: > "$RUN_LOG"

{
  log "Sandbox run into $OUT_DIR"
  log "Reading from $LOG_DIR and $PCAP_DIR (read-only)"

  for f in "$BASE_CYPHER" "$AUG_CYPHER" "$MAIN_DB" "$MAIN_DB.wal" \
           "$MQTT_DB" "$MQTT_DB.wal" "$OPCUA_DB" "$OPCUA_DB.wal" \
           "$CACHE" "$PROTOCOL_CACHE"; do
    [[ -e "$f" ]] && rm -f "$f"
  done

  log "[1/3] Building base graph"
  TMPDIR="$TMP_DIR" python3 ICSGraph/Collection/build_graph.py \
    --logs "$LOG_DIR" \
    --assets "$ASSETS" \
    --output "$BASE_CYPHER" \
    --workers 8 || exit 1

  log "[2/3] Streaming augmentation with main Modbus DuckDB"
  TMPDIR="$TMP_DIR" python3 -m network_aug \
    --base-cypher "$BASE_CYPHER" \
    --output-cypher "$AUG_CYPHER" \
    --pcap-dir "$PCAP_DIR" \
    --assets "$ASSETS" \
    --cache "$CACHE" \
    --force-rebuild \
    --streaming \
    --signal-db "$MAIN_DB" || exit 1

  log "[3/3] Standalone MQTT/OPC UA extraction"
  TMPDIR="$TMP_DIR" python3 -m invariantExperiments.extract_protocol_signals \
    "$PCAP_DIR" \
    --mqtt-db "$MQTT_DB" \
    --opcua-db "$OPCUA_DB" \
    --assets "$ASSETS" \
    --cache "$PROTOCOL_CACHE" \
    --force-rebuild || exit 1

  log "Done. Outputs in $OUT_DIR"
} >> "$RUN_LOG" 2>&1
