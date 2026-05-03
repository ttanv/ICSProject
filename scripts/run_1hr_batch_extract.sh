#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

OUT_ROOT="${OUT_ROOT:-paper_graphs_1hr}"
ASSETS="${ASSETS:-ICSGraph/Collection/assets.yaml}"
BATCH_SIZE="${BATCH_SIZE:-2}"
BUILD_WORKERS="${BUILD_WORKERS:-8}"

ORCH_LOG="$OUT_ROOT/batch_extract_1hr.log"
mkdir -p "$OUT_ROOT"

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*" | tee -a "$ORCH_LOG"
}

is_nonempty_file() {
  [[ -s "$1" ]]
}

pcap_count() {
  find "$1" -maxdepth 1 -type f \( -name '*.pcap' -o -name '*.pcapng' \) | wc -l
}

dataset_paths() {
  local slug="$1"

  case "$slug" in
    BlackEnergy)
      LOG_DIR='logs/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)'
      PCAP_DIR='pcap_traffic/extracted_1hr/BlackEnergy (2015 Ukraine Electric Power Attack)'
      ;;
    FrostyGoop)
      LOG_DIR='logs/extracted_1hr/FrostyGoop'
      PCAP_DIR='pcap_traffic/extracted_1hr/Frostygoop'
      ;;
    Fuxnet)
      LOG_DIR='logs/extracted_1hr/Fuxnet (Malware)'
      PCAP_DIR='pcap_traffic/extracted_1hr/Fuxnet (Malware)'
      ;;
    Industroyer)
      LOG_DIR='logs/extracted_1hr/industroyer'
      PCAP_DIR='pcap_traffic/extracted_1hr/Industroyer'
      ;;
    Industroyer2)
      LOG_DIR='logs/extracted_1hr/industroyer2'
      PCAP_DIR='pcap_traffic/extracted_1hr/Industroyer2'
      ;;
    Pipedream)
      LOG_DIR='logs/extracted_1hr/Pipedream'
      PCAP_DIR='pcap_traffic/extracted_1hr/Pipedream'
      ;;
    Triton)
      LOG_DIR='logs/extracted_1hr/Triton'
      PCAP_DIR='pcap_traffic/extracted_1hr/Triton'
      ;;
    *)
      printf 'Unknown dataset: %s\n' "$slug" >&2
      return 2
      ;;
  esac

  OUT_DIR="$OUT_ROOT/$slug"
  BASE_CYPHER="$OUT_DIR/base_${slug}.cypher"
  AUG_CYPHER="$OUT_DIR/augmented_${slug}.cypher"
  MAIN_DB="$OUT_DIR/${slug}_signals.duckdb"
  MQTT_DB="$OUT_DIR/${slug}_mqtt_signals.duckdb"
  OPCUA_DB="$OUT_DIR/${slug}_opcua_signals.duckdb"
  CACHE_FILE="$OUT_DIR/${slug}_pcap_index.pkl"
  TMP_DIR="$OUT_DIR/tmp"
}

backup_existing_db_if_needed() {
  local db_path="$1"
  local reason="$2"

  if [[ -e "$db_path" || -e "$db_path.wal" ]]; then
    local stamp
    stamp="$(date +%Y%m%d_%H%M%S)"
    if [[ -e "$db_path" ]]; then
      mv "$db_path" "${db_path}.partial_${stamp}"
    fi
    if [[ -e "$db_path.wal" ]]; then
      mv "$db_path.wal" "${db_path}.wal.partial_${stamp}"
    fi
    printf '[%s] Backed up existing DB for clean rerun: %s (%s)\n' "$(date -Is)" "$db_path" "$reason"
  fi
}

verify_duckdb() {
  local db_path="$1"
  local label="$2"

  if ! is_nonempty_file "$db_path"; then
    printf '[%s] WARN: %s DB missing or empty: %s\n' "$(date -Is)" "$label" "$db_path"
    return 1
  fi

  python3 - "$db_path" "$label" <<'PY'
import sys
from pathlib import Path

db_path = Path(sys.argv[1])
label = sys.argv[2]

try:
    import duckdb
    conn = duckdb.connect(str(db_path), read_only=True)
    row_count = conn.execute("SELECT COUNT(*) FROM signal_observations").fetchone()[0]
    conn.close()
except Exception as exc:
    print(f"[verify] ERROR: {label} DB could not be read: {db_path}: {exc}")
    raise SystemExit(1)

print(f"[verify] {label} DB readable: {db_path} rows={row_count:,}")
PY
}

build_base_graph() {
  if is_nonempty_file "$BASE_CYPHER"; then
    printf '[%s] Base graph already exists, skipping: %s\n' "$(date -Is)" "$BASE_CYPHER"
    return 0
  fi

  printf '[%s] Building base graph: %s\n' "$(date -Is)" "$BASE_CYPHER"
  TMPDIR="$TMP_DIR" python3 ICSGraph/Collection/build_graph.py \
    --logs "$LOG_DIR" \
    --assets "$ASSETS" \
    --output "$BASE_CYPHER" \
    --workers "$BUILD_WORKERS"
}

extract_main_db_only() {
  if is_nonempty_file "$MAIN_DB"; then
    printf '[%s] Main Modbus DB already exists, skipping: %s\n' "$(date -Is)" "$MAIN_DB"
    return 0
  fi

  backup_existing_db_if_needed "$MAIN_DB" "main DB-only extraction"
  printf '[%s] Extracting main Modbus DB without rewriting graph: %s\n' "$(date -Is)" "$MAIN_DB"
  TMPDIR="$TMP_DIR" python3 -m invariantExperiments.extract_signals \
    "$PCAP_DIR" \
    "$MAIN_DB" \
    "$ASSETS"
}

augment_with_main_db() {
  if is_nonempty_file "$AUG_CYPHER"; then
    printf '[%s] Augmented graph already exists, skipping: %s\n' "$(date -Is)" "$AUG_CYPHER"
    extract_main_db_only
    return $?
  fi

  backup_existing_db_if_needed "$MAIN_DB" "augmented graph missing"
  printf '[%s] Running augmentation: %s\n' "$(date -Is)" "$AUG_CYPHER"
  TMPDIR="$TMP_DIR" python3 -m network_aug \
    --base-cypher "$BASE_CYPHER" \
    --output-cypher "$AUG_CYPHER" \
    --pcap-dir "$PCAP_DIR" \
    --assets "$ASSETS" \
    --cache "$CACHE_FILE" \
    --force-rebuild \
    --streaming \
    --signal-db "$MAIN_DB"
}

extract_protocol_dbs() {
  local args=(
    python3 -m invariantExperiments.extract_protocol_signals
    "$PCAP_DIR"
    --assets "$ASSETS"
    --force-rebuild
  )

  if ! is_nonempty_file "$MQTT_DB"; then
    args+=(--mqtt-db "$MQTT_DB")
  else
    printf '[%s] MQTT DB already exists, skipping: %s\n' "$(date -Is)" "$MQTT_DB"
  fi

  if ! is_nonempty_file "$OPCUA_DB"; then
    args+=(--opcua-db "$OPCUA_DB")
  else
    printf '[%s] OPC UA DB already exists, skipping: %s\n' "$(date -Is)" "$OPCUA_DB"
  fi

  if [[ "${#args[@]}" -eq 7 ]]; then
    printf '[%s] Protocol DBs already exist, skipping standalone MQTT/OPC UA extraction\n' "$(date -Is)"
    return 0
  fi

  printf '[%s] Extracting standalone MQTT/OPC UA DBs\n' "$(date -Is)"
  TMPDIR="$TMP_DIR" "${args[@]}"
}

verify_dataset_outputs() {
  local failed=0

  for path in "$BASE_CYPHER" "$AUG_CYPHER"; do
    if is_nonempty_file "$path"; then
      printf '[%s] OK file: %s\n' "$(date -Is)" "$path"
    else
      printf '[%s] ERROR missing/empty file: %s\n' "$(date -Is)" "$path"
      failed=1
    fi
  done

  verify_duckdb "$MAIN_DB" "main Modbus" || failed=1
  verify_duckdb "$MQTT_DB" "MQTT" || failed=1
  verify_duckdb "$OPCUA_DB" "OPC UA" || failed=1

  return "$failed"
}

run_dataset() {
  local slug="$1"
  dataset_paths "$slug" || return $?

  mkdir -p "$OUT_DIR" "$TMP_DIR"

  printf '[%s] Dataset start: %s\n' "$(date -Is)" "$slug"
  printf '[%s] Logs: %s\n' "$(date -Is)" "$LOG_DIR"
  printf '[%s] PCAPs: %s\n' "$(date -Is)" "$PCAP_DIR"

  if [[ ! -d "$LOG_DIR" ]]; then
    printf '[%s] ERROR missing log directory: %s\n' "$(date -Is)" "$LOG_DIR"
    return 1
  fi

  if [[ ! -d "$PCAP_DIR" ]]; then
    printf '[%s] ERROR missing PCAP directory: %s\n' "$(date -Is)" "$PCAP_DIR"
    return 1
  fi

  local pcaps
  pcaps="$(pcap_count "$PCAP_DIR")"
  if [[ "$pcaps" -eq 0 ]]; then
    printf '[%s] ERROR no PCAP/PCAPNG files found in: %s\n' "$(date -Is)" "$PCAP_DIR"
    return 1
  fi
  printf '[%s] PCAP count: %s\n' "$(date -Is)" "$pcaps"

  build_base_graph || return $?
  augment_with_main_db || return $?
  extract_protocol_dbs || return $?
  verify_dataset_outputs || return $?

  printf '[%s] Dataset complete: %s\n' "$(date -Is)" "$slug"
}

run_batch() {
  local batch_num="$1"
  shift

  local pids=()
  local slugs=()
  local status=0

  log "Batch ${batch_num} start: $*"

  for slug in "$@"; do
    dataset_paths "$slug" || return $?
    mkdir -p "$OUT_DIR" "$TMP_DIR"

    local dataset_log="$OUT_DIR/${slug}_extract.log"
    log "Starting ${slug}; log=${dataset_log}"
    (
      run_dataset "$slug"
    ) >"$dataset_log" 2>&1 &

    local pid=$!
    printf '%s\n' "$pid" > "$OUT_DIR/${slug}_extract.pid"
    pids+=("$pid")
    slugs+=("$slug")
    log "${slug} PID ${pid}"
  done

  for i in "${!pids[@]}"; do
    local pid="${pids[$i]}"
    local slug="${slugs[$i]}"
    if wait "$pid"; then
      log "${slug} completed successfully"
    else
      local rc=$?
      log "${slug} failed with exit code ${rc}; see $OUT_ROOT/$slug/${slug}_extract.log"
      status=1
    fi
  done

  log "Batch ${batch_num} done"
  return "$status"
}

main() {
  : > "$ORCH_LOG"
  log "1hr batch extraction orchestrator starting"
  log "Root: $ROOT"
  log "Output root: $OUT_ROOT"
  log "Batch size: $BATCH_SIZE"
  log "Build workers per base graph: $BUILD_WORKERS"
  log "Stuxnet is intentionally skipped because it is already complete"

  if [[ "$BATCH_SIZE" != "2" ]]; then
    log "WARN: this script was requested for batches of 2; current BATCH_SIZE=$BATCH_SIZE"
  fi

  local overall=0

  run_batch 1 FrostyGoop Fuxnet || overall=1
  run_batch 2 BlackEnergy Triton || overall=1
  run_batch 3 Industroyer2 Pipedream || overall=1
  run_batch 4 Industroyer || overall=1

  if [[ "$overall" -eq 0 ]]; then
    log "All requested 1hr extractions completed successfully"
  else
    log "One or more 1hr extractions failed; check per-dataset logs"
  fi

  return "$overall"
}

main "$@"
