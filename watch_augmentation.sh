#!/usr/bin/env bash

set -u

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <pid> [label]" >&2
  exit 2
fi

PID="$1"
LABEL="${2:-augmentation}"

CHECK_INTERVAL_SECONDS="${CHECK_INTERVAL_SECONDS:-10}"
MAX_RSS_KB="${MAX_RSS_KB:-12582912}"          # 12 GiB
MIN_AVAILABLE_KB="${MIN_AVAILABLE_KB:-20971520}" # 20 GiB
MAX_SWAP_USED_KB="${MAX_SWAP_USED_KB:-1048576}"  # 1 GiB
MAX_RSS_JUMP_KB="${MAX_RSS_JUMP_KB:-1572864}"    # 1.5 GiB between checks

LOG_DIR="${LOG_DIR:-/home/temoorali/Documents/ICSProject/logs}"
mkdir -p "$LOG_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/${LABEL}_watch_${STAMP}.log"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

kill_target() {
  local reason="$1"
  log "KILLING pid=${PID} reason=${reason}"
  kill -TERM "$PID" 2>/dev/null || true
  sleep 5
  if ps -p "$PID" >/dev/null 2>&1; then
    log "pid=${PID} ignored SIGTERM; sending SIGKILL"
    kill -KILL "$PID" 2>/dev/null || true
  fi
}

if ! ps -p "$PID" >/dev/null 2>&1; then
  log "pid=${PID} is not running; nothing to watch"
  exit 1
fi

log "watch started pid=${PID} label=${LABEL} interval=${CHECK_INTERVAL_SECONDS}s max_rss_kb=${MAX_RSS_KB} min_available_kb=${MIN_AVAILABLE_KB} max_swap_used_kb=${MAX_SWAP_USED_KB} max_rss_jump_kb=${MAX_RSS_JUMP_KB}"

PREV_RSS_KB=0

while true; do
  if ! ps -p "$PID" >/dev/null 2>&1; then
    log "pid=${PID} exited normally or was already stopped"
    exit 0
  fi

  PROC_LINE="$(ps -p "$PID" -o rss=,etime=,%cpu=,%mem=,args=)"
  RSS_KB="$(awk '{print $1}' <<<"$PROC_LINE")"
  ELAPSED="$(awk '{print $2}' <<<"$PROC_LINE")"
  CPU_PCT="$(awk '{print $3}' <<<"$PROC_LINE")"
  MEM_PCT="$(awk '{print $4}' <<<"$PROC_LINE")"
  CMD="$(cut -d' ' -f5- <<<"$PROC_LINE")"

  MEMINFO="$(awk '
    /^MemAvailable:/ {ma=$2}
    /^SwapTotal:/ {st=$2}
    /^SwapFree:/ {sf=$2}
    END { printf "%s %s %s\n", ma, st, sf }
  ' /proc/meminfo)"
  AVAILABLE_KB="$(awk '{print $1}' <<<"$MEMINFO")"
  SWAP_TOTAL_KB="$(awk '{print $2}' <<<"$MEMINFO")"
  SWAP_FREE_KB="$(awk '{print $3}' <<<"$MEMINFO")"
  SWAP_USED_KB=$((SWAP_TOTAL_KB - SWAP_FREE_KB))

  log "pid=${PID} rss_kb=${RSS_KB} elapsed=${ELAPSED} cpu_pct=${CPU_PCT} mem_pct=${MEM_PCT} available_kb=${AVAILABLE_KB} swap_used_kb=${SWAP_USED_KB} cmd=${CMD}"

  if [ "$RSS_KB" -ge "$MAX_RSS_KB" ]; then
    kill_target "rss_kb=${RSS_KB} >= max_rss_kb=${MAX_RSS_KB}"
    exit 1
  fi

  if [ "$AVAILABLE_KB" -le "$MIN_AVAILABLE_KB" ]; then
    kill_target "available_kb=${AVAILABLE_KB} <= min_available_kb=${MIN_AVAILABLE_KB}"
    exit 1
  fi

  if [ "$SWAP_USED_KB" -ge "$MAX_SWAP_USED_KB" ]; then
    kill_target "swap_used_kb=${SWAP_USED_KB} >= max_swap_used_kb=${MAX_SWAP_USED_KB}"
    exit 1
  fi

  if [ "$PREV_RSS_KB" -gt 0 ]; then
    RSS_JUMP_KB=$((RSS_KB - PREV_RSS_KB))
    if [ "$RSS_JUMP_KB" -ge "$MAX_RSS_JUMP_KB" ]; then
      kill_target "rss_jump_kb=${RSS_JUMP_KB} >= max_rss_jump_kb=${MAX_RSS_JUMP_KB}"
      exit 1
    fi
  fi

  PREV_RSS_KB="$RSS_KB"
  sleep "$CHECK_INTERVAL_SECONDS"
done
