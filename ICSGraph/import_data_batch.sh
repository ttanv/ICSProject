#!/usr/bin/env bash
set -euo pipefail

# === CONFIGURATION ===
NEO4J_CONTAINER="neo4j"
NEO4J_USER="neo4j"
NEO4J_PASS="CPS@QCRI2255"
DB_NAME="neo4j"
BATCH_SIZE=5000  # Statements per transaction
TEMP_BATCHED="/tmp/import_batched.cypher"

# === FUNCTIONS ===
log() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

err() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
    exit 1
}

wait_for_neo4j() {
    log "Waiting for Neo4j to accept Bolt connections..."
    for i in {1..60}; do
        if docker exec "$NEO4J_CONTAINER" \
            cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASS" "RETURN 1;" \
            &>/dev/null; then
            log "Neo4j is ready."
            return
        fi
        sleep 1
    done
    err "Neo4j did not become ready in time."
}

create_batched_file() {
    local input_file="$1"
    local output_file="$2"

    log "Creating batched transaction file..."

    awk -v batch_size="$BATCH_SIZE" '
    BEGIN {
        count = 0
        in_transaction = 0
        schema_done = 0
    }

    # Pass through comments and empty lines
    /^\/\// || /^$/ {
        print
        next
    }

    # Handle schema operations (constraints) - no batching
    /^CREATE CONSTRAINT/ {
        if (in_transaction) {
            print ":commit"
            in_transaction = 0
        }
        print
        next
    }

    # Process data operations (MERGE, MATCH)
    /^(MERGE|MATCH)/ {
        # Start new transaction if needed
        if (count % batch_size == 0) {
            if (in_transaction) {
                print ":commit"
                in_transaction = 0
            }
            print ":begin"
            in_transaction = 1
        }
        print
        count++
        next
    }

    # Pass through other lines
    {
        print
    }

    END {
        if (in_transaction) {
            print ":commit"
        }
    }
    ' "$input_file" > "$output_file"

    log "Batched file created with $(grep -c '^:begin' "$output_file" || echo 0) transactions"
}

# === ARGUMENT CHECK ===
if [[ $# -lt 1 ]]; then
    err "Usage: $0 <export_file.cypher>"
fi

EXPORT_FILE="$1"
[[ ! -f "$EXPORT_FILE" ]] && err "Export file not found: $EXPORT_FILE"

# === MAIN SCRIPT ===

# Ensure container exists
if ! docker ps -a --format '{{.Names}}' | grep -q "^$NEO4J_CONTAINER$"; then
    err "Docker container '$NEO4J_CONTAINER' does not exist."
fi

log "Restarting Neo4j container..."
docker restart "$NEO4J_CONTAINER" >/dev/null

wait_for_neo4j

log "Clearing existing database..."
docker exec "$NEO4J_CONTAINER" cypher-shell \
    -u "$NEO4J_USER" -p "$NEO4J_PASS" \
    "MATCH (n) DETACH DELETE n;" 2>/dev/null || true

# Create batched version locally first
TEMP_LOCAL="/tmp/neo4j_batched.cypher"
create_batched_file "$EXPORT_FILE" "$TEMP_LOCAL"

log "Copying batched file into container..."
docker cp "$TEMP_LOCAL" "$NEO4J_CONTAINER:$TEMP_BATCHED" \
    || err "Failed to copy file into container."

log "Importing with batched transactions..."
docker exec "$NEO4J_CONTAINER" cypher-shell \
    -u "$NEO4J_USER" -p "$NEO4J_PASS" \
    --file "$TEMP_BATCHED" \
    --format plain \
    || err "Import failed."

log "Cleaning up..."
docker exec "$NEO4J_CONTAINER" rm -f "$TEMP_BATCHED"
rm -f "$TEMP_LOCAL"

log "Import completed successfully."
