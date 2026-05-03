#!/usr/bin/env python3
"""Compare streaming vs batch augmentor output on the same input.

Parses the output Cypher files and compares structural artifacts:
- ICSSignal node GUIDs
- CONNECT_TO edge (src_guid, dst_guid) pairs
- READ_SIGNAL / WRITE_SIGNAL edges
- Property key sets on relationships
"""

import re
import sys
import tempfile
from pathlib import Path
from collections import Counter

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from network_aug.enhancer import AugmentationConfig
from network_aug.missing_augmentor import MissingTrafficAugmentor
from network_aug.streaming_augmentor import StreamingAugmentor


BASE_CYPHER = Path("/home/temoorali/Documents/ICSProject/graphs/base_BlackEnergy.cypher")
PCAP_DIR = Path("/tmp/blackenergy_test/pcap")
ASSET_FILE = Path("/home/temoorali/Documents/ICSProject/ICSGraph/assets.yaml")


def parse_cypher_artifacts(cypher_path: Path) -> dict:
    """Parse a Cypher output file and extract structural artifacts."""
    text = cypher_path.read_text()

    # Extract ICSSignal node GUIDs
    ics_signal_guids = set(re.findall(r"MERGE \(n:ICSSignal \{guid: '([^']+)'\}\)", text))

    # Extract CONNECT_TO edges (src_guid, dst_guid)
    connect_to_pattern = re.compile(
        r"MATCH \(m1:\w+ \{guid: '([^']+)'\}\).*?"
        r"MATCH \(m2:\w+ \{guid: '([^']+)'\}\).*?"
        r"MERGE \(m1\)-\[r:CONNECT_TO\]",
        re.DOTALL,
    )
    connect_to_edges = set()
    for m in connect_to_pattern.finditer(text):
        connect_to_edges.add((m.group(1), m.group(2)))

    # Also match SET-based CONNECT_TO updates (correlated edges)
    set_connect_pattern = re.compile(
        r"MATCH \(src:\w+ \{guid: '([^']+)'\}\).*?"
        r"MATCH \(dst:\w+ \{guid: '([^']+)'\}\).*?"
        r"MATCH \(src\)-\[rel:CONNECT_TO\]",
        re.DOTALL,
    )
    correlated_edges = set()
    for m in set_connect_pattern.finditer(text):
        correlated_edges.add((m.group(1), m.group(2)))

    # Extract READ_SIGNAL / WRITE_SIGNAL edges
    read_signal_pattern = re.compile(
        r"MATCH \(proc:Process \{guid: '([^']+)'\}\).*?"
        r"MATCH \(sig:ICSSignal \{guid: '([^']+)'\}\).*?"
        r"MERGE \(proc\)-\[acc:READ_SIGNAL\]",
        re.DOTALL,
    )
    read_signals = set()
    for m in read_signal_pattern.finditer(text):
        read_signals.add((m.group(1), m.group(2)))

    write_signal_pattern = re.compile(
        r"MATCH \(proc:Process \{guid: '([^']+)'\}\).*?"
        r"MATCH \(sig:ICSSignal \{guid: '([^']+)'\}\).*?"
        r"MERGE \(proc\)-\[acc:WRITE_SIGNAL\]",
        re.DOTALL,
    )
    write_signals = set()
    for m in write_signal_pattern.finditer(text):
        write_signals.add((m.group(1), m.group(2)))

    # Count NetworkEndpoint/NetworkService/Process nodes
    endpoint_guids = set(re.findall(r"MERGE \(n:NetworkEndpoint \{guid: '([^']+)'\}\)", text))
    service_guids = set(re.findall(r"MERGE \(n:NetworkService \{guid: '([^']+)'\}\)", text))
    process_guids = set(re.findall(r"MERGE \(n:Process \{guid: '([^']+)'\}\)", text))

    # Extract EXPOSED_ON edges (ICSSignal -> NetworkEndpoint)
    exposed_on = set(re.findall(
        r"MERGE \(n\)-\[:EXPOSED_ON\]->\(m1:NetworkEndpoint \{guid: '([^']+)'\}\)", text
    ))

    return {
        "ics_signal_guids": ics_signal_guids,
        "connect_to_edges": connect_to_edges,
        "correlated_edges": correlated_edges,
        "read_signals": read_signals,
        "write_signals": write_signals,
        "endpoint_guids": endpoint_guids,
        "service_guids": service_guids,
        "process_guids": process_guids,
        "exposed_on_targets": exposed_on,
    }


def compare(label: str, batch_set: set, streaming_set: set) -> bool:
    """Compare two sets and print differences."""
    ok = True
    only_batch = batch_set - streaming_set
    only_streaming = streaming_set - batch_set
    common = batch_set & streaming_set

    print(f"\n  {label}:")
    print(f"    Batch: {len(batch_set)}, Streaming: {len(streaming_set)}, Common: {len(common)}")

    if only_batch:
        print(f"    ONLY in batch ({len(only_batch)}):")
        for item in sorted(str(x) for x in list(only_batch)[:5]):
            print(f"      - {item}")
        if len(only_batch) > 5:
            print(f"      ... and {len(only_batch) - 5} more")
        ok = False
    if only_streaming:
        print(f"    ONLY in streaming ({len(only_streaming)}):")
        for item in sorted(str(x) for x in list(only_streaming)[:5]):
            print(f"      - {item}")
        if len(only_streaming) > 5:
            print(f"      ... and {len(only_streaming) - 5} more")
        ok = False
    if ok:
        print(f"    MATCH")
    return ok


def main():
    asset_file = ASSET_FILE if ASSET_FILE.exists() else None

    print("=" * 70)
    print("STREAMING vs BATCH PARITY COMPARISON")
    print("=" * 70)
    print(f"Base cypher: {BASE_CYPHER}")
    print(f"PCAP dir:    {PCAP_DIR}")
    print(f"Asset file:  {asset_file}")
    print()

    # --- Run batch augmentor ---
    print("Running BATCH augmentor...")
    batch_output = Path(tempfile.mktemp(suffix="_batch.cypher"))
    batch_config = AugmentationConfig(
        base_cypher=BASE_CYPHER,
        output_cypher=batch_output,
        pcap_directory=PCAP_DIR,
        asset_file=asset_file,
        force_rebuild_index=True,
    )
    batch_aug = MissingTrafficAugmentor(batch_config)
    batch_nodes, batch_rels = batch_aug.run()
    print(f"Batch: {batch_nodes} nodes, {batch_rels} relationships -> {batch_output}")

    # --- Run streaming augmentor ---
    print("\nRunning STREAMING augmentor...")
    streaming_output = Path(tempfile.mktemp(suffix="_streaming.cypher"))
    streaming_config = AugmentationConfig(
        base_cypher=BASE_CYPHER,
        output_cypher=streaming_output,
        pcap_directory=PCAP_DIR,
        asset_file=asset_file,
    )
    streaming_aug = StreamingAugmentor(streaming_config)
    streaming_nodes, streaming_rels = streaming_aug.run()
    print(f"Streaming: {streaming_nodes} nodes, {streaming_rels} relationships -> {streaming_output}")

    # --- Parse and compare ---
    print("\n" + "=" * 70)
    print("COMPARING ARTIFACTS")
    print("=" * 70)

    batch_artifacts = parse_cypher_artifacts(batch_output)
    streaming_artifacts = parse_cypher_artifacts(streaming_output)

    all_ok = True
    all_ok &= compare("ICSSignal node GUIDs", batch_artifacts["ics_signal_guids"], streaming_artifacts["ics_signal_guids"])
    all_ok &= compare("CONNECT_TO edges", batch_artifacts["connect_to_edges"], streaming_artifacts["connect_to_edges"])
    all_ok &= compare("Correlated edge updates", batch_artifacts["correlated_edges"], streaming_artifacts["correlated_edges"])
    all_ok &= compare("READ_SIGNAL edges", batch_artifacts["read_signals"], streaming_artifacts["read_signals"])
    all_ok &= compare("WRITE_SIGNAL edges", batch_artifacts["write_signals"], streaming_artifacts["write_signals"])
    all_ok &= compare("NetworkEndpoint nodes", batch_artifacts["endpoint_guids"], streaming_artifacts["endpoint_guids"])
    all_ok &= compare("NetworkService nodes", batch_artifacts["service_guids"], streaming_artifacts["service_guids"])
    all_ok &= compare("Process nodes", batch_artifacts["process_guids"], streaming_artifacts["process_guids"])

    print("\n" + "=" * 70)
    if all_ok:
        print("RESULT: ALL ARTIFACTS MATCH")
    else:
        print("RESULT: DIFFERENCES FOUND (see above)")
    print("=" * 70)

    # Cleanup
    print(f"\nOutput files preserved for inspection:")
    print(f"  Batch:     {batch_output}")
    print(f"  Streaming: {streaming_output}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
