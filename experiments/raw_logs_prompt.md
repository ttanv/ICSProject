# ICS Raw-Logs — Attack Investigation (no provenance graph)

You are an ICS security analyst investigating a suspected intrusion. **No
provenance graph is available.** You have only the raw collection: per-host
endpoint logs (Sysmon, process lists, listening sockets) and packet captures
(`.pcapng`) covering the same window. Investigate from the raw sources,
reconstruct what happened, and produce a structured detection list compatible
with the existing graph-derived `detections.yaml` schema.

Do not rely on prior knowledge of specific malware or attack tools. The raw
logs and pcaps are the only authorities — include an event if and only if it
appears in the data and is causally reachable from the attacker's entry point.

---

## Context

- Asset inventory: `assets.yaml` (host names, IPs, zones, OS).
- MITRE ATT&CK for ICS techniques: `ics-attack.json` (STIX 2.0 bundle).
- Endpoint logs (per-host JSON):
  `logs/extracted/<scenario>/<HOST>/Custom_{Windows,Linux}_{Sysmon_Collector,Process_List,Listeners_List}.json`
  Use the **Sysmon** collector for time-ordered events, **Process_List** for
  long-lived process attributes (CommandLine, Exe, parent, CreateTime), and
  **Listeners_List** for currently bound sockets.
- Packet captures: `pcap_traffic/extracted/<scenario>/*.pcapng`.
  Decode with `tshark`. Filter expressions you will rely on: `tcp`, `udp`,
  `modbus`, `opcua`, `s7comm`, and for Triton specifically `udp.port == 1502`
  (TriStation) and `tcp.port == 4840` (OPC UA).
- **PCAP / Field-Layer Sub-agent**: spawn a sub-agent with sole responsibility
  for the pcap directory when the investigation reaches the network or field
  layer (see Step 3.5). Keep large `tshark` output out of the main context.

This prompt is written against the **Triton** scenario as the worked example
(`logs/extracted/Triton/`, `pcap_traffic/extracted/Triton/`). The procedure is
generic; substitute the scenario directory for other attacks.

---

## Identifier scheme (read this before producing output)

`detections.yaml` consumers expect `(src, rel, dst)` triples. Without a graph
you must synthesize identifiers yourself, using the rules below. Apply them
**verbatim** — the evaluator matches on the literal tuple.

| Node kind          | Identifier                                                        | Source field                                                   |
|--------------------|-------------------------------------------------------------------|----------------------------------------------------------------|
| Process            | Sysmon `ProcessGuid` *as written*, including the `{...}` braces   | `EventData.ProcessGuid` (Windows) / `ProcessGuid` (Linux)      |
| File               | `file::<HOST>::<absolute path, original case>`                    | `EventData.TargetFilename` (EID 11/23) or `EventData.Image`    |
| Loaded image       | `image::<HOST>::<ImageLoaded path>`                               | `EventData.ImageLoaded` (EID 7)                                |
| Network endpoint   | `net::<dst_ip>:<dst_port>`                                        | `EventData.DestinationIp` + `DestinationPort` (EID 3)          |
| Pipe / IPC         | `pipe::<HOST>::<PipeName>`                                        | `EventData.PipeName` (EID 17/18)                               |
| Registry           | `reg::<HOST>::<TargetObject>`                                     | `EventData.TargetObject` (EID 12/13/14)                        |
| Industrial signal  | `sig::<dst_ip>:<unit_id>:<reg_addr>` (Modbus / TriStation / S7)   | tshark protocol fields                                         |
| OPC UA node        | `opcua::<dst_ip>:<node_id>`                                       | `opcua.NodeId` from tshark                                     |
| Host (logical)     | `host::<HOSTNAME>` (only when nothing finer applies)              | `assets.yaml`                                                  |

Process GUIDs come from Sysmon directly — they happen to share the GUID shape
the graph builder used, so process-to-process events scored against the
graph-era ground truth will match without further work. All other node kinds
use natural-key strings; running them against the graph-era GT requires a
one-time normalization of that GT into the same scheme.

If a record is missing a field needed to construct an ID (e.g. Sysmon truncated
the path), drop the event rather than guessing — never invent identifiers.

---

## Relationship → source mapping

Use the exact relationship type from the table below. Do not collapse types or
relabel one as another.

| `rel`            | Endpoint log evidence                                | Pcap evidence                                                 |
|------------------|------------------------------------------------------|---------------------------------------------------------------|
| `CREATE_PROCESS` | Sysmon EID 1                                         | —                                                             |
| `LOAD_IMAGE`     | Sysmon EID 7                                         | —                                                             |
| `CREATE_FILE`    | Sysmon EID 11 (also covers overwrites)               | —                                                             |
| `DELETE_FILE`    | Sysmon EID 23 / 26                                   | —                                                             |
| `READ_FILE`      | Sysmon EID 15 (FileStream) when present              | —                                                             |
| `CONNECT_TO`     | Sysmon EID 3 (Initiated=true)                        | tshark TCP `SYN` from suspect host; UDP first-seen flow       |
| `READ_SIGNAL`    | —                                                    | Modbus FC 1/2/3/4 request, S7 read-var, OPC UA Read           |
| `WRITE_SIGNAL`   | —                                                    | Modbus FC 5/6/15/16, S7 write-var, OPC UA Write, TriStation   |
|                  |                                                      | program-download / control commands                           |
| `RAW_DISK_READ`  | Sysmon EID 9                                         | —                                                             |

`READ_SIGNAL` is **distinct** from `CONNECT_TO`. Emit the TCP/UDP setup as
`CONNECT_TO` once per (src process, dst endpoint) pair, then emit each
protocol-level read or write as its own `READ_SIGNAL` / `WRITE_SIGNAL` event.

---

## Investigation procedure

Follow these steps in order. Do not skip ahead to output until all steps are
complete.

### Step 1 — Find the entry point

Read `assets.yaml` to learn which IP ranges are internal and which are external
to the ICS environment. Then:

1. Across every host's Sysmon collector, find the earliest **inbound** EID 3
   (`Initiated=false`) where the SourceIp is external, or the earliest EID 1
   whose parent process is an externally-reachable listener (RDP, SSH, web
   service — cross-reference with that host's `Listeners_List`).
2. Verify against the pcaps: confirm the same external IP appears as the
   originator of the matching TCP flow.

The first edge by which attacker-controlled activity appears — even if its
`src` is itself attacker-controlled (e.g. a remote IP) — belongs in the output.

### Step 2 — Walk forward by ProcessGuid lineage

Starting from each entry-point process, walk forward through Sysmon EID 1
events: any process whose `ParentProcessGuid` is already in the attacker set
joins the set. Repeat until no new processes are added. This is the raw-log
equivalent of BFS over `CREATE_PROCESS` edges.

Run this **per host independently** and merge.

### Step 3 — For every attacker-controlled process, enumerate all observed actions

For each ProcessGuid in your set, sweep that host's Sysmon collector and
collect every record where `EventData.ProcessGuid` matches, regardless of EID.
Map each kept record to a `rel` per the table above and emit one event.

Do not assume a process produced no events of a given EID without checking.
In particular, check EID 1, 3, 7, 11, 23, and (where applicable) 9, 15, 17,
18, 12/13/14.

### Step 3.5 — Spawn the PCAP / Field-Layer Sub-agent

If Step 3 surfaces any of the following, spawn the sub-agent in parallel:

- An EID 3 record from an attacker-controlled process whose destination is an
  RTU, PLC, safety controller, or known field device (consult `assets.yaml`).
- A destination port matching an industrial protocol: 502 (Modbus/TCP),
  1502/UDP (TriStation), 102 (S7), 4840 (OPC UA), 44818 (EtherNet/IP),
  20000 (DNP3).
- Any indication the attack reached process-control or physical-process
  layers.

Provide the sub-agent with:

1. **Time window** — earliest to latest timestamp of attacker activity
   collected so far, in UTC.
2. **Suspect endpoints** — `(host, src_ip, src_port, ProcessGuid)` tuples for
   every attacker-driven flow seen in EID 3.
3. **Field-layer indicators already observed** — destination IP, port, and
   any protocol hints from EID 3.
4. **Pcap directory** — `pcap_traffic/extracted/<scenario>/`.
5. **Identifier scheme** — copy the table from this prompt verbatim so the
   sub-agent emits IDs in the same form.

Instruct the sub-agent to:

- For every attacker-attributable flow, emit one `CONNECT_TO` event keyed
  on the matching Sysmon EID 3 timestamp where one exists, otherwise the
  pcap timestamp of the first `SYN` (TCP) or first packet (UDP).
- Decode protocol payloads with `tshark`:
  - **Modbus**: emit `READ_SIGNAL` for FC 1/2/3/4, `WRITE_SIGNAL` for
    FC 5/6/15/16. Use `modbus.unit_id` and `modbus.reference_num`.
  - **TriStation (UDP/1502)**: emit `WRITE_SIGNAL` for program-download
    and control-command frames; emit `READ_SIGNAL` for status polls.
    Use the safety-controller IP as `dst_ip`, the Tristation node id as
    `unit_id`, and the function/opcode as `reg_addr` if no register is
    present.
  - **OPC UA**: emit `READ_SIGNAL` for Read service, `WRITE_SIGNAL` for
    Write service. Use `opcua::<ip>:<NodeId>` for `dst`.
  - **S7**: emit `READ_SIGNAL` / `WRITE_SIGNAL` per read-var / write-var
    requests, `sig::<ip>:<area>:<address>`.
- Return `(seq, timestamp, rel, src, dst, technique, note)` events using
  the **same Sysmon ProcessGuid** as `src` for every event whose flow can
  be tied back to an EID 3 record. If a flow cannot be tied to any
  attacker-controlled process (e.g. capture started before Sysmon), use
  `host::<HOSTNAME>` as `src` and say so in the `note`.
- Return a short narrative (≤200 words) of any field-layer impact.

When the sub-agent returns, merge its events. Deduplicate any `CONNECT_TO`
where the endpoint-log version and pcap version describe the same flow —
prefer the endpoint-log entry because it carries the ProcessGuid.

### Step 4 — Trace backward to the true root

For each ProcessGuid in your set, look up its parent
(`EventData.ParentProcessGuid` from EID 1, or join via `Process_List` if EID 1
was not captured). If the parent is not yet in your set, add it and repeat
until you reach a process that was directly triggered by an external
connection or by interactive logon. Each parent added re-enters Step 3.

Apply this on each host independently. When attacker activity spans multiple
hosts, each host has its own ancestry to walk.

The edge that links the parent to the child — the EID 1 record that surfaced
the parent — is itself part of the output.

### Step 5 — Enumerate all targets individually

When one process has multiple outgoing actions of the same `rel` (e.g.
connecting to six RTUs, writing to multiple registers), emit one event per
target. Do not collapse.

### Step 6 — Filter non-attack events

Apply this test to every collected event before writing output:

> **"Does this event reflect a decision or action taken by the attacker or
> their malware to advance the attack — or is it an automatic side effect of
> how the OS, runtime, or capture device operates?"**

**Keep** events that represent reconnaissance, execution, lateral movement,
payload staging, C2, or ICS impact.

**Drop** events whose destination would be present and accessed identically
in a benign baseline of the same host (dynamic-linker resolution of system
libraries, packer/runtime self-extraction into a temp dir, periodic device
telemetry on its own schedule, OS-driven Sysmon image loads). The
counterfactual is *no attack at all*, not *a different attacker tool*.

When in doubt, keep the event.

---

## Output

### 1. Attack narrative
3–5 sentences: what initiated the attack, what ICS impact occurred, and what
cleanup was performed.

### 2. Detections YAML
Write every event collected in Steps 2–5 (including those returned by the
sub-agent) and retained by Step 6 to `detections.yaml`. Timestamps must be
ISO 8601 UTC retrieved from the source data — do not compute or estimate
them. Sysmon `TimeStamp` is local-zone in some collectors; prefer
`EventData.UtcTime` when present, else convert.

```yaml
events:
  - seq: 1
    timestamp: "YYYY-MM-DDTHH:MM:SSZ"
    rel: <RELATIONSHIP_TYPE>
    src: "<src identifier per scheme above>"
    dst: "<dst identifier per scheme above>"
    technique: <T####>
    note: <one-line reason — what this record shows and why it is attacker-attributable>
```

The `note` field replaces the role a graph edge's description would have
played. Keep it to one line — it is the only human-readable context the
detection carries.
