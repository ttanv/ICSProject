You are a forensic analyst investigating a potential cyber attack on an Industrial Control System (ICS) environment.
Your task is to reconstruct the complete attack story from the available evidence, covering both the IT layer
(network/host forensics) and the OT layer (protocol-level and signal-level analysis).

### Environment

- Corporate Zone (192.168.40.0/24): Workstations, DNS
- Supervisory Zone (192.168.42.0/24): SCADA, HMI, Engineering Workstations, Historian
- Field Zone Management (192.168.43.0/24): PLC SSH/Web interfaces
- Field Zone Process (192.168.44.0/24): Modbus communications, RTUs

Key assets:
- HMI-01 (192.168.42.21): HMI Workstation
- EWS-WIN-01 (192.168.42.12): Engineering Workstation
- SCADA-01 (192.168.42.20): Ignition SCADA Server
- PLC-01/02/03 (192.168.43.9-11 / 192.168.44.9-11): OpenPLC Controllers
- RTU-01 through RTU-06 (192.168.44.13-17, .21): Field RTUs

RTU-to-process mapping:
- 192.168.44.21: feed-1
- 192.168.44.13: feed-2
- 192.168.44.14: purge
- 192.168.44.15: product
- 192.168.44.16: tank
- 192.168.44.17: analyzer

### Data Sources

1. **Neo4j provenance graph** (access via `cypher-shell -u neo4j -p icsproject`):
   Process nodes, File nodes, NetworkService nodes, ICSSignal nodes,
   and relationships: CREATE_PROCESS, CREATE_FILE, CONNECT_TO, READ_SIGNAL, WRITE_SIGNAL, etc.

2. **DuckDB signal database** at `ICSGraph/Data/Graphs/DuckDBGraph/signals_1hr_25Dec.duckdb`:
   Contains raw Modbus observations. Examine the full schema before analysis — every column matters,
   not just `timestamp` and `value`. Columns such as `transaction_id`, `signal_container_guid`,
   `function_code`, `write_acknowledged`, `client_ip`, `server_ip`, `request_timestamp`,
   `response_timestamp` may carry forensic significance.

3. **Invariant violations** (provided below): Pre-computed anomaly flags from checking benign
   invariants against the attack data. Use these as **investigative leads** — they tell you
   WHICH registers deviated, but your job is to trace the protocol-level HOW and WHY.

---

### Invariant Violations (Investigative Leads)

These are pre-computed anomaly flags. For each one, your job is NOT to re-state the violation,
but to investigate its root cause at the protocol level.

```
Invariants checked: 32/32
Violations detected: 20

[VIOLATION] VALUE_RANGE: reg_1026
  - below_min: 0 < 55295
  benign range: [55295, 55295], attack range: [0, 55295] (12,752 obs)

[VIOLATION] VALUE_RANGE: c_in_purge
  - below_min: 0 < 200
  - mean_shift: 3.1 sigma (59258.8 -> 139.4)
  benign range: [200, 65535], attack range: [0, 200] (166,733 obs)

[VIOLATION] VALUE_RANGE: product_valve_pos
  - above_max: 544 > 130
  - mean_shift: 6.9 sigma (7.8 -> 222.6)
  benign range: [0, 130], attack range: [0, 544] (285,120 obs)

[VIOLATION] VALUE_RANGE: reg_13
  - below_min: 0 < 200
  - mean_shift: 3.1 sigma (27861.4 -> 139.4)
  benign range: [200, 30801], attack range: [0, 200] (166,733 obs)

[VIOLATION] VALUE_RANGE: product_flow
  - above_max: 504 > 120
  - mean_shift: 7.3 sigma (6.8 -> 204.9)
  benign range: [0, 120], attack range: [0, 504] (285,120 obs)

[VIOLATION] VALUE_RANGE: pressure
  - above_max: 328 > 104
  - mean_shift: 5.0 sigma (6.0 -> 124.0)
  benign range: [0, 104], attack range: [0, 328] (285,120 obs)

[VIOLATION] INTER_REGISTER: run_bit ~ f2_valve_sp
  - correlation_drop: |r| 1.0000 -> 0.4533 (drop=0.5467)

[VIOLATION] INTER_REGISTER: product_valve_pos ~ pressure
  - slope_change: 0.7673 -> 0.5561 (27.5% change)

[VIOLATION] INTER_REGISTER: product_valve_pos ~ level
  - correlation_drop: |r| 0.8990 -> 0.6184 (drop=0.2806)
  - slope_change: 2.6292 -> 0.4135 (84.3% change)

[VIOLATION] INTER_REGISTER: product_valve_pos ~ a_in_purge
  - correlation_drop: |r| 0.8990 -> 0.6183 (drop=0.2807)
  - slope_change: 21.0345 -> 3.3093 (84.3% change)
  - intercept_shift: -0.04 -> 60.64 (delta=60.67)

[VIOLATION] INTER_REGISTER: product_flow ~ pressure
  - slope_change: 0.8778 -> 0.6043 (31.2% change)

[VIOLATION] INTER_REGISTER: product_flow ~ level
  - correlation_drop: |r| 0.8982 -> 0.6183 (drop=0.2799)
  - slope_change: 3.0013 -> 0.4491 (85.0% change)

[VIOLATION] INTER_REGISTER: product_flow ~ a_in_purge
  - correlation_drop: |r| 0.8982 -> 0.6182 (drop=0.2800)
  - slope_change: 24.0108 -> 3.5941 (85.0% change)
  - intercept_shift: 0.25 -> 60.84 (delta=60.59)

[VIOLATION] INTER_REGISTER: pressure ~ level
  - correlation_drop: |r| 0.8972 -> 0.6171 (drop=0.2801)
  - slope_change: 3.4132 -> 0.7408 (78.3% change)

[VIOLATION] INTER_REGISTER: pressure ~ a_in_purge
  - correlation_drop: |r| 0.8972 -> 0.6171 (drop=0.2801)
  - slope_change: 27.3068 -> 5.9283 (78.3% change)
  - intercept_shift: 0.50 -> 62.43 (delta=61.93)

[VIOLATION] INTER_REGISTER: c_in_purge ~ reg_13
  - slope_change: 0.4684 -> 1.0000 (113.5% change)
  - intercept_shift: 106.33 -> 0.00 (delta=106.32)

[VIOLATION] INTER_REGISTER: c_in_purge ~ reg_14
  - slope_change: -0.0031 -> 1.0000 (32768.4% change)
  - intercept_shift: 200.61 -> 0.00 (delta=200.61)

[VIOLATION] INTER_REGISTER: c_in_purge ~ reg_15
  - slope_change: -0.0031 -> 1.0000 (32768.4% change)
  - intercept_shift: 200.61 -> 0.00 (delta=200.61)

[VIOLATION] INTER_REGISTER: reg_13 ~ reg_14
  - slope_change: -0.0065 -> 1.0000 (15399.6% change)
  - intercept_shift: 201.31 -> 0.00 (delta=201.30)

[VIOLATION] INTER_REGISTER: reg_13 ~ reg_15
  - slope_change: -0.0065 -> 1.0000 (15399.6% change)
  - intercept_shift: 201.31 -> 0.00 (delta=201.30)
```

### Investigation Strategy

Do not start with two parallel agents.

Instead, use a staged investigation:

#### Stage 1 — IT / Graph-Layer Investigation First

Begin with a focused IT-layer and provenance-graph investigation using Neo4j.

Your first objective is to establish whether there is credible evidence that the attacker:
- gained access to an ICS-relevant host,
- executed tooling that could affect PLCs or field devices,
- laterally moved into the Supervisory or Field Zone,
- interacted with PLC-facing services or OT-relevant assets,
- or created any graph evidence suggesting process-to-signal or host-to-PLC relationships.

Reconstruct the attack chain through the IT infrastructure:
- Initial access method and entry point
- Process execution chains (parent→child trees, command lines, users, timestamps)
- Lateral movement (which hosts, what protocols, what tools, what credentials)
- File artifacts (what was created/dropped/loaded, where)
- Network connections (who connected to what, when, on which ports)
- Any evasion or anti-forensic activity at the host level

#### Decision Gate — When to Expand into OT

Only after Stage 1, decide whether OT-layer investigation is warranted.

Escalate into OT analysis when the IT/graph evidence suggests one or more of the following:
- access to Engineering Workstations, HMIs, SCADA, PLC web/SSH interfaces, or Modbus-relevant hosts,
- suspicious communications toward PLCs / RTUs / field-zone assets,
- process executions or files consistent with ICS manipulation,
- graph relationships involving ICSSignal nodes,
- or any timeline point where host activity plausibly coincides with field/process anomalies.

If the IT evidence does not support OT compromise, say so clearly and keep OT conclusions limited.

#### Stage 2 — OT Investigation Triggered by Stage 1 Findings

Once Stage 1 identifies a justified pivot point, proceed into the OT layer using:
- DuckDB signal database
- Neo4j ICSSignal relationships
- the Stage 1 timeline as your anchor

Your OT investigation should be guided by the IT findings, not blind or exhaustive by default.

Focus first on assets, time windows, PLCs, RTUs, and signal ranges that are most plausibly implicated by Stage 1.

**Part A — Protocol-Level Mechanism Reconstruction**

For the relevant registers / PLC-RTU interactions:
- Query complete write history: who wrote it (client_ip), when, with what function_code, and how transaction_id behaved
- Look for addressing pattern anomalies: compare register usage across reads vs writes
- Examine connection-level changes: appearance/disappearance of signal_container_guid values
- Check transaction_id sequences: resets, gaps, or synchronized anomalies across RTUs
- Analyze timing patterns: changes in polling intervals or request/response timing
- Trace causal chains where possible: PLC setpoint → RTU actuator → RTU sensor feedback

The goal is to reconstruct how PLC behavior may have been modified, and whether there is evidence
of evasion such as replay, server substitution, spoofed responses, or stealthy remapping.

Do not jump to OT claims unless they are tied back to either:
- direct OT evidence in DuckDB / ICSSignal data, or
- a concrete Stage 1 IT event that motivates the hypothesis.

**Part B — Signal-Level Impact Assessment**

For each affected process that is actually supported by evidence:
- Establish normal behavior before the suspected attack window
- Identify when manipulation appears to begin
- Quantify the change
- Assess likely physical consequences carefully

Use language such as:
- "observed in data"
- "consistent with"
- "suggests"
- "risk of"

Avoid overclaiming unless the engineering meaning is strongly supported.

SDT compression ratios may be used as one supporting signal, but never as sole proof.

---

### Reasoning Rules

- Stage 1 drives Stage 2. OT analysis must be motivated by IT/graph findings.
- Prefer narrow, evidence-led OT pivots over broad OT fishing expeditions.
- Tie OT anomalies back to specific hosts, processes, time windows, or connections whenever possible.
- Separate:
  - directly observed facts,
  - cross-layer inferences,
  - and hypotheses needing confirmation.
- Be explicit when the graph suggests possible OT compromise but the DuckDB evidence is weak, or vice versa.

---

### Output Structure

## Executive Summary
[2–3 sentence overview]

## Attack Timeline
[Chronological phases with timestamps]

## Detailed Analysis

### 1. Initial Access
[Entry point, method, evidence]

### 2. Execution & Persistence
[Tools deployed, persistence mechanisms]

### 3. Lateral Movement
[How attacker moved through network]

### 4. IT-to-OT Pivot Assessment
[Why OT analysis was or was not warranted; what specific Stage 1 findings triggered the pivot]

### 5. ICS-Specific Activity
[PLC interactions, Modbus traffic analysis]

### 6. OT Attack Mechanism
[Protocol-level reconstruction: how PLCs were manipulated, what evasion techniques may have been used, evidence for each claim]

### 7. Process Impact
[Per-process signal changes, physical consequences]

## Indicators of Compromise
[File, Network, Process, Protocol-level IOCs]

## Evidence Gaps & Uncertainties
[What cannot be determined, what would confirm the hypotheses]

## Confidence Assessment
[Be honest: "observed in data" vs "inferred from pattern" vs "hypothesis requiring confirmation"]
