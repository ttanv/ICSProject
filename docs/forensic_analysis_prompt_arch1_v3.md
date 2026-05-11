## ICS Forensic Analysis Prompt

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
   Contains raw Modbus observations. **Start by examining the full schema** — every column matters,
   not just `timestamp` and `value`. Columns like `transaction_id`, `signal_container_guid`,
   `function_code`, `write_acknowledged`, `client_ip`, `server_ip`, `request_timestamp`,
   `response_timestamp` carry forensic significance.

3. **Invariant violations** (provided below): Pre-computed anomaly flags. Use these as
   **investigative leads** — they tell you WHICH registers deviated and by how much, but your
   job is to trace the protocol-level HOW and WHY behind each violation.

---

### Investigation Strategy

Run two parallel agents:

#### Agent 1: IT-Layer Forensics (Neo4j)

Reconstruct the attack chain through the IT infrastructure:
- Initial access method and entry point
- Process execution chains (parent→child trees, command lines, users, timestamps)
- Lateral movement (which hosts, what protocols, what tools, what credentials)
- File artifacts (what was created/dropped/loaded, where)
- Network connections (who connected to what, when, on which ports)
- Any evasion or anti-forensic activity at the host level

#### Agent 2: OT-Layer Forensics (DuckDB + Neo4j ICSSignal nodes)

This is the critical layer. The OT investigation has two parts:

**Part A — Protocol-Level Mechanism Reconstruction (most important):**

For each register flagged by the invariants:
- Query its **complete write history**: who wrote it (client_ip), when, with what function_code,
  and what was the transaction_id sequence
- Look for **addressing pattern anomalies**: compare which register addresses are used across
  different function codes (reads vs writes). OpenPLC has specific address mapping conventions
- Examine **connection-level changes**: when do new `signal_container_guid` values appear?
  Do existing ones disappear? What changes about the traffic pattern at those boundaries?
- Check **transaction_id sequences** across connections: are they monotonically increasing as
  expected, or do you see resets, gaps, or synchronized anomalies across multiple RTU connections?
- Analyze **timing patterns**: compare `request_timestamp` vs `response_timestamp` distributions
  before and during the attack — do response times change? Do polling intervals shift?
- Trace the **causal chain**: which PLC register changes precede which RTU changes? What is the
  control flow from PLC setpoint → RTU actuator → RTU sensor feedback?

**The goal is to reconstruct exactly how the attacker modified PLC behavior while potentially
evading SCADA-level detection.** Don't just identify what changed — figure out the mechanism
and whether there's evidence of evasion (traffic replay, server substitution, spoofed responses, etc.).

**Part B — Signal-Level Impact Assessment:**

For each affected process (feed-1, feed-2, purge, product, tank, analyzer):
- Characterize normal behavior before the attack
- Identify the exact moment manipulation began and what triggered it
- Quantify the magnitude of change
- Assess physical consequences (but frame as "risk of" / "consistent with", not certainties,
  unless you have engineering-unit validation)

SDT compression ratios can be used as **one supporting indicator** among many — a signal that
was dynamic and becomes flat will compress much better, which is consistent with freezing/manipulation.
But don't treat compression ratios as proof of manipulation on their own.

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
  → INVESTIGATE: What wrote to this register? What is the write pattern/periodicity?

[VIOLATION] VALUE_RANGE: c_in_purge
  - below_min: 0 < 200
  - mean_shift: 3.1 sigma (59258.8 -> 139.4)
  benign range: [200, 65535], attack range: [0, 200] (166,733 obs)
  → INVESTIGATE: What caused the purge concentration to collapse? Trace the control chain.

[VIOLATION] VALUE_RANGE: product_valve_pos
  - above_max: 544 > 130
  - mean_shift: 6.9 sigma (7.8 -> 222.6)
  benign range: [0, 130], attack range: [0, 544] (285,120 obs)
  → INVESTIGATE: Was the valve driven open by a write, or did it drift due to lost control?

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
  → INVESTIGATE: Is pressure still rising at end of capture? What controls it?

[VIOLATION] INTER_REGISTER: run_bit ~ f2_valve_sp
  - correlation_drop: |r| 1.0000 -> 0.4533 (drop=0.5467)
  → INVESTIGATE: These should be locked together. Find the exact moment they diverge
    and what Modbus operations happened at that timestamp.

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
  → INVESTIGATE: Slope going to 1.0 means these registers became identical.
    Were they independently written to the same value, or did one cause the other?

[VIOLATION] INTER_REGISTER: c_in_purge ~ reg_14
  - slope_change: -0.0031 -> 1.0000 (32768.4% change)
  - intercept_shift: 200.61 -> 0.00 (delta=200.61)
  → INVESTIGATE: Correlation flipped from -1 to +1. What changed the relationship?

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

---

### Output Structure

## Executive Summary
[2-3 sentence overview]

## Attack Timeline
[Chronological phases with timestamps]

## Detailed Analysis

### 1. Initial Access
[Entry point, method, evidence]

### 2. Execution & Persistence
[Tools deployed, persistence mechanisms]

### 3. Lateral Movement
[How attacker moved through network]

### 4. ICS-Specific Activity
[PLC interactions, Modbus traffic analysis]

### 5. OT Attack Mechanism
[Protocol-level reconstruction: exactly how PLCs were manipulated,
 what evasion techniques were used, evidence for each claim]

### 6. Process Impact
[Per-process signal changes, physical consequences]

## Indicators of Compromise
[File, Network, Process, Protocol-level IOCs]

## Evidence Gaps & Uncertainties
[What you cannot determine, what would confirm your hypotheses]

## Confidence Assessment
[Be honest: "observed in data" vs "inferred from pattern" vs "hypothesis requiring confirmation"]
