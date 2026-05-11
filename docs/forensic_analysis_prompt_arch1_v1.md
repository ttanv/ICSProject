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

For registers involved in PLC-RTU interactions:
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
