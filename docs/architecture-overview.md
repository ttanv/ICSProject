# ICS Network Provenance Analysis - Architecture Overview

## Executive Summary

This system creates **forensic provenance graphs** for Industrial Control System (ICS) environments by fusing two complementary data sources:

1. **Host Telemetry** (Sysmon/ETW logs) - Captures *who* performed actions (processes, users)
2. **Network Traffic** (PCAP) - Captures *what* happened on the wire (protocols, payloads)

The result is a unified Neo4j graph that enables **story reconstruction**: answering questions like "Which operator workstation modified PLC register 40001 at 14:32, and what process was responsible?"

---

## The Visibility Gap Problem

### Host Telemetry Alone (Incomplete Picture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                     WHAT TELEMETRY CAPTURES                         │
├─────────────────────────────────────────────────────────────────────┤
│  ✓ Process creation (who launched what executable)                  │
│  ✓ User context (which account, logon session)                      │
│  ✓ File operations (reads, writes, deletes)                         │
│  ✓ Network connections (IP:port pairs, basic metadata)              │
│  ✓ Parent-child process relationships                               │
├─────────────────────────────────────────────────────────────────────┤
│                     WHAT TELEMETRY MISSES                           │
├─────────────────────────────────────────────────────────────────────┤
│  ✗ Protocol-level details (Modbus registers, HTTP paths)            │
│  ✗ Actual data values transmitted                                   │
│  ✗ Connections from devices without logging (PLCs, RTUs)            │
│  ✗ Precise packet timing and network metrics                        │
│  ✗ Full conversation reconstruction                                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Network Traffic Alone (Incomplete Picture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                       WHAT PCAP CAPTURES                            │
├─────────────────────────────────────────────────────────────────────┤
│  ✓ Every packet on the wire (complete network visibility)           │
│  ✓ Protocol details (Modbus function codes, register values)        │
│  ✓ HTTP requests/responses with full headers                        │
│  ✓ TLS metadata (SNI, certificates)                                 │
│  ✓ Precise timing, packet sizes, TCP behavior                       │
├─────────────────────────────────────────────────────────────────────┤
│                       WHAT PCAP MISSES                              │
├─────────────────────────────────────────────────────────────────────┤
│  ✗ Which process initiated the connection                           │
│  ✗ Which user was logged in                                         │
│  ✗ Local file operations that triggered the network activity        │
│  ✗ Process command-line arguments                                   │
│  ✗ Internal host activity (memory, registry, etc.)                  │
└─────────────────────────────────────────────────────────────────────┘
```

### The Unified View (Complete Picture)

By **correlating** both sources, we can answer forensic questions neither source can answer alone:

| Question | Telemetry | PCAP | Combined |
|----------|-----------|------|----------|
| "Who connected to the PLC?" | ✓ Process name | ✗ Only IP | ✓ Process + IP + timing |
| "What registers were accessed?" | ✗ No protocol detail | ✓ Full Modbus | ✓ Process → Register |
| "What value was written?" | ✗ No payload | ✓ Actual value | ✓ Process wrote value X |
| "Was this connection normal?" | Partial | ✓ Flow metrics | ✓ Behavioral baseline |

---

## System Architecture

### High-Level Data Flow

```
                    ┌─────────────────────┐
                    │   ICS ENVIRONMENT   │
                    └─────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
    ┌───────────────┐                   ┌───────────────┐
    │  HOST LOGS    │                   │  NETWORK TAP  │
    │  (Sysmon/ETW) │                   │  (PCAP Files) │
    └───────────────┘                   └───────────────┘
            │                                   │
            ▼                                   ▼
    ┌───────────────┐                   ┌───────────────┐
    │ Base Cypher   │                   │ PCAP Index    │
    │ Export        │                   │ (Parsed)      │
    └───────────────┘                   └───────────────┘
            │                                   │
            └─────────────┬─────────────────────┘
                          ▼
                ┌─────────────────────┐
                │  CORRELATION &      │
                │  AUGMENTATION       │
                │  ENGINE             │
                └─────────────────────┘
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
    ┌───────────────┐           ┌───────────────┐
    │  Neo4j Graph  │           │  DuckDB       │
    │  (Structure)  │           │  (Raw Signals)│
    └───────────────┘           └───────────────┘
                          │
                          ▼
                ┌─────────────────────┐
                │  STORY              │
                │  RECONSTRUCTION     │
                │  (Forensic Queries) │
                └─────────────────────┘
```

### Processing Pipeline Stages

| Stage | Purpose | Input | Output |
|-------|---------|-------|--------|
| **1. Telemetry Loading** | Parse existing provenance graph | Base Cypher export | Nodes, relationships, IP mappings |
| **2. PCAP Indexing** | Extract network conversations | PCAP files | Indexed connections with packets |
| **3. Correlation** | Link PCAP flows to processes | Both sources | Process attribution |
| **4. Aggregation** | Collapse noisy connections | Raw PCAP connections | Logical conversation groups |
| **5. Enhancement** | Create augmented nodes | Aggregated data | SignalContainers, enriched edges |
| **6. Emission** | Generate graph statements | Augmented model | Neo4j Cypher + DuckDB records |

---

## The ICS Environment Model

### Network Zones

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENTERPRISE ZONE                             │
│                      (Corporate Network)                            │
│  ┌─────────────┐                                                    │
│  │ Historian   │                                                    │
│  │ Server      │                                                    │
│  └─────────────┘                                                    │
└─────────────────────────────────────────────────────────────────────┘
                              │ DMZ Gateway
┌─────────────────────────────────────────────────────────────────────┐
│                       SUPERVISORY ZONE                              │
│                      (192.168.42.0/24)                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │  SCADA-01   │  │   HMI-01    │  │  EWS-WIN-01 │                  │
│  │  (Ignition) │  │ (Operator)  │  │(Engineering)│                  │
│  └─────────────┘  └─────────────┘  └─────────────┘                  │
│        │                │                │                          │
│        └────────────────┴────────────────┘                          │
└─────────────────────────────────────────────────────────────────────┘
                              │ Modbus TCP (Port 502)
┌─────────────────────────────────────────────────────────────────────┐
│                         FIELD ZONE                                  │
│                      (192.168.43.0/24)                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │   PLC-01    │  │   PLC-02    │  │   RTU-01    │                  │
│  │ (Controller)│  │ (Controller)│  │  (Remote)   │                  │
│  └─────────────┘  └─────────────┘  └─────────────┘                  │
│        │                │                │                          │
│        └────────────────┴────────────────┘                          │
│                         │                                           │
│                    Physical I/O                                     │
│              (Sensors, Actuators, Valves)                           │
└─────────────────────────────────────────────────────────────────────┘
```

### Typical Data Flows

| Flow | Direction | Protocol | Purpose |
|------|-----------|----------|---------|
| SCADA → PLC | Supervisory → Field | Modbus TCP | Read sensor values, write setpoints |
| HMI → PLC | Supervisory → Field | Modbus TCP | Operator control commands |
| EWS → PLC | Supervisory → Field | Modbus TCP | Engineering/programming |
| SCADA → Historian | Supervisory → Enterprise | HTTP/SQL | Archive process data |
| HMI → SCADA | Within Supervisory | HTTP | Display updates |

---

## Neo4j Graph Schema

### Node Types

#### Asset
Represents a physical or virtual computing device in the ICS environment.

```
(:Asset {
    guid: "md5-based-uuid",
    hostname: "SCADA-01",
    ipAddresses: ["192.168.42.20"],
    role: "SCADA Server",           // Optional: from assets.yaml
    zone: "Supervisory",            // Optional: network zone
    description: "Ignition Gateway" // Optional: human description
})
```

**Examples**: SCADA servers, HMI workstations, engineering stations, PLCs, RTUs

---

#### Process
Represents an executing program on a host. Can be:
- **Real**: Captured by telemetry (has full metadata)
- **Virtual**: Placeholder for devices without telemetry (PLCs)

```
(:Process {
    guid: "process-guid-from-sysmon",
    image: "C:\\Program Files\\Ignition\\ignition.exe",
    processId: 1234,
    computerName: "SCADA-01",
    user: "SYSTEM",
    commandLine: "ignition.exe -Xmx2048m",
    parentProcessGuid: "parent-guid",
    startTime: "2024-01-15T08:00:00Z"
})
```

**For PLCs/RTUs (Virtual Process)**:
```
(:Process {
    guid: "virtual-plc-01-modbus",
    image: "PLC Firmware",
    computerName: "PLC-01",
    isVirtual: true,
    description: "Virtual process for field device without telemetry"
})
```

---

#### NetworkService
Represents a network endpoint (listening service or client connection point).

```
(:NetworkService {
    guid: "md5-based-uuid",
    host: "PLC-01",
    port: 502,
    protocol: "tcp",
    service: "modbus",
    direction: "server"  // or "client"
})
```

**Common Services in ICS**:
| Port | Protocol | Service |
|------|----------|---------|
| 502 | TCP | Modbus TCP |
| 44818 | TCP | EtherNet/IP |
| 102 | TCP | S7comm (Siemens) |
| 80/443 | TCP | HTTP/HTTPS (SCADA web) |
| 8080 | TCP | Ignition Gateway |

---

#### SignalContainer
Represents observations of a specific signal (Modbus register) at a specific observation point. **Key insight**: The same physical register may have multiple SignalContainer nodes—one per observer—enabling multi-hop integrity verification.

```
(:SignalContainer {
    guid: "md5-based-uuid",
    address: 40001,                    // Register address
    unitId: 1,                         // Modbus unit ID
    observerHost: "SCADA-01",          // WHO observed this signal
    port: 502,
    modbusRegisterType: "holdingRegister",  // coil, discreteInput, holdingRegister, inputRegister

    // Observation statistics
    totalObservations: 15420,
    readCount: 15400,
    writeCount: 20,

    // Value statistics (for analog signals)
    minValue: 0,
    maxValue: 1023,
    meanValue: 512.5,
    distinctValues: 847,

    // Temporal bounds
    firstSeenAt: 1705312800.0,         // Unix timestamp
    lastSeenAt: 1705399200.0,

    pcapAugmented: true
})
```

**Why Multiple Observers Matter**:
```
Physical Register 40001 on PLC-01
        │
        ├── SignalContainer (observer: PLC-01)     ← Server's view
        ├── SignalContainer (observer: SCADA-01)   ← SCADA's view
        └── SignalContainer (observer: HMI-01)     ← HMI's view

If values differ between observers → potential tampering or network issue
```

---

#### Host (External/Unknown)
Represents an external or unidentified network endpoint.

```
(:Host {
    guid: "md5-based-uuid",
    ipAddress: "10.0.0.50",
    classification: "external"
})
```

---

### Relationship Types

#### ESTABLISH_CONNECTION
Network connection between two endpoints. The primary relationship for network provenance.

```
(source)-[:ESTABLISH_CONNECTION {
    // Identification
    guid: "connection-guid",

    // Directionality
    srcIp: "192.168.42.20",
    srcPort: 49152,
    dstIp: "192.168.43.9",
    dstPort: 502,
    protocol: "tcp",

    // Timing
    firstPacketTime: 1705312800.0,
    lastPacketTime: 1705312860.0,
    duration: 60.0,

    // Volume metrics
    totalPackets: 1200,
    totalBytes: 48000,
    packetsClientToServer: 600,
    packetsServerToClient: 600,

    // Protocol detection
    highLevelProtocol: "modbus",

    // Process attribution (if correlated)
    attributedProcessGuid: "process-guid",
    attributedProcessImage: "ignition.exe",
    correlationConfidence: 0.95,

    // PCAP source
    pcapAugmented: true,
    pcapFile: "capture_2024-01-15.pcap"
}]->(destination)
```

---

#### SERVED_ON
Links a NetworkService to the Asset it runs on.

```
(:NetworkService)-[:SERVED_ON]->(:Asset)

Example: Modbus service on PLC
(:NetworkService {host: "PLC-01", port: 502})-[:SERVED_ON]->(:Asset {hostname: "PLC-01"})
```

---

#### OBSERVED
Links a NetworkService to SignalContainers it observed (saw traffic for).

```
(:NetworkService)-[:OBSERVED {
    role: "server",           // or "client"
    observationCount: 15420,
    firstObserved: 1705312800.0,
    lastObserved: 1705399200.0
}]->(:SignalContainer)
```

---

#### ACCESSED_SIGNAL
**Critical for story reconstruction**: Links a Process to SignalContainers it accessed. This is where telemetry meets PCAP.

```
(:Process)-[:ACCESSED_SIGNAL {
    accessType: "read",           // or "write" or "read_write"
    readCount: 15400,
    writeCount: 20,
    firstAccess: 1705312800.0,
    lastAccess: 1705399200.0,

    // Attribution metadata
    correlationMethod: "telemetry",  // or "temporal"
    correlationConfidence: 0.95,

    pcapAugmented: true
}]->(:SignalContainer)
```

---

#### RUNS
Links an Asset to Processes running on it.

```
(:Asset)-[:RUNS]->(:Process)

Example:
(:Asset {hostname: "SCADA-01"})-[:RUNS]->(:Process {image: "ignition.exe"})
```

---

### Graph Visualization

#### Simple Connection (Telemetry Only)
```
┌─────────┐         ┌─────────────────┐         ┌─────────┐
│ SCADA-01│◄─RUNS───│    ignition.exe │         │  PLC-01 │
│ (Asset) │         │    (Process)    │         │ (Asset) │
└─────────┘         └────────┬────────┘         └────┬────┘
                             │                       │
                             │ ESTABLISH_CONNECTION  │
                             │ (basic: IP, port)     │
                             └───────────────────────┘
```

#### Augmented Connection (Telemetry + PCAP)
```
┌─────────┐         ┌─────────────────┐                    ┌─────────┐
│ SCADA-01│◄─RUNS───│    ignition.exe │                    │  PLC-01 │
│ (Asset) │         │    (Process)    │                    │ (Asset) │
└────┬────┘         └───────┬─────────┘                    └────┬────┘
     │                      │                                   │
     │              ┌───────┴────────┐                          │
     │              │ ACCESSED_SIGNAL│                          │
     │              │ (read: 15400)  │                          │
     │              └───────┬────────┘                          │
     │                      ▼                                   │
     │            ┌──────────────────┐                          │
     │            │ SignalContainer  │◄────────OBSERVED─────────┤
     │            │ addr: 40001      │                          │
     │            │ observer: SCADA  │         ┌────────────────┤
     │            └──────────────────┘         │                │
     │                                         ▼                │
     │                               ┌──────────────────┐       │
     │                               │ SignalContainer  │       │
     │                               │ addr: 40001      │       │
     │                               │ observer: PLC-01 │       │
     │                               └──────────────────┘       │
     │                                         ▲                │
     │ SERVED_ON    ┌─────────────────┐        │                │
     └──────────────│ NetworkService  │────────┘                │
                    │ port: 49152     │  OBSERVED               │
                    │ (client)        │                    SERVED_ON
                    └─────────────────┘                         │
                                                                │
                              ┌─────────────────┐               │
                              │ NetworkService  │◄──────────────┘
                              │ port: 502       │
                              │ (server/modbus) │
                              └─────────────────┘
```

---

## Story Reconstruction Capabilities

### What Questions Can Be Answered?

#### Attribution Questions
- **"Which process accessed register 40001?"**
  ```cypher
  MATCH (p:Process)-[:ACCESSED_SIGNAL]->(s:SignalContainer {address: 40001})
  RETURN p.image, p.computerName, p.user
  ```

- **"What did user OPERATOR1 modify?"**
  ```cypher
  MATCH (p:Process {user: "OPERATOR1"})-[r:ACCESSED_SIGNAL {accessType: "write"}]->(s:SignalContainer)
  RETURN s.address, r.writeCount, s.observerHost
  ```

#### Temporal Questions
- **"What happened between 14:00 and 14:30?"**
  ```cypher
  MATCH (p:Process)-[r:ACCESSED_SIGNAL]->(s:SignalContainer)
  WHERE r.firstAccess >= timestamp1 AND r.lastAccess <= timestamp2
  RETURN p.image, s.address, r.accessType
  ORDER BY r.firstAccess
  ```

- **"Show the sequence of register accesses"**
  ```cypher
  MATCH (p:Process)-[r:ACCESSED_SIGNAL]->(s:SignalContainer)
  RETURN p.image, s.address, r.accessType, r.firstAccess
  ORDER BY r.firstAccess
  ```

#### Integrity Questions
- **"Did SCADA and HMI see the same value for register 40001?"**
  ```cypher
  MATCH (s1:SignalContainer {address: 40001, observerHost: "SCADA-01"})
  MATCH (s2:SignalContainer {address: 40001, observerHost: "HMI-01"})
  RETURN s1.meanValue, s2.meanValue,
         abs(s1.meanValue - s2.meanValue) as discrepancy
  ```

- **"Find registers with observation discrepancies across observers"**
  ```cypher
  MATCH (s1:SignalContainer)-[:OBSERVED]-(ns1:NetworkService)
  MATCH (s2:SignalContainer {address: s1.address})-[:OBSERVED]-(ns2:NetworkService)
  WHERE s1.observerHost <> s2.observerHost
    AND abs(s1.meanValue - s2.meanValue) > threshold
  RETURN s1.address, s1.observerHost, s2.observerHost,
         s1.meanValue, s2.meanValue
  ```

#### Behavioral Questions
- **"Which hosts communicated with the PLC?"**
  ```cypher
  MATCH (a:Asset)-[:SERVED_ON]-(ns:NetworkService)-[r:ESTABLISH_CONNECTION]-(ns2:NetworkService)-[:SERVED_ON]-(plc:Asset {hostname: "PLC-01"})
  RETURN DISTINCT a.hostname, r.totalPackets, r.highLevelProtocol
  ```

- **"Find unusual connection patterns"**
  ```cypher
  MATCH (p:Process)-[r:ESTABLISH_CONNECTION]->(ns:NetworkService {port: 502})
  WHERE NOT p.image CONTAINS "ignition"
    AND NOT p.image CONTAINS "scada"
  RETURN p.image, p.computerName, ns.host
  ```

#### Forensic Reconstruction
- **"Reconstruct the attack timeline"**
  ```cypher
  MATCH path = (attacker:Process)-[:ACCESSED_SIGNAL|ESTABLISH_CONNECTION*1..5]->(target)
  WHERE attacker.computerName = "COMPROMISED-HOST"
  RETURN path
  ORDER BY relationships(path)[0].firstAccess
  ```

---

## Correlation Mechanisms

### How PCAP Flows Are Attributed to Processes

```
┌─────────────────────────────────────────────────────────────────────┐
│                    CORRELATION STRATEGIES                           │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ STRATEGY 1: Direct Telemetry Match (High Confidence)                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Telemetry says: "Process X connected to 192.168.43.9:502"          │
│  PCAP shows:     "192.168.42.20:49152 → 192.168.43.9:502"           │
│                                                                     │
│  Match criteria:                                                    │
│  • Same source IP (via hostname resolution)                         │
│  • Same destination IP and port                                     │
│  • Same protocol (TCP)                                              │
│  • Overlapping time window                                          │
│                                                                     │
│  Result: PCAP details attributed to Process X                       │
│  Confidence: HIGH (backed by telemetry)                             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ STRATEGY 2: Temporal Inference (Medium Confidence)                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PCAP shows connection from internal IP, but no direct telemetry    │
│  match. System finds processes active on that host during the       │
│  connection timeframe.                                              │
│                                                                     │
│  Match criteria:                                                    │
│  • PCAP source IP resolves to known host                            │
│  • Process was running on that host                                 │
│  • Process start_time < PCAP timestamp < process end_time           │
│  • Process has network capability (not notepad.exe)                 │
│                                                                     │
│  Result: PCAP details attributed with temporallyInferred: true      │
│  Confidence: MEDIUM (circumstantial)                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ STRATEGY 3: Virtual Process (For Field Devices)                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PLCs and RTUs don't run Windows, so no Sysmon telemetry.           │
│  System creates virtual Process placeholders.                       │
│                                                                     │
│  Match criteria:                                                    │
│  • PCAP source IP resolves to known PLC/RTU (via assets.yaml)       │
│  • Device role is "PLC", "RTU", or similar                          │
│                                                                     │
│  Result: Virtual Process created, PCAP attributed to it             │
│  Confidence: HIGH (device identification known)                     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Modbus Protocol Deep Dive

### Why Modbus Matters for ICS Forensics

Modbus is the lingua franca of industrial control. Understanding Modbus traffic reveals:
- What sensors are being read (inputs)
- What actuators are being controlled (outputs)
- What setpoints are being changed (configuration)
- Anomalous access patterns (reconnaissance, manipulation)

### Modbus Register Types

| Type | Address Range | Access | Purpose |
|------|---------------|--------|---------|
| **Coil** | 00001-09999 | R/W | Digital outputs (on/off) |
| **Discrete Input** | 10001-19999 | R | Digital inputs (sensors) |
| **Input Register** | 30001-39999 | R | Analog inputs (16-bit) |
| **Holding Register** | 40001-49999 | R/W | Analog outputs/config |

### What the Graph Captures

For each Modbus register observed:
- **Address**: Which register (e.g., 40001)
- **Unit ID**: Which slave device
- **Access pattern**: Read count vs write count
- **Value statistics**: Min, max, mean, distinct values
- **Temporal bounds**: First and last observation
- **Multi-observer data**: Same register seen from multiple vantage points

### Example: Detecting Unauthorized Modification

```
Normal pattern:
  SCADA-01/ignition.exe writes register 40001 every 5 minutes
  Values: 100-200 range (temperature setpoint)

Anomaly detected:
  EWS-WIN-01/cmd.exe writes register 40001 at 02:30 AM
  Value: 999 (outside normal range)

Graph query reveals:
  - Process: cmd.exe (unusual for Modbus)
  - User: YOURDOMAINNAME\admin (legitimate but unusual time)
  - No corresponding HMI activity (operator wasn't present)
```

---

## Data Storage Architecture

### Dual Storage Strategy

```
┌─────────────────────────────────────────────────────────────────────┐
│                         NEO4J GRAPH                                 │
│                    (Structure & Relationships)                      │
├─────────────────────────────────────────────────────────────────────┤
│  Stores:                                                            │
│  • Node identities (Assets, Processes, Services, SignalContainers)  │
│  • Relationships (connections, observations, access patterns)       │
│  • Aggregate statistics (counts, min/max, means)                    │
│  • Temporal bounds (first seen, last seen)                          │
│                                                                     │
│  Optimized for: Graph traversal, relationship queries, pathfinding  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ SignalContainer.guid references
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DUCKDB                                      │
│                    (Raw Signal Observations)                        │
├─────────────────────────────────────────────────────────────────────┤
│  Stores:                                                            │
│  • Every individual register read/write observation                 │
│  • Exact timestamps (request and response)                          │
│  • Actual values transmitted                                        │
│  • Transaction IDs for request/response correlation                 │
│  • PCAP file source for audit trail                                 │
│                                                                     │
│  Optimized for: Time-series queries, value analysis, data export    │
└─────────────────────────────────────────────────────────────────────┘
```

### Why Two Databases?

| Concern | Neo4j | DuckDB |
|---------|-------|--------|
| "Who accessed what?" | ✓ Graph queries | |
| "What value at time T?" | | ✓ Time-series |
| "Path from A to B?" | ✓ Pathfinding | |
| "Statistical analysis?" | | ✓ SQL analytics |
| "Visualize relationships?" | ✓ Graph viz | |
| "Export to CSV?" | | ✓ Columnar export |

---

## Aggregation and Noise Reduction

### The Problem: Ephemeral Port Explosion

A single SCADA polling session might create hundreds of TCP connections:
```
SCADA:49152 → PLC:502  (poll 1)
SCADA:49153 → PLC:502  (poll 2)
SCADA:49154 → PLC:502  (poll 3)
... (hundreds more)
```

Without aggregation, the graph becomes cluttered with redundant relationships.

### The Solution: Logical Grouping

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AGGREGATION STRATEGIES                           │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ MODBUS GROUPING (Port 502)                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Before: 500 connections (SCADA:ephemeral → PLC:502)                │
│  After:  1 ModbusGroup with aggregated register statistics          │
│                                                                     │
│  Preserves: All register accesses, values, timing                   │
│  Collapses: Redundant connection-level details                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ HTTP MONITOR GROUPING (Port 8080)                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Before: 1000 HTTP requests (HMI polling SCADA web interface)       │
│  After:  1 HTTPMonitorGroup representing the monitoring session     │
│                                                                     │
│  Preserves: Endpoints accessed, request patterns                    │
│  Collapses: Individual HTTP request noise                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ GENERIC COLLAPSED GROUPING                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  For other protocols with ephemeral client ports                    │
│  Groups by: (client_ip, server_ip, server_port, protocol)           │
│                                                                     │
│  Before: 50 connections (Host:ephemeral → Server:443)               │
│  After:  1 CollapsedGroup with total metrics                        │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Forensic Analysis Workflows

### Workflow 1: Incident Investigation

```
1. IDENTIFY ANOMALY
   └── Alert: "Unusual Modbus write to PLC-01 register 40001"

2. FIND THE CONNECTION
   └── Query: SignalContainers with write access to address 40001
   └── Result: Write from SCADA-01 at 14:32:15

3. ATTRIBUTE TO PROCESS
   └── Query: Process with ACCESSED_SIGNAL to that SignalContainer
   └── Result: Process "custom_tool.exe" by user "YOURDOMAINNAME\contractor"

4. TRACE ORIGIN
   └── Query: How did custom_tool.exe get on SCADA-01?
   └── Follow: Process parent chain, file creation events

5. ASSESS IMPACT
   └── Query: What else did this process access?
   └── Result: Also wrote to registers 40002, 40003 (safety limits)

6. BUILD TIMELINE
   └── Query: All activities by this user/process in time window
   └── Export: Chronological event sequence for report
```

### Workflow 2: Baseline Comparison

```
1. ESTABLISH NORMAL
   └── Query: All processes that access Modbus registers
   └── Result: ignition.exe, kepserver.exe (expected SCADA software)

2. DETECT DEVIATION
   └── Query: Processes accessing Modbus NOT in baseline
   └── Result: python.exe on EWS-WIN-01 (new, needs investigation)

3. INVESTIGATE
   └── Query: What registers did python.exe access?
   └── Result: Read all holding registers 40001-40100 (reconnaissance?)

4. CORRELATE
   └── Query: What else happened on EWS-WIN-01 around that time?
   └── Result: USB device inserted 5 minutes prior
```

### Workflow 3: Multi-Hop Integrity Check

```
1. SELECT CRITICAL SIGNAL
   └── Register 40001: Reactor temperature setpoint (safety-critical)

2. FIND ALL OBSERVERS
   └── Query: All SignalContainers for address 40001
   └── Result: Observed by PLC-01, SCADA-01, HMI-01, Historian

3. COMPARE VALUES
   └── For each observer: min, max, mean, observation count
   └── Expected: All observers see same values (network is honest)

4. DETECT DISCREPANCY
   └── PLC-01 mean: 150.0
   └── SCADA-01 mean: 150.0
   └── HMI-01 mean: 175.0    ← DISCREPANCY!

5. INVESTIGATE
   └── Man-in-the-middle? HMI compromise? Network issue?
   └── Check: Are HMI observations from same time window?
   └── Check: Is there a process on HMI modifying displayed values?
```

---

## Summary: The Provenance Graph Value Proposition

### Without This System
- Telemetry shows "something connected to the PLC"
- PCAP shows "someone read register 40001"
- No link between the two observations
- Manual correlation required (hours of analyst time)

### With This System
- Graph shows "ignition.exe on SCADA-01 (user: SYSTEM) read register 40001 on PLC-01, value was 350, at 14:32:15"
- Single query returns full attribution
- Multi-hop verification catches tampering
- Automated correlation saves analyst time

### Key Capabilities

| Capability | Benefit |
|------------|---------|
| **Process Attribution** | Know which software accessed which registers |
| **User Attribution** | Know which operator/account was responsible |
| **Temporal Precision** | Exact timestamps for forensic timeline |
| **Value Capture** | Know what data was read or written |
| **Multi-Hop Integrity** | Detect data manipulation in transit |
| **Behavioral Baseline** | Distinguish normal from anomalous |
| **Graph Traversal** | Follow attack paths through network |

This unified provenance graph transforms ICS security from "we saw network traffic" to "we know exactly who did what, when, and what the impact was."
