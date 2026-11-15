# Suricata NIDS + Wazuh SIEM | SOC Detection Engineering Lab

<p align="center">
  <img src="https://img.shields.io/badge/Wazuh-v4.14.9-007EC6?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh v4.14.9">
  <img src="https://img.shields.io/badge/Suricata-v8.0.8-EF3B2C?style=for-the-badge&logo=suricata&logoColor=white" alt="Suricata v8.0.8">
  <img src="https://img.shields.io/badge/Engine-AF__PACKET-blue?style=for-the-badge&logo=linux&logoColor=white" alt="AF_PACKET">
  <img src="https://img.shields.io/badge/Signatures-53%2C500%2B-orange?style=for-the-badge&logo=securityscorecard&logoColor=white" alt="Signatures">
  <img src="https://img.shields.io/badge/Status-Verified%20%26%20Operational-success?style=for-the-badge&logo=checkmarx&logoColor=white" alt="Status">
</p>

A hands-on detection engineering and security operations lab demonstrating the deployment, architecture, and integration of **Suricata High-Performance Network IDS** with the **Wazuh SIEM Platform**. Network packets are captured, decoded, and matched against 53,500+ threat signatures in near-real time, normalized into structured EVE JSON telemetry, and correlated inside Wazuh for centralized SOC threat hunting and investigation from the security analyst workstation.

> [!IMPORTANT]
> **Co-Located Server Architecture:** Suricata runs natively on the Wazuh Server. The Wazuh Manager's built-in **Logcollector** daemon monitors Suricata's `eve.json` output in real time using the native JSON log format. The security analyst accesses the **Wazuh Dashboard** remotely from the **Windows 11 Analyst Workstation** via browser over HTTPS.

---

## Table of Contents

- [1. Executive Summary & Capabilities](#1-executive-summary--capabilities)
- [2. System Architecture & Topology](#2-system-architecture--topology)
  - [2.1 High-Level Architecture Diagram](#21-high-level-architecture-diagram)
  - [2.2 Detailed Event Pipeline](#22-detailed-event-pipeline)
  - [2.3 Component Responsibility Matrix](#23-component-responsibility-matrix)
- [3. Monitored Endpoint Fleet](#3-monitored-endpoint-fleet)
- [4. Core Integration & Detection Flow](#4-core-integration--detection-flow)
- [5. SOC Threat Hunting in Wazuh Dashboard](#5-soc-threat-hunting-in-wazuh-dashboard)
  - [5.1 Threat Hunting Queries](#51-threat-hunting-queries)
  - [5.2 Normalized Field Reference](#52-normalized-field-reference)
- [6. Detection Engineering & Operational Boundaries](#6-detection-engineering--operational-boundaries)
- [7. Official References](#7-official-references)

---

## 1. Executive Summary & Capabilities

Modern Security Operations Centers (SOCs) require comprehensive visibility across both endpoint telemetry (EDR/HIDS) and network telemetry (NIDS). This lab establishes a centralized detection and correlation pipeline delivering:

- **High-Speed Network Sniffing:** Multi-threaded packet capture and stream reassembly powered by Suricata's `AF_PACKET` engine on `ens33`.
- **Threat Intelligence Feeds:** Integration with **Emerging Threats Open (ET Open)** and **OISF TrafficID** feeds, compiling over 53,500 active detection signatures.
- **Deep Protocol Decoding:** Layered inspection decoding Ethernet, IP, TCP, UDP, and application protocols (HTTP, TLS, DNS).
- **Structured Telemetry Normalization:** Outputting enriched flow, DNS, TLS, HTTP, anomaly, and alert data into Suricata's Extensible Event Format (`eve.json`).
- **SIEM Correlation & Rule Evaluation:** Ingestion by the Wazuh Logcollector and automated parsing through Wazuh's JSON decoder and Suricata ruleset (`0475-suricata_rules.xml`).
- **Analyst Threat Hunting on Windows 11:** Secure web-based exploration via the Wazuh Dashboard accessed from the Windows 11 analyst workstation.

---

## 2. System Architecture & Topology

### 2.1 High-Level Architecture Diagram

The lab network consists of monitored enterprise endpoints alongside the central Ubuntu security server hosting Suricata and the Wazuh SIEM stack:

<p align="center">
  <img src="assets/suricata-wazuh-architecture.jpg" alt="Suricata + Wazuh SOC Lab Architecture" width="900">
</p>

### 2.2 Detailed Event Pipeline

The end-to-end data pipeline moves telemetry from raw packet capture through protocol decoding, signature evaluation, SIEM ingestion, indexing, and analyst investigation on Windows 11:

```mermaid
flowchart TB
    subgraph MonitoredNetwork["Monitored Endpoints & Attacker"]
        W10["Windows 10 Pro<br/>(Monitored Endpoint - Agent 001)"]
        KALI["Kali Linux<br/>(Attack Emulation & Security Testing - Agent 002)"]
    end

    subgraph UbuntuServer["Ubuntu Server (SIEM & NIDS Core Architecture)"]
        NIC["Host Network Interface (ens33)"]

        subgraph SuricataPipeline["Suricata Engine (Network Detection & Analysis)"]
            PKT["Raw Network Packets"]
            DEC["Suricata Packet Decoder<br/>(Decodes Ethernet, IP, TCP, UDP and application-layer protocols)"]
            DET["Suricata Detection Engine<br/>(Evaluates network traffic against Suricata signatures)"]
            EVE["EVE JSON Generation<br/>(Converts detected network events into structured JSON format)"]

            PKT --> DEC
            DEC --> DET
            DET --> EVE
        end

        subgraph WazuhPipeline["Wazuh Manager (Log Analysis & Monitoring)"]
            LCOL["Wazuh Local Logcollector<br/>(Reads eve.json in real time)"]
            JDEC["Wazuh JSON Decoder<br/>(Extracts and normalizes event fields)"]
            RENG["Wazuh Rules Engine<br/>(Evaluates events against 0475-suricata_rules.xml)"]
            ALERTS["Security Alert Generation<br/>(Outputs qualified alerts to alerts.json)"]

            LCOL --> JDEC
            JDEC --> RENG
            RENG --> ALERTS
        end

        FB["Filebeat Log Shipper<br/>(Forwards alerts over TLS)"]
        IDX["Wazuh Indexer<br/>(Stores and indexes documents on port 9200)"]
        DASH_SRV["Wazuh Dashboard Service<br/>(Web Application Backend - Port 443)"]

        NIC --> PKT
        EVE --> LCOL
        ALERTS --> FB
        FB --> IDX
        IDX --> DASH_SRV
    end

    subgraph Win11Host["Windows 11 (SOC Analyst Workstation - Agent 003)"]
        DASH_UI["Wazuh Dashboard Web Interface<br/>(SOC Threat Hunting, Incident Investigation & Visual Dashboards)"]
    end

    MonitoredNetwork -. Network Traffic & Encrypted Agent Events (Port 1514) .-> NIC
    DASH_SRV ==>|"HTTPS Web Session (Analyst UI)"| DASH_UI
```

### 2.3 Component Responsibility Matrix

| Component | Layer / Host | Role & Responsibility in Pipeline |
|---|---|---|
| **Raw Packets & Suricata Decoder** | Network / Ubuntu Server | Captures raw frames via `AF_PACKET` on `ens33` and decodes Ethernet, IP, TCP, UDP, and application-layer protocols. |
| **Suricata Detection Engine** | Detection / Ubuntu Server | Evaluates network traffic against 53,500+ active Suricata signatures (ET Open & OISF TrafficID). |
| **EVE JSON Generation** | Serialization / Ubuntu Server | Converts detected network events into structured JSON format written to `/var/log/suricata/eve.json`. |
| **Wazuh Local Logcollector** | Ingestion / Ubuntu Server | Real-time file collector that continuously reads `eve.json` and submits records into the Wazuh analysis queue. |
| **Wazuh JSON Decoder** | Normalization / Ubuntu Server | Extracts nested JSON key-value pairs (`data.alert.*`, `data.src_ip`, `data.dest_ip`, `data.proto`) into searchable fields. |
| **Wazuh Rules Engine** | Correlation / Ubuntu Server | Evaluates parsed events against `0475-suricata_rules.xml`, assigns alert levels (3–12), and outputs to `alerts.json`. |
| **Filebeat Log Shipper** | Transport / Ubuntu Server | Ships formatted alert documents securely over TLS to the Wazuh Indexer. |
| **Wazuh Indexer** | Search & Storage / Ubuntu Server | High-performance distributed OpenSearch datastore indexing alerts into `wazuh-alerts-*`. |
| **Wazuh Dashboard (Analyst UI)** | Presentation / Windows 11 | Accessed via browser from the Windows 11 workstation for interactive threat hunting, query filtering, and incident investigation. |

---

## 3. Monitored Endpoint Fleet

| System Name | Operating System | Wazuh Agent ID | Communication Channel | Role |
|---|---|:---:|---|---|
| **`wazuh-server`** | Ubuntu Server 22.04/24.04 | `000` | Local System / Logcollector | Central SIEM & NIDS Server |
| **`WIN11-SOC-HOST`** | Windows 11 Enterprise | `003` | TCP 1514 (Agent) & HTTPS (Dashboard Web UI) | SOC Analyst Workstation & Monitored Host |
| **`WIN10-SOC-LAB`** | Windows 10 Pro | `001` | TCP 1514 (AES Encrypted) | Monitored Endpoint |
| **`KALI-SOC-LAB`** | Kali Linux Rolling | `002` | TCP 1514 (AES Encrypted) | Attack Emulation & Security Testing |

---

## 4. Core Integration & Detection Flow

The pipeline operates through a streamlined four-stage data cycle:

```
[ Network Traffic ]
        │
        ▼
(1) Suricata NIDS ────► Packet Decoder ──► Detection Engine (53k+ Signatures)
        │
        ▼
(2) EVE JSON ─────────► EVE JSON Generation ──► /var/log/suricata/eve.json
        │
        ▼
(3) Wazuh Manager ────► Logcollector ──► JSON Decoder ──► Rules Engine
        │
        ▼
(4) Storage & UI ─────► Filebeat ──► Wazuh Indexer ──► Windows 11 Analyst Dashboard
```

1. **Traffic Ingestion & Packet Decoding:** Suricata binds to `ens33` using high-speed `AF_PACKET` capture with hardware ring buffers (`tpacket-v3: yes`), decoding Ethernet, IP, TCP/UDP, and application layers.
2. **Signature Evaluation & EVE JSON Generation:** Ingress and egress traffic is compared against Emerging Threats and OISF signatures. Matching events are serialized with comprehensive metadata (flow IDs, payload anomalies, protocol decoders) into `eve.json`.
3. **Local Manager Collection:** The Wazuh Manager ingests the JSON log stream via its native `<localfile>` configuration:
   ```xml
   <localfile>
     <location>/var/log/suricata/eve.json</location>
     <log_format>json</log_format>
   </localfile>
   ```
4. **Correlation, Indexing & Threat Hunting:** Wazuh correlates network anomalies with host events, generates standardized security alert objects, and Filebeat transmits them into the Wazuh Indexer. Security analysts investigate alerts directly from the Windows 11 workstation.

---

## 5. SOC Threat Hunting in Wazuh Dashboard

### 5.1 Threat Hunting Queries

Security analysts can query the `wazuh-alerts-*` data view in the Wazuh Dashboard from the Windows 11 workstation using Kibana Query Language (KQL) or Lucene syntax:

| Investigation Objective | Query Filter |
|---|---|
| **All Suricata Detections** | `rule.groups: "suricata"` |
| **Local Host Network Alerts** | `agent.id: "000" AND rule.groups: "suricata"` |
| **Specific Rule ID Match** | `rule.id: 86601` |
| **High-Severity Network Detections** | `rule.groups: "suricata" AND rule.level >= 7` |
| **Filter by Source IP** | `data.src_ip: "<target-ip>"` |
| **Protocol Anomaly Detections** | `data.alert.signature: *TLS*` or `data.alert.signature: *Anomaly*` |
| **Specific Threat Signatures** | `data.alert.signature: *GPL*` or `data.alert.signature: *ET*` |

### 5.2 Normalized Field Reference

When Suricata alerts are indexed, Wazuh normalizes the nested JSON keys into standard investigation fields:

| Field Name | Type | Description |
|---|---|---|
| `agent.id` | Keyword | Wazuh agent (`000` corresponds to local Manager) |
| `rule.id` | Keyword | Wazuh rule ID (e.g., `86601` for Suricata alerts) |
| `rule.level` | Integer | Wazuh severity rating (typically 3 to 12) |
| `rule.groups` | Array | Classification tags (`["ids", "suricata"]`) |
| `data.src_ip` | IP | Source IP of the flagged network flow |
| `data.src_port` | Integer | Source transport port |
| `data.dest_ip` | IP | Destination IP of the flagged network flow |
| `data.dest_port` | Integer | Destination transport port |
| `data.proto` | Keyword | Network layer 4 protocol (`TCP`, `UDP`, `ICMP`) |
| `data.alert.signature` | Text | Human-readable name of the triggered signature |
| `data.alert.signature_id` | Long | Unique Suricata Signature ID (SID) |
| `data.alert.category` | Keyword | Threat classification (e.g., `Potentially Bad Traffic`) |
| `data.alert.action` | Keyword | Enforcement disposition (`allowed` or `blocked`) |

---

## 6. Detection Engineering & Operational Boundaries

1. **Virtual Switch Visibility:** In virtualized environments (e.g., VMware Workstation, ESXi, Proxmox), a standard virtual NIC only receives broadcast traffic and unicast traffic addressed to or from that host. To inspect East-West traffic between other virtual machines (e.g., Kali Linux attacking Windows 10), configure a virtual switch with promiscuous mode or set up a dedicated SPAN/port-mirroring session.
2. **Passive IDS vs. Inline IPS:** In this configuration, Suricata operates as a passive **Intrusion Detection System (IDS)** using `AF_PACKET`. Alerts marked with `action: allowed` indicate that traffic matched a signature and was recorded, but was **not dropped**. For active packet blocking (IPS), Suricata must be configured inline with `NFQUEUE` or bridged interfaces.
3. **Telemetry Volume & Storage Hygiene:** Network monitoring produces substantial log volume. Maintain log rotation policies (`/etc/logrotate.d/suricata`) to preserve disk health, and enable full raw archive forwarding (`<logall_json>yes</logall_json>`) only when storage capacity is planned accordingly.

---

## 7. Official References

- [Wazuh Documentation — Network IDS Integration with Suricata](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
- [Wazuh Documentation — Local Log Data Collection (`localfile`)](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
- [Wazuh Documentation — Ruleset and Decoder Architecture](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Suricata Documentation — Quickstart & Configuration Guide](https://docs.suricata.io/en/latest/quickstart.html)
- [Suricata Documentation — AF_PACKET High Speed Capture](https://docs.suricata.io/en/latest/capture-hardware/af-packet.html)
- [Suricata Documentation — EVE JSON Output Format](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [Suricata-Update Documentation — Managing Threat Feeds](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)

---

<p align="center">
  <b>SOC Engineering Lab</b> • Crafted for high-fidelity detection engineering and defensive security operations.
</p>
