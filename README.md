# 🛡️ SENTINEL — Autonomous Cyber Incident Investigation Platform

**SENTINEL** is an end-to-end autonomous cyber security incident investigation platform designed to ingest multi-source security evidence (firewall logs, authentication events, endpoint alerts, DNS queries, phishing emails, PDFs, CSVs, JSONs), reconstruct attack timelines, perform threat intelligence enrichment, construct entity graph relationships, run autonomous investigation loops with competing hypotheses ($H_1-H_4$), detect false positives via counter-evidence evaluation, score incident risk, enforce human-in-the-loop action approvals, and produce evidence-backed reports.

---

## 🌟 Key Features

1. **Multi-Source Evidence Ingestion & Auto-Classification**: Accepts CSV, JSON, TXT, EML, and PDF files, automatically detecting log types without manual classification.
2. **Deterministic Entity Extraction & Unified Schema**: High-precision extraction of IPs, domains, URLs, file hashes, timestamps, usernames, and CVEs mapped to a unified `Timestamp → Source → Entity → Event → Severity → Relationship` schema.
3. **NetworkX Evidence Graph**: Directed multi-graph connecting users, devices, emails, domains, IPs, URLs, hashes, and processes via directed edges (`sent_to`, `clicked`, `resolved_to`, `connected_to`, `executed_on`, `authenticated_from`).
4. **"Hidden Connection" Discovery**: Automatically discovers multi-hop attack paths spanning disparate log files (e.g. Phishing EML → Malicious URL → DNS query → Firewall traffic → Endpoint execution → Auth log).
5. **Autonomous Investigative Loop & Controlled Sandbox**: Implements the `Investigate → Observe → Reason → Decide → Investigate` loop with dynamic lead generation, competing hypotheses (ACH framework $H_1-H_4$), audit trail logging, and autonomous stopping conditions.
6. **Threat Intelligence Enrichment & MITRE ATT&CK**: Integrates VirusTotal, AbuseIPDB, URLScan, WHOIS/RDAP, and MITRE ATT&CK technique mapping with natural-language security explanations.
7. **Contradiction & False-Positive Engine**: Actively searches for counter-evidence (e.g., verifying legitimate cloud provider IPs like AWS/Microsoft or routine scheduled admin tasks) to calibrate confidence scores.
8. **Incident Risk & Impact Scoring**: Dynamically calculates incident risk ($0-100\%$, CRITICAL/HIGH/MED/LOW) and identifies affected user accounts, workstations, and domains.
9. **Attack Chain Reconstruction**: Maps events to 6 attack stages (*Initial Access → Execution → Credential Access → Persistence → C2 → Impact*) with explicit `[UNCONFIRMED]` markers for missing stages.
10. **Human-in-the-Loop (HITL) Action Center**: Destructive containment actions (Block IP, Block Domain, Isolate Host) require explicit human investigator approval before execution.
11. **Explainable AI Rationale**: Clickable *"Why did AI conclude this?"* modal providing an auditable breakdown of evidence pillars with zero hallucinated findings.
12. **Interactive 10-Tab Investigator Dashboard**: Modern dark-mode web application featuring step-by-step investigation replay mode, RAG natural language QA chat, multi-case campaign clustering, and benchmark evaluation metrics.

---

## 🏗️ System Architecture

```
                                  +---------------------------------------+
                                  |   Multi-Source Evidence Ingestion     |
                                  |   (CSV, JSON, TXT, EML, PDF Parser)   |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   Deterministic Extraction & Schema   |
                                  |   (IP, Domain, URL, Hash, Timestamp)  |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   Case Memory & NetworkX Graph Engine |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   Autonomous Investigation Agent      |
                                  |   - Dynamic Priority Lead Queue       |
                                  |   - Competing Hypotheses ACH (H1-H4)  |
                                  |   - Contradiction/False Positive Check|
                                  |   - Controlled Tool Sandbox           |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  | Threat Intel, Risk & Timeline Engine  |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |   Web Dashboard & HITL Action Center  |
                                  +---------------------------------------+
```

---

## 📁 Repository Structure

```
SENTINEL/
├── backend/
│   ├── app.py                  # FastAPI server & REST API routes
│   ├── ingestion.py            # Multi-format ingestion & auto-type classifier
│   ├── extractors.py           # Deterministic regex & entity extractor
│   ├── normalizer.py           # Unified schema normalizer
│   ├── threat_intel.py         # Threat Intel (VT, AbuseIPDB, WHOIS, MITRE)
│   ├── graph_engine.py         # NetworkX evidence multi-graph engine
│   ├── agent.py                # Autonomous agent loop, sandbox & audit trail
│   ├── leads_hypothesis.py     # Dynamic leads queue & Competing Hypotheses (ACH)
│   ├── contradiction_engine.py # Self-verification & counter-evidence evaluator
│   ├── timeline.py             # Timeline & Attack Chain stage reconstructor
│   ├── risk_engine.py          # Incident risk scoring & victim impact engine
│   ├── campaign.py             # Historical case comparison & campaign clustering
│   ├── rag_chat.py             # RAG-backed natural language QA engine
│   ├── report_generator.py     # Evidence-backed report & explainability generator
│   ├── eval_metrics.py         # Benchmark metrics (Manual vs Autonomous triage)
│   └── demo_dataset.py         # Synthetic multi-file realistic attack scenario
├── frontend/
│   ├── index.html              # 10-Tab Single-Page Application dashboard
│   ├── css/styles.css          # Dark-mode cybersecurity UI styling
│   └── js/app.js               # Frontend controller, replay mode & graph renderer
├── Dockerfile                  # Container deployment configuration
├── requirements.txt            # Python dependencies
└── run.py                      # Application launcher script
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.9+ installed.

### 1. Installation
Clone or navigate to the SENTINEL repository:
```bash
git clone https://github.com/your-repo/SENTINEL.git
cd SENTINEL
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launching SENTINEL
Run the single launcher script:
```bash
python run.py
```

Open your browser and navigate to:
👉 **`http://localhost:8000`**

---

## 🐳 Docker Deployment

To build and run SENTINEL inside a Docker container:

```bash
# Build Docker image
docker build -t sentinel-cyber .

# Run Docker container
docker run -d -p 8000:8000 --name sentinel_app sentinel-cyber
```

---

## 🖥️ Web Dashboard Tabs

| Tab Name | Description |
| :--- | :--- |
| **📊 Overview & Risk** | Incident risk score, confidence rating, risk factors, and victim impact summary. |
| **📥 Evidence Inbox** | Upload new evidence files (`.csv`, `.json`, `.eml`, `.pdf`, `.txt`) and inspect normalized events. |
| **🕸️ Investigation Graph** | Interactive HTML5 Canvas visualization of connected entities and hidden attack paths. |
| **⏳ Attack Timeline** | Reconstructed attack chain stages (*Initial Access → C2*) and chronological log timeline. |
| **🤖 AI Agent & Replay** | Audit trail of tool calls executed by the AI and step-by-step investigation replay player. |
| **🎯 Leads & Hypotheses** | Priority queue of unanswered questions and Competing Hypotheses ($H_1-H_4$) ACH matrix. |
| **🔍 Threat Intel & MITRE** | Threat intelligence verdicts (VirusTotal, AbuseIPDB) and mapped MITRE ATT&CK techniques. |
| **⚡ Action Center (HITL)** | Human-in-the-loop approval matrix for recommended response containment actions. |
| **💬 Natural Language QA** | RAG-backed chat interface to ask natural-language questions about the incident. |
| **📈 Benchmark Metrics** | Performance metrics comparing manual analyst triage vs SENTINEL autonomous triage. |

---

---

## 💾 Persistent Database Storage (Phase 2)

SENTINEL features persistent investigation storage powered by SQLAlchemy ORM with multi-database support:

- **Primary Database**: PostgreSQL (configured via `DATABASE_URL` environment variable).
- **Zero-Setup Local Fallback**: SQLite (`sentinel.db`) automatically engaged when PostgreSQL is absent or unreachable, ensuring zero application crashes.
- **Persisted Models**: `Case`, `Evidence`, `IOC`, `InvestigationStep`, `Lead`, `Hypothesis`, `GraphEntity`, `GraphRelationship`, `ThreatIntelResult`, `Report`, `AuditLog`.
- **State Survival**: Complete cases, evidence, audit steps, and graph structures survive full server restarts.
- **Controlled Tool #11 (`get_investigation_memory`)**: Enables the AI agent to query past investigation steps and findings across the active case history.

---

## 🔍 Live Threat Intelligence & IOC Enrichment (Phase 3)

SENTINEL features a modular, read-only threat intelligence provider architecture:

- **VirusTotal Integration**: Read-only IP, domain, URL, and hash reputation (`VIRUSTOTAL_API_KEY`).
- **AbuseIPDB Integration**: Read-only IP abuse confidence scoring, report counts, ISP data (`ABUSEIPDB_API_KEY`).
- **URLScan Integration**: Read-only domain and URL search lookups (`URLSCAN_API_KEY`).
- **RDAP / WHOIS Integration**: **No API key required** (queries public `rdap.org` endpoints for registrar data, creation dates, nameservers).
- **MITRE ATT&CK Mapping**: Local structured mapping of indicators and techniques ($T1566.002, T1071.001, T1059.001$).
- **Multi-Provider Correlation & Caching**: Database-backed caching in `ThreatIntelResultModel` avoids redundant external API calls.
- **UI Status Badging**: Displays 🟢 `LIVE`, 🔵 `CACHED`, 🟡 `FALLBACK`, and ⚪ `UNAVAILABLE` badges on the dashboard and audit trail.
- **Prompt Injection Protection**: Sanitizes raw external threat intel text to defuse malicious instruction overrides.

---

## 📡 REST API Reference

- `GET /api/cases`: Lists all persisted cases saved in the database.
- `POST /api/cases`: Creates a new persistent investigation case.
- `GET /api/cases/{case_id}`: Loads a specific case from persistent storage.
- `DELETE /api/cases/{case_id}`: Deletes a case from persistent storage.
- `GET /api/case`: Retrieves complete active case state (Risk, Graph, Timeline, Audit Trail, Hypotheses, Report).
- `POST /api/ingest`: Accepts file uploads (`multipart/form-data`) and runs autonomous triage on new evidence.
- `POST /api/load-demo`: Reloads the synthetic multi-file demo attack scenario and persists it to DB.
- `POST /api/approve-action`: Updates status of recommended response actions (`APPROVED` / `REJECTED`).
- `POST /api/natural-language`: Submits analyst questions to the RAG query engine.

---

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.
