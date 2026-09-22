# 🛡️ SENTINEL — Final Demonstration Guide

> **Autonomous Cyber Incident Investigation & Explainable Triage Platform**  
> *Pipeline Flow:* **INGEST → EXTRACT → CORRELATE → INVESTIGATE → ENRICH → REASON → VERIFY → REPORT → HUMAN APPROVAL**

---

## Executive Overview

SENTINEL is an end-to-end autonomous cyber incident investigation platform designed for Tier-1/Tier-2 Security Operations Centers (SOC). When a security incident occurs, SENTINEL correlates fragmented evidence across multiple telemetry silos (Email, EDR, Sysmon, Firewall, DNS, Proxy), forms dynamic investigation hypotheses using the Analysis of Competing Hypotheses (ACH) methodology, autonomously queries external threat intelligence and local evidence, constructs an attack graph, and produces grounded, audit-trailed incident assessments for human sign-off.

---

## 15-Step Live Demonstration Script

### Step 1: Reset Demo Scenario
- **Action**: In the top navigation bar, click `🔄 Reset Demo Scenario`.
- **What to Explain**:
  - Automatically loads the multi-stage cyberattack scenario (`Operation DarkPhish`).
  - Initializes a fresh, persistent case in SQLite (`sentinel.db`) with unique case ID.
  - Automatically indexes all multi-source forensic evidence into FAISS local vector store.

### Step 2: Show Evidence Inbox (Tab 2)
- **Action**: Navigate to `📥 Evidence Inbox`.
- **What to Explain**:
  - Displays multi-format telemetry: `.eml` (Phishing Email), `.csv` (Sysmon/Endpoint Process Logs), `.json` (DNS & Proxy telemetry), `.txt` (Firewall logs), and `.pdf` (Threat Intelligence Advisory).
  - **Security Controls**: Upload form enforces a 10MB/file limit, 25MB aggregate limit, extension whitelist, path traversal protection, executable signature blocking (`MZ`, `ELF`, shebangs), and prompt-injection defusing on intake.

### Step 3: Show Investigation Graph (Tab 3)
- **Action**: Navigate to `🕸️ Investigation Graph`.
- **What to Explain**:
  - Displays the live interactive NetworkX attack graph connecting:
    - Target User: `user.smith@company.com`
    - Victim Workstation: `WORKSTATION-FIN01` (10.0.0.15)
    - Phishing Domain: `malicious-phish.net`
    - C2 Server IP: `198.51.100.45`
    - Dropped Payload Hash: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - Demonstrates multi-hop attack path discovery connecting email interaction to outbound C2 beaconing.

### Step 4: Show Attack Timeline (Tab 4)
- **Action**: Navigate to `⏳ Attack Timeline`.
- **What to Explain**:
  - Reconstructs chronological attack chain stages:
    1. Initial Access (Spearphishing Email)
    2. Execution (PowerShell Stager on Endpoint)
    3. Defense Evasion & Persistence
    4. Command & Control (Outbound TCP connection to C2 IP)

### Step 5: Open AI Agent & Replay (Tab 5)
- **Action**: Navigate to `🤖 AI Agent & Replay`.
- **What to Explain**:
  - Demonstrates the interactive replay slider allowing SOC leads to scrub forward and backward through the AI's investigation steps.

### Step 6: Show Autonomous Investigation Steps
- **Action**: Inspect the Step-by-Step Audit Cards.
- **What to Explain**:
  - Each step documents:
    - Current Lead & Observation
    - Selected Controlled Tool from the 12 whitelisted tools
    - Validated Tool Arguments (safe, secret-free)
    - Reasoning Rationale & Findings Summary
    - Newly Discovered IOCs (e.g., Domain → IP → Workstation)
    - Bayesian Hypothesis Update
    - Contradiction Check Status
    - **Stopping Decision & Reason**: Shows the autonomous agent terminating once sufficient evidence confidence is achieved (e.g. posterior probability $\ge 85\%$).

### Step 7: Show Leads & Hypotheses (Tab 6)
- **Action**: Navigate to `🎯 Leads & Hypotheses`.
- **What to Explain**:
  - Visualizes the Analysis of Competing Hypotheses (ACH) Matrix:
    - $H_1$: External Spearphishing Campaign
    - $H_2$: Malware / C2 Backdoor Execution
    - $H_3$: Insider Threat / Credential Misuse
    - $H_4$: Benign False Positive / IT Activity
  - Shows how evidence mathematically updates posterior probabilities and flags $H_2$ / $H_1$ as leading while suppressing $H_4$.

### Step 8: Show Threat Intel & MITRE Enrichment (Tab 7)
- **Action**: Navigate to `🔍 Threat Intel & MITRE`.
- **What to Explain**:
  - Displays IOC enrichment cards with live status badges: `🟢 LIVE`, `🔵 CACHED`, or `🟡 FALLBACK`.
  - Enriches indicators with AbuseIPDB confidence scores, VirusTotal malware detections, and automated MITRE ATT&CK mapping (`T1566.002`, `T1059.001`, `T1071.001`).

### Step 9: Show Action Center / Human-in-the-Loop (Tab 8)
- **Action**: Navigate to `⚡ Action Center (HITL)`.
- **What to Explain**:
  - **Safety Policy**: The AI *never* unilaterally modifies firewalls or isolates machines.
  - All recommended actions (Block Domain, Block IP, Isolate Endpoint) start strictly in `🟡 PENDING APPROVAL`.
  - Click `Approve` or `Reject` on an action to demonstrate real-time Human-in-the-Loop governance with simulated safe sandbox execution.

### Step 10: Ask a Natural Language QA Question (Tab 9)
- **Action**: Navigate to `💬 Natural Language QA`.
- **Query**: Type `"What evidence connects the phishing email to the compromised endpoint?"` and press Enter.

### Step 11: Show Semantic Vector RAG Citations
- **What to Explain**:
  - Retrieval method is strictly `retrieval_method: "vector"` using local `all-MiniLM-L6-v2` embeddings and FAISS index.
  - Displays citations with exact `chunk_id` (e.g., `CHK-EV-0002`), provenance (`phishing_email.eml`, `sysmon_endpoint.csv`), and relevance scores.
  - No synthetic placeholders (`CHK-UNKNOWN` eliminated).

### Step 12: Open Benchmark Metrics (Tab 10)
- **Action**: Navigate to `📈 Benchmark Metrics`.
- **What to Explain**:
  - Displays the 4 primary performance summary cards:
    - **Entity Extraction F1**: `83.3% (Measured)`
    - **RAG Hit Rate**: `100.0% (Measured)`
    - **Graph Path Recovery**: `100.0% (Measured)`
    - **Case Isolation Accuracy**: `100.0% (Measured)`
  - **Integrity**: Zero static or fabricated claims (`1,300x`, `87% Reduction`, etc. have been completely removed).

### Step 13: Run Live Benchmark
- **Action**: Click `⚡ Run Live Benchmark`.
- **What to Explain**:
  - Re-executes the real benchmark runner across all 7 pipeline modules directly over `POST /api/evaluation/run`.
  - Demonstrates verifiable reproducibility under live testing conditions.

### Step 14: Show Measured Results Table
- **What to Explain**:
  - Table populates with all 7 live experiments:
    1. Entity Extraction F1
    2. Graph Attack Path Recovery
    3. Vector RAG Retrieval Hit Rate
    4. Case Isolation Correctness
    5. Hypothesis Evaluation Consistency
    6. Average Controlled Tool Latency
    7. End-to-End Investigation Latency
  - Every row displays `MEASURED` and `PASS`.

### Step 15: Explain Security Controls & Prompt Injection Defense
- **Action**: Click `💡 Why did AI conclude this?` in the navbar.
- **What to Explain**:
  - Explainability modal displays grounded forensic pillars, leading hypothesis, and audit trail progression without exposing system prompts or API keys.
  - **Defensive Engineering**:
    - **Input Boundary Enforcement**: User queries and evidence text are wrapped in `<untrusted_evidence_record>` and `<retrieved_case_evidence>` tags.
    - **Injection Defusing**: Malicious phrases (`Ignore previous instructions`, `Delete database`, `Exfiltrate key`) are automatically sanitized into `[DEFUSED_INJECTION_TEXT]`.
    - **Tool Sandbox**: All tool requests pass through a strict parameter whitelist. Arbitrary shell commands (`powershell`, `cmd.exe`, `bash`, `rm -rf`) are strictly rejected.
    - **Secret Masking**: All API responses, audit logs, and database records are scrubbed to ensure API keys are never disclosed.

---

## Verification & Self-Test Checklist

Run the following test suites from the project root to confirm full system readiness:

```powershell
# Phase 6 Security & Hardening Suite (15/15 tests)
python scratch/verify_phase6.py

# Phase 5 Real Evaluation & Benchmarking Suite (11/11 tests)
python scratch/verify_phase5.py

# Phase 4 Semantic Vector RAG Suite (9/9 tests)
python scratch/verify_phase4.py
```
