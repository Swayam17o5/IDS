# AegisNIDS Live Presentation & SOC Defense Rehearsal Script

---

## 1. Pre-Demo Checklist (5 Minutes Before Presentation)

Execute these checks in order to guarantee 100% demo reliability:

- [ ] **1. Server Running & Clean**:
  - Ensure the backend server is active:
    ```powershell
    python -m uvicorn services.inference.app:app --host 0.0.0.0 --port 8000
    ```
  - Open browser to: `http://localhost:8000/`
  - Click **RESET SOC DATA** in the top-right header and confirm the modal.
  - Verify all metrics start clean: Flows: `0`, Alerts: `0`, Criticals: `0`, Analyst Precision: `—`.

- [ ] **2. Windows Terminal 1 (Admin Shell for Live Capture / Nmap)**:
  - Open an **Elevated (Administrator)** PowerShell window.
  - Verify Nmap 7.92 binary is accessible:
    ```powershell
    .\tools\nmap-7.92\nmap.exe --version
    ```
  - Confirm LAN Gateway IP is reachable:
    ```powershell
    ping 192.168.1.1 -n 1
    ```

- [ ] **3. Wireshark Ready (Optional for 3-Window Side-by-Side)**:
  - If demonstrating the packet capture stream in Wireshark, launch Wireshark and bind to the `Wi-Fi` physical interface.
  - Set display filter: `tcp.port in {21,22,23,53,80,443,8080,8443} and ip.addr == 192.168.1.1`.

- [ ] **4. Browser Window Layout**:
  - Position the AegisNIDS dashboard on the right half of the screen (or primary monitor).
  - Position the Administrator Terminal on the left half of the screen.

---

## 2. Step-by-Step Presentation Script & Talking Points

```
+-----------------------------------------------------------------------------+
|                               TIMELINE OVERVIEW                             |
| 00:00 - 01:30 : Problem Statement & Architecture Overview                   |
| 01:30 - 04:00 : Centerpiece: The 3-Window Live PortScan Correlation Demo     |
| 04:00 - 05:30 : Explainability (Tree SHAP & Natural Language Explanations)  |
| 05:30 - 07:00 : Analyst Triage Workflow & Active Feedback Loop (Retraining) |
| 07:00 - 08:30 : Model Registry Benchmarks & Hot-Switching                   |
| 08:30 - 10:00 : Q&A & Technical Defense                                     |
+-----------------------------------------------------------------------------+
```

---

### Act 1: Introduction & Architecture (00:00 - 01:30)

#### What to Show:
- Browser on `http://localhost:8000/` (Dashboard in Replay Mode, zeroed out).

#### What to Say:
> *"Good morning/afternoon. Today I am presenting **AegisNIDS**, a real-time Security Operations Center (SOC) intelligence engine and Network Intrusion Detection System built from the ground up.*
>
> *Traditional NIDS rely on static signatures or heavy black-box deep learning models that lack operational explainability and can't be easily audited by SOC analysts. AegisNIDS solves this by pairing high-performance tabular ML models (trained on CICIDS2017) with **real-time packet-to-flow aggregation**, **sub-millisecond Tree SHAP explainability**, and a **closed-loop analyst triage feedback workflow** designed for continuous model retraining."*

---

### Act 2: Centerpiece — The 3-Window Live Scan Correlation (01:30 - 04:00)

#### What to Click / Type:
1. On the Dashboard: Under **ADAPTER**, select your active physical adapter (`Wi-Fi (192.168.1.x)`) or `Software Loopback (127.0.0.1)`.
2. Click **▶ START LIVE CAPTURE**.
3. Point out the top header badge switching from blue `REPLAY MODE` to pulsing red `LIVE CAPTURE — Wi-Fi`, and packet counters ticking up.
4. In the Admin Terminal, run the real stealth SYN scan targeting the local gateway router:
   ```powershell
   .\tools\nmap-7.92\nmap.exe -sS 192.168.1.1 -p 21,22,23,53,80,443,8080,8443
   ```

#### What to Say:
> *"Let's demonstrate live detection. I've engaged the live Layer-2 packet sniffer on our physical Wi-Fi adapter. The system extracts 77 bidirectional network flow features per TCP/UDP session in real time.*
>
> *Now, from an attacker terminal, I am launching an actual Nmap stealth SYN scan against our local network gateway on ports 21, 22, 80, 443, and 8080.*
>
> *[Nmap finishes in ~0.4s]*
>
> *Watch the dashboard in real time: Every probe packet was grouped into a bidirectional flow, evaluated through our active ML model, and classified as a PortScan with >99% confidence. The Alert Feed instantly populated the corresponding security incidents, complete with source IP, destination port, and severity mapping."*

---

### Act 3: Explainability — SHAP & Plain-Language Explanations (04:00 - 05:30)

#### What to Click:
1. Point to the **Real-Time Tree SHAP Attributions** card on the right.
2. Highlight the **AI Alert Explanation** box and the feature importance bar charts.

#### What to Say:
> *"A critical problem in cybersecurity is alert fatigue — analysts receive alerts but don't know why a black-box model fired. In AegisNIDS, every alert is accompanied by two layers of explainability:*
>
> *1. **Tree SHAP Attributions**: Exact mathematical game-theoretic feature contributions showing the exact network parameters (such as backward packet counts, initial window bytes, and inter-arrival times) that drove the classification.*
>
> *2. **Plain-Language Alert Explanations**: A deterministic, rule-based reasoning engine that translates those mathematical SHAP attributions into a single clear sentence: 'Flagged as PortScan due to sequential port probing with minimal payload and short-lived connections.' No hallucinating LLMs or secondary ML calls are required for this translation."*

---

### Act 4: Analyst Triage Workflow & Continuous Retraining (05:30 - 07:00)

#### What to Click:
1. In the **Live Security Incident & Alert Stream** table, click **ACK** on the first alert.
   - Point out status badge changes to blue `ACK`.
2. Click **ESC** on the second alert.
   - Point out status badge changes to purple `ESC`.
3. Click **FP** on the third alert:
   - The gold-bordered **Mark as False Positive** modal opens.
   - Explain the form: original detection (`PortScan`), corrected classification (`Benign`), and analyst justification notes.
   - Type note: *"Authorized network scan by security auditor"* and click **Confirm False Positive & Log Feedback**.
4. Point to the top metric card: **Analyst-Verified Precision** has updated live to **`66.7%`** (2 confirmed out of 3 triaged).
5. Point to **Active Security Alerts**: It decremented by 1 because false positives are excluded from active threat statistics.

#### What to Say:
> *"Security operations require rigorous alert triage. Our dashboard provides a 5-state state machine: `NEW`, `ACKNOWLEDGED`, `FALSE_POSITIVE`, `ESCALATED`, and `RESOLVED`.*
>
> *When an analyst flags an alert as a `FALSE_POSITIVE`, two critical things happen automatically:*
> *First, the alert is removed from active threat metrics, and our **Analyst-Verified Precision** metric immediately recalculates in real time — showing 66.7%.*
> *Second, the full 77-feature vector, original classification, corrected label, and analyst notes are persisted into the `analyst_feedback` database table. This creates a curated, high-value dataset for active learning and future model retraining loops.*
>
> *Furthermore, repeat triggers for that exact false-positive signature are automatically suppressed during the session to prevent feed flooding."*

---

### Act 5: Model Registry Benchmark & Dynamic Switcher (07:00 - 08:30)

#### What to Click:
1. Scroll down to the **Registered Models Benchmark & Dynamic Switcher** card.
2. Point out the dataset benchmark indicators: `● CICIDS2017 (Active — 7 Models)`, `○ NSL-KDD (Not yet implemented)`, `○ UNSW-NB15 (Not yet implemented)`.
3. Click **ACTIVATE MODEL** on `XGBoost Classifier`.
4. Point out the top **Active ML Model** card immediately reflects `xgboost`.
5. Click **ACTIVATE MODEL** back on `Weighted Voting Ensemble`.

#### What to Say:
> *"AegisNIDS includes a modular model registry with 7 benchmarked architectures trained across tree-based, deep learning, and tabular attention frameworks — including XGBoost, LightGBM, HistGradientBoosting, MLP Neural Networks, PyTorch TabNet, and FT-Transformers.*
>
> *Our default production champion is the **Weighted Voting Ensemble**, combining our top gradient-boosted trees with soft-voting weights `[0.45, 0.35, 0.20]` to achieve 99.84% F1-score.*
>
> *Analysts can hot-switch the active inference engine with zero downtime via our REST API. We've also scaffolded multi-dataset expansion for NSL-KDD and UNSW-NB15 as part of our future roadmap."*

---

## 3. Fallback Plan (If Live Capture / Driver Fails Live)

If Npcap driver permissions fail or live sniffing is interrupted on the host:

1. **Seamless Switch to Replay / Test Mode**:
   - The dashboard gracefully stays in **REPLAY MODE** with a clear notification toast.
   - Run the pre-scripted multi-attack replayer script in a terminal:
     ```powershell
     python .\test_dashboard_live.py
     ```
   - Or send individual synthesized attack profiles via curl/python:
     ```powershell
     python .\scratch\seed_data.py
     ```
2. **Talking Point**:
   > *"AegisNIDS is dual-mode by design: It seamlessly ingests live Layer-2 physical packet captures when driver access is available, and operates in deterministic high-throughput PCAP/flow replay mode for automated pipeline verification and training validation."*

---

## 4. Anticipated Questions & Honest Technical Answers

Be completely transparent and confident with these prepared answers:

---

### Q1: *"Why did Nmap self-scan (`127.0.0.1` / self-IP) not show up on the physical Wi-Fi card?"*
> **Answer**:
> *"On Windows, the TCP/IP kernel stack routes self-targeted packets internally via the virtual loopback adapter (`\Device\NPF_Loopback`) before they ever touch the physical Wi-Fi hardware ring buffer (`\Device\NPF_{GUID}`). When scanning external or LAN destinations like the default gateway (`192.168.1.1`), the frames physically transit the Wi-Fi card and are 100% captured and classified by our Npcap sniffer."*

---

### Q2: *"Is your ensemble a true Stacking meta-classifier or a Weighted Voting ensemble?"*
> **Answer**:
> *"In our initial prototype, we implemented a calibrated **weighted soft-voting probability blender** (`[0.45, 0.35, 0.20]` over XGBoost, LightGBM, and HistGradientBoosting) which yields 99.84% F1-score with sub-millisecond latency. Training a second-stage meta-classifier (e.g. Ridge regression or Logistic Regression over cross-validated out-of-fold predictions) is documented in our `FUTURE_WORK.md` roadmap as Phase 2."*

---

### Q3: *"Where is the Backdoor / Trojan Trigger detector?"*
> **Answer**:
> *"Backdoor and trojan trigger detection was scoped as an architectural design in `FUTURE_WORK.md` rather than active detection code, because the CICIDS2017 dataset does not contain poisoned model weights or trigger-embedded traffic (e.g. stealth TCP window-size watermarks). The model registry schema was designed modularly so a dedicated backdoor anomaly detector can be registered as soon as a poisoned dataset is synthesized."*

---

### Q4: *"How does the model handle rare attack classes or domain shift (generalization gap)?"*
> **Answer**:
> *"In CICIDS2017, certain classes like Heartbleed and Infiltration have very few sample flows (under 50), leading to higher variance compared to volumetric attacks like DDoS or PortScan. This is precisely why we built the **Analyst Triage Feedback Table (`analyst_feedback`)**: It captures human corrections and full 77-feature vectors on false positives so that active learning can iteratively rebalance rare-class decision boundaries."*

---

### Q5: *"Are the plain-language explanations generated by an LLM?"*
> **Answer**:
> *"No, by design. We intentionally avoided calling an LLM in the critical alert pipeline to eliminate latency, cost, and hallucination risks. Instead, we use a deterministic templating engine that pairs the top 2 mathematical Tree SHAP features with attack-specific behavioral signatures."*

---

### Q6: *"How does the system distinguish modern bursty web traffic (CDNs, ads, HTTP/2 multiplexing) from actual DDoS or PortScan attacks?"*
> **Answer**:
> *"CICIDS2017 was synthesized in 2017 with simulated traffic generators where multi-connection web bursts were less prevalent than in modern web browsing. In modern traffic, browsers open multiple parallel TLS sessions across diverse CDNs. Our system prevents false alarms by coupling our **Weighted Voting Ensemble** (which correctly evaluates established bidirectional flows with payload as Benign with >99% confidence) with a host-paired probe counter that requires rapid unacknowledged half-open SYN probes across 6+ ports on a single target before triggering a scan incident."*

---
