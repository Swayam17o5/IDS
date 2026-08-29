# How to Run AegisNIDS

**AegisNIDS** is a real-time Security Operations Center (SOC) intelligence engine and Network Intrusion Detection System powered by machine learning (trained on CICIDS2017), featuring real-time packet-to-flow feature extraction, Tree SHAP explainability, and analyst triage feedback loops.

---

## 📋 Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Environment Setup](#2-environment-setup)
3. [Running the Backend & Web Dashboard](#3-running-the-backend--web-dashboard)
4. [Modes of Operation](#4-modes-of-operation)
   - [Replay / Simulation Mode](#mode-a-replay--simulation-mode)
   - [Live Packet Capture Mode](#mode-b-live-packet-capture-mode-admin-required)
5. [Running via Docker](#5-running-via-docker)
6. [Testing & Verification](#6-testing--verification)
7. [API Documentation](#7-api-documentation)
8. [Troubleshooting & FAQ](#8-troubleshooting--faq)

---

## 1. Prerequisites

Before running AegisNIDS, ensure you have the following installed:

- **Python 3.10+** (Python 3.9 - 3.11 supported)
- **Pip & virtualenv**
- **Npcap** (Windows) or **libpcap** (Linux / macOS): Required ONLY if running live packet capture. Download Npcap from [npcap.com](https://npcap.com/) with WinPcap compatibility enabled.
- **Docker & Docker Compose** (Optional, for containerized execution)
- **Nmap** (Optional, for generating test security scanning traffic)

---

## 2. Environment Setup

### Step 1: Clone / Navigate to Project Directory
```powershell
cd "c:\Users\Swayam Rangoonwala\Desktop\cicids"
```

### Step 2: Create & Activate Virtual Environment
- **Windows (PowerShell)**:
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS**:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 3. Running the Backend & Web Dashboard

Launch the FastAPI application server using Uvicorn:

```powershell
python -m uvicorn services.inference.app:app --host 0.0.0.0 --port 8000
```

or with auto-reload enabled during development:

```powershell
uvicorn services.inference.app:app --reload --host 0.0.0.0 --port 8000
```

### Accessing the Web Dashboard
Once launched, open your web browser and navigate to:
- **SOC Dashboard UI**: [http://localhost:8000/](http://localhost:8000/)
- **Interactive OpenAPI (Swagger) Specs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)

---

## 4. Modes of Operation

AegisNIDS supports two operating modes depending on your environment and permissions:

### Mode A: Replay / Simulation Mode

*Does not require administrative privileges.*

1. **Dashboard Simulation**:
   - Open the dashboard at `http://localhost:8000/`.
   - Ensure the header badge shows **`REPLAY MODE`** (Blue badge).
   - Use the UI buttons or API endpoints to stream synthetic traffic or model predictions.

2. **Replaying PCAP Files**:
   Execute the included PCAP replay utility script:
   ```powershell
   python replay_pcap.py
   ```

3. **Running Model Diagnostics**:
   Test model inference across all 7 supported architectures:
   ```powershell
   python run_diagnostics.py
   ```

---

### Mode B: Live Packet Capture Mode (Admin Required)

*Requires Windows Npcap / Linux libpcap driver and elevated shell permissions.*

1. **Launch PowerShell as Administrator**:
   - Right-click PowerShell and select **Run as Administrator**.
   - Activate your virtual environment and start the server:
     ```powershell
     python -m uvicorn services.inference.app:app --host 0.0.0.0 --port 8000
     ```

2. **Select Adapter & Start Live Sniffing**:
   - Open `http://localhost:8000/`.
   - In the top control bar under **ADAPTER**, select your active interface (e.g. `Wi-Fi` or `Software Loopback`).
   - Click **▶ START LIVE CAPTURE**.
   - Verify header badge turns to pulsing **`LIVE CAPTURE`** (Red badge).

3. **Generating Live Test Attacks (Nmap)**:
   Launch a stealth SYN port scan using the built-in Nmap binary or local Nmap installation:
   ```powershell
   .\tools\nmap-7.92\nmap.exe -sS 192.168.1.1 -p 21,22,23,53,80,443,8080,8443
   ```
   The live alert feed on the dashboard will immediately populate detected `PortScan` security incidents with SHAP feature attributions and natural-language explanations.

---

## 5. Running via Docker

You can run AegisNIDS inside a Docker container using the provided `docker-compose.yml`:

```bash
# Build and run container in foreground
docker-compose up --build

# Run in background (detached)
docker-compose up -d
```

To stop the container:
```bash
docker-compose down
```

---

## 6. Testing & Verification

Run the automated test suite and live verification scripts to confirm system health:

### Automated Pytest Suite
```powershell
pytest
```
or specifically:
```powershell
python -m pytest tests/
```

### Live Component Tests
```powershell
# Test live inference pipeline
python test_inference_service_live.py

# Test alert engine and triage feedback
python test_alert_engine_live.py

# Test dashboard end-to-end integration
python test_dashboard_live.py
```

---

## 7. API Documentation

Key available REST API endpoints:

| Endpoint | Method | Description |
|:---|:---:|:---|
| `/` | `GET` | Main SOC Dashboard HTML Web UI |
| `/health` | `GET` | Health check endpoint |
| `/api/predict` | `POST` | Perform inference on a raw network flow feature vector |
| `/api/models` | `GET` | List available models in the Model Registry |
| `/api/models/switch` | `POST` | Dynamically hot-switch the active classification model |
| `/api/alerts` | `GET` | Fetch active security alerts stream |
| `/api/triage` | `POST` | Update alert triage status (`ACKNOWLEDGED`, `FALSE_POSITIVE`, `RESOLVED`, `ESCALATED`) |
| `/api/stats` | `GET` | Retrieve real-time SOC metrics and analyst-verified precision |
| `/api/capture/start` | `POST` | Start live packet capture on selected network adapter |
| `/api/capture/stop` | `POST` | Stop live packet capture |
| `/api/reset` | `POST` | Reset all active flow, alert, and analyst feedback database records |

Full OpenAPI specification is available interactively at `http://localhost:8000/docs`.

---

## 8. Troubleshooting & FAQ

- **Issue: Npcap / Packet Sniffing Error on Live Capture Start**
  - *Cause*: Missing Npcap driver or un-elevated shell permissions.
  - *Fix*: Install Npcap from [npcap.com](https://npcap.com/) with WinPcap API compatibility. Ensure Uvicorn is executed from an Administrator command prompt. The dashboard gracefully falls back to Replay Mode if live capture is unavailable.

- **Issue: Database locked error (`nids.db`)**
  - *Cause*: Concurrent SQLite writes during rapid traffic ingestion.
  - *Fix*: SQLite write-ahead logging (WAL mode) is enabled automatically by `database/db.py`. Click **RESET SOC DATA** or restart the backend server if locks persist.

- **Issue: Port 8000 already in use**
  - *Fix*: Specify a different port when running Uvicorn:
    ```powershell
    python -m uvicorn services.inference.app:app --host 0.0.0.0 --port 8080
    ```
