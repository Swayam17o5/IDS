# AegisNIDS: Real-Time SOC Intelligence Engine & Network Intrusion Detection System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**AegisNIDS** is an end-to-end, machine learning-powered Security Operations Center (SOC) intelligence engine and Network Intrusion Detection System. It bridges high-performance tabular ML classification (trained on the CICIDS2017 dataset) with real-time Layer-2 packet-to-flow feature extraction, sub-millisecond Tree SHAP explainability, plain-language AI alert summaries, and a closed-loop analyst triage feedback workflow.

---

## 🔑 Key Features

- **Multi-Model Machine Learning Suite**: Supports 7 pre-trained intrusion detection models:
  - Stacking Ensemble (`IDSStackingEnsemble`)
  - Random Forest, XGBoost, LightGBM, Extra Trees
  - Multi-Layer Perceptron (MLP)
  - Deep Learning Tabular Models: TabNet & FT-Transformer (`rtdl`)
- **Real-Time Packet Capture & Flow Aggregation**: Live Layer-2 packet sniffing via Scapy and Npcap/libpcap with 77 bidirectional network flow feature extractions.
- **Tree SHAP & Plain-Language Explainability**: Instant game-theoretic feature attribution and rule-based natural language explanations for every detected security incident.
- **Analyst Triage & Feedback Loop**: Dynamic alert triage (`NEW`, `ACKNOWLEDGED`, `FALSE_POSITIVE`, `ESCALATED`, `RESOLVED`) with real-time Analyst-Verified Precision tracking and session-level false-positive pattern suppression.
- **Interactive Modern SOC Dashboard**: Built-in real-time telemetry dashboard with live chart metrics, model hot-switching, and database reset capabilities.

---

## ⚡ Quick Start Guide

For full detailed setup, troubleshooting, and operating modes, see **[HOW_TO_RUN.md](file:///c:/Users/Swayam%20Rangoonwala/Desktop/cicids/HOW_TO_RUN.md)**.

### 1. Prerequisites
- Python 3.10+
- [Npcap](https://npcap.com/) (Required for live packet sniffing on Windows)

### 2. Installation
```powershell
# Clone / navigate to project repository
cd "c:\Users\Swayam Rangoonwala\Desktop\cicids"

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1   # On Windows
# source venv/bin/activate    # On Linux/macOS

# Install required dependencies
pip install -r requirements.txt
```

### 3. Run the Server
```powershell
python -m uvicorn services.inference.app:app --host 0.0.0.0 --port 8000
```

### 4. Access Web UI
- Open browser to **[http://localhost:8000/](http://localhost:8000/)**
- Swagger API documentation: **[http://localhost:8000/docs](http://localhost:8000/docs)**

---

## 🐳 Docker Deployment

```bash
# Start container stack via Docker Compose
docker-compose up --build
```

---

## 🧪 Running Automated Tests

```powershell
# Run all unit and integration tests
pytest

# Run diagnostics suite across all models
python run_diagnostics.py
```

---

## 📁 Repository Structure

```
cicids/
├── services/
│   ├── alert_engine/         # Alert generation, deduplication & FP suppression
│   ├── feature_extractor/    # Live Scapy packet capture & 77 flow feature extraction
│   ├── inference/            # FastAPI app, model loader, Tree SHAP explainer & ensemble
│   └── registry/             # Model Registry for benchmark tracking & hot-switching
├── database/                 # SQLite database ORM models & session management
├── models/                   # Serialized model artifacts (.pkl, .pth, .zip)
├── tests/                    # Unit and integration pytest suite
├── tools/                    # Portable Nmap binaries & diagnostic scripts
├── docker-compose.yml        # Docker composition setup
├── Dockerfile                # Backend containerization file
├── requirements.txt          # Python dependency specifications
├── HOW_TO_RUN.md             # Complete step-by-step operational guide
└── README.md                 # Project overview and quick start guide
```

---

## 📄 License
This project is licensed under the MIT License.
