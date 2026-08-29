# AegisNIDS: Architectural Scope & Future Work Roadmap

This document outlines intentional architectural scope decisions and the technical roadmap for features planned for future release phases.

---

## 1. Backdoor & Trojan Trigger Detection
* **Current Scope Decision**: Backdoor/trojan detection was scoped for this system but **not implemented** in the active detection pipeline — no backdoor-attack training data or poisoned model weights were available in the initial dataset.
* **Planned Approach**: 
  1. Synthesize and source a poisoned-model/trojaned-flow dataset (e.g., embedding stealth watermark triggers in TCP window sizes and packet timing intervals).
  2. Train a dedicated binary classifier / anomaly detector to identify trigger activations.
  3. Integrate the detector via the same modular `ModelRegistry` schema used for the baseline CICIDS2017 models.

---

## 2. Multi-Dataset Support (NSL-KDD & UNSW-NB15)
* **Current Scope Decision**: Directory scaffolding (`models/nsl_kdd/`, `models/unsw_nb15/`) has been created to support multi-dataset expansion, but no trained model weights or feature schemas have been loaded yet.
* **Planned Approach**:
  1. Ingest NSL-KDD (41 features) and UNSW-NB15 (49 features) datasets.
  2. Train baseline models (XGBoost, LightGBM, Neural Networks) on each dataset.
  3. Register dedicated `model_card.json` artifacts per dataset and enable multi-dataset selection in the SOC Dashboard.

---

## 3. Stacking Ensemble Meta-Learner Training
* **Current Scope Decision**: The current Stacking Ensemble ([`IDSStackingEnsemble`](file:///c:/Users/Swayam%20Rangoonwala/Desktop/cicids/services/inference/ensemble.py)) operates as a weighted soft-voting probability blender (`[0.45, 0.35, 0.20]` over XGBoost, LightGBM, and HistGradientBoosting).
* **Planned Approach**:
  1. Re-export the complete, uncorrupted `X_train.pkl` and `X_test.pkl` matrices from the source raw parquets.
  2. Generate out-of-fold cross-validation probability features from the base models.
  3. Fit a calibrated meta-learner (e.g. Ridge Classifier or Shallow MLP) and compute measured empirical held-out test metrics.

---

## 4. Containerized Environment Testing
* **Current Scope Decision**: Production-ready [`Dockerfile`](file:///c:/Users/Swayam%20Rangoonwala/Desktop/cicids/Dockerfile) and [`docker-compose.yml`](file:///c:/Users/Swayam%20Rangoonwala/Desktop/cicids/docker-compose.yml) configurations have been authored and verified for syntax. Live container execution is pending a Docker-enabled host environment.
* **Planned Approach**: Verify `docker compose up --build` on a staging environment with Docker Engine / Docker Desktop installed.
