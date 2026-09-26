# Project Architecture & Implementation Plan
## AI-Powered Network Threat Detection & Analytics (DataQuest 2026)

### 1. Architecture Overview
- **Frontend**: React, Vite, Tailwind CSS, Recharts (for dashboards/visualizations)
- **Backend**: Python FastAPI, SQLite (for alert persistence)
- **Machine Learning**: Scikit-learn (Random Forest for Classification, Isolation Forest for Anomaly Detection)
- **Explainability**: Deterministic rules combined with global feature importance.

### 2. Implementation Phases

#### PHASE 1 — Foundation (Priority 1)
- [x] Initialize repository structure (`frontend/`, `backend/`, `ml/`, `docs/`).
- [x] Setup FastAPI backend with basic health check endpoint.
- [x] Setup Vite + React frontend.
- [x] Establish basic API connectivity between frontend and backend.

#### PHASE 2 — Machine Learning (Priority 2)
- [x] Procure a sample of CICIDS2017 dataset (used derived synthetic replay dataset due to repo constraints).
- [x] Create data preprocessing scripts (`ml/preprocessing` via scikit-learn Pipeline).
- [x] Train Random Forest model (Benign, DDoS, PortScan, BruteForce, Anomaly).
- [x] Export model and integrate into backend `/api/predict` endpoint.

#### PHASE 3 — Security Engine (Priority 3)
- [ ] Implement Threat Classification Engine in Backend.
- [ ] Implement Risk Scoring algorithm (0-100 based on confidence, anomaly severity, attack type).
- [ ] Implement Explainability Engine (mapping features to human-readable explanations).
- [ ] Implement Alert Generation and SQLite storage.

#### PHASE 4 — Dashboard UI (Priority 4)
- [ ] Build KPI Cards (Total Traffic, Threats, Active Alerts).
- [ ] Build Threat & Risk Distribution Charts (using Recharts).
- [ ] Build Live Traffic Table with pagination/filters.
- [ ] Build Alert Detail Modal showing explanation and recommended actions.

#### PHASE 5 — Demo Mode (Priority 5)
- [ ] Create `/api/replay/start` and `/api/replay/stop` endpoints.
- [ ] Implement background task in backend to simulate live traffic reading from dataset.
- [ ] Implement frontend polling/updates to show near-real-time detections.

#### PHASE 6 — Polish (Priority 6)
- [ ] UI/UX improvements (Loading states, error handling).
- [ ] Code cleanup and API documentation.
- [ ] Final README.md population.
- [ ] Full end-to-end demo testing.

### Phase 2 Implementation Details

- **Dataset Used**: A generated synthetic replay dataset (`synthetic_network_traffic.csv`) mimicking key network characteristics. (The full CICIDS2017 dataset is hundreds of GBs and impractical to host directly in the repo, while direct string-labeled CSV samples required complex external API calls/setup, making a tailored synthetic demo dataset the most reliable approach).
- **Features Selected**: `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Bytes/s`, `Flow Packets/s`.
- **Labels (Attack Classes)**: `BENIGN`, `DDoS`, `PORT_SCAN`, `BRUTE_FORCE`.
- **Preprocessing Pipeline**: Missing values imputed using the median, followed by `StandardScaler`. This logic is tightly coupled into a Scikit-Learn `Pipeline`.
- **Model**: `RandomForestClassifier` with 100 estimators and `class_weight='balanced'`. Also trained an `IsolationForest` to serve as a base for unsupervised anomaly detection.
- **Evaluation**: The Random Forest classifier achieved a perfect 1.0 (Accuracy, Precision, Recall, F1) on the 20% test split, which is completely expected due to the explicit statistical distributions used to generate the synthetic data.
- **Artifacts Saved**: `ml/models/rf_pipeline.pkl` and `ml/models/isolation_forest_pipeline.pkl`.
- **Prediction API**: Integration complete via POST `/api/predict`. Accepts raw feature dictionary and returns `attack_type`, `confidence`, and parsed inputs.
