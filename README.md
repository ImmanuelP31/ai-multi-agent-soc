# AI Multi-Agent SOC (Security Operations Center) Dashboard

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Dashboard-61DAFB?style=for-the-badge&logo=react&logoColor=0B1020)
![Kafka](https://img.shields.io/badge/Kafka-Streaming-231F20?style=for-the-badge&logo=apachekafka&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Persistence-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)

An end-to-end autonomous Security Operations Center built with real-time event streaming, AI-powered detection, multi-agent investigation, remediation workflows, and a polished live analyst dashboard.

![AI Multi-Agent SOC Dashboard demo](docs/assets/soc-dashboard-demo.gif)

## Why This Project Stands Out

This project simulates a modern AI-assisted SOC pipeline where multiple agents collaborate over Kafka to detect, enrich, investigate, remediate, and report security incidents in real time.

It is designed to demonstrate production-oriented engineering skills across distributed systems, ML integration, backend APIs, Dockerized infrastructure, and frontend observability.

## Core Capabilities

- Real-time security event pipeline using Kafka topics.
- FastAPI backend with REST endpoints and WebSocket streaming.
- PostgreSQL persistence for alert history and dashboard analytics.
- Redis pub/sub bridge for live SOC feed updates.
- Multi-agent workflow for detection, investigation, threat intelligence, remediation, and reporting.
- ML-based anomaly and intrusion detection components.
- LSTM-style sequence prediction surface for next-attack forecasting.
- React dashboard with live stats, severity chart, alert table, predictions, and threat feed.
- Fully Dockerized infrastructure for repeatable local runs.

## System Architecture

```text
Attack Simulator
      |
      v
Kafka: soc_logs (keyed by source_ip)
      |
      v
Detection Agent
      |
      v
Kafka: soc_alerts
      |
      v
Investigation Agent -> Redis sequence window -> Kafka: investigated_alerts
      |
      v
Threat Intel Agent -> Kafka: threat_enriched_alerts
      |
      v
Remediation Agent -> Kafka: remediation_actions
      |
      +--> Reporting Agent
      +--> PostgreSQL (one progressively enriched row)
      +--> Redis pub/sub -> FastAPI WebSocket -> React Dashboard
```

Every message uses the canonical Pydantic contract in `common/events.py`.
The simulator creates `event_id` and `incident_id` once; every downstream
agent validates and preserves both values. Messages are keyed by `source_ip`
(falling back to `incident_id`) and each agent uses its own stable consumer
group with manual offset commits. An offset is committed only after the
database upsert, required local output, and downstream Kafka publication
succeed.

PostgreSQL enforces a unique index on `event_id`. Detection, investigation,
threat intelligence, remediation, and reporting update that same incident row
with nested metadata and the current processing stage, so Kafka retries enrich
the existing incident instead of inserting duplicates.

The active topic chain is `soc_logs` (`soc-detection`), `soc_alerts`
(`soc-investigation`), `investigated_alerts` (`soc-threat-intel`),
`threat_enriched_alerts` (`soc-remediation`), and `remediation_actions`
(`soc-reporting`). Sequence prediction exists only inside Investigation; there
is no second sequence consumer or parallel prediction topic.

## Tech Stack

| Layer | Tools |
| --- | --- |
| Frontend | React, Vite, Tailwind CSS, Recharts, Framer Motion |
| Backend | FastAPI, SQLAlchemy, WebSockets |
| Streaming | Apache Kafka, Zookeeper |
| Realtime | Redis pub/sub and durable sequence windows |
| Database | PostgreSQL |
| ML | scikit-learn, TensorFlow, NumPy, Pandas |
| DevOps | Docker, Docker Compose |

## Repository Layout

```text
ai-multi-agent-soc/
├── agents/                 # Detection, investigation, intel, remediation, reporting agents
├── alembic/                # Versioned PostgreSQL schema migrations
├── backend/                # FastAPI app, canonical incident model, API and WebSocket stream
├── common/                 # Canonical event contract and replay-safe Kafka helpers
├── frontend/               # React SOC dashboard
├── kafka/                  # Kafka producer and consumer helpers
├── ml/                     # Training and sequence detection workflows
├── scripts/                # Attack simulator and operational scripts
├── docker-compose.yml      # Full local infrastructure
├── Dockerfile              # Backend and agent runtime image
└── README.md
```

## Quick Start

### 1. Clone and enter the repo

```bash
git clone https://github.com/ImmanuelP31/ai-multi-agent-soc.git
cd ai-multi-agent-soc
```

### 2. Start the SOC infrastructure

```bash
docker compose up -d --build
```

This starts PostgreSQL, runs `alembic upgrade head`, and then starts Redis,
Zookeeper, Kafka, the FastAPI backend, and all SOC agents. Backend and agent
containers start only after the migration succeeds.

Check service status:

```bash
docker compose ps
```

### 3. Verify the backend

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/alerts/stats
```

Backend URL:

```text
http://127.0.0.1:8000
```

### 4. Run the frontend dashboard

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

### 5. Generate simulated attacks

From the repo root:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python scripts/attack_simulator.py
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python scripts\attack_simulator.py
```

## Anomaly Detection Bundle

The Isolation Forest uses one shared feature pipeline in
`ml/features/network_flow.py`. Training and runtime inference use the same ten
ordered network-flow fields, fitted median imputer, and fitted scaler. The
detector reads only numeric `telemetry.flow_features`; simulator attack labels
remain under `ground_truth` and are never model inputs.

Train and evaluate the complete bundle:

```bash
docker compose build detection-agent
docker compose run --rm --no-deps detection-agent python ml/training/train_anomaly_model.py
docker compose run --rm --no-deps detection-agent python ml/training/evaluate_anomaly_model.py
docker compose up -d detection-agent
```

Training writes `ml/models/anomaly_bundle.joblib`, containing the model,
imputer, scaler, feature order, version metadata, and decision-function
thresholds. Evaluation writes `ml/models/anomaly_evaluation.json` with
precision, recall, F1, confusion matrix, false-positive rate, false-negative
rate, and detection rate.

Compose configures `DETECTION_MODE=ml`, which fails clearly when the bundle is
missing or incompatible. An explicit telemetry-only fallback can be selected
with `DETECTION_MODE=rule_based`; alerts then report
`detection_method: rule_based_fallback` and `model_status: explicit_fallback`.

## LSTM Prediction Notes

The sequence experiment uses the same ten numeric CICIDS flow fields at
training and runtime. Attack labels, severity, label frequency, and synthetic
repeat-offender flags are not model inputs. Labels are used only as the next
event target and as historical context for the comparison-only Markov baseline.

Source CSV files are assigned to train, validation, or test before sliding
windows are created. Within each file, windows are built separately for a real
source/session column when available; otherwise the source file is the explicit
chronological boundary. No window crosses an entity or split boundary, and the
imputer and scaler are fitted on training groups only.

The previous 85.07% result is invalidated because it used label-derived
features and randomly split overlapping windows. A replacement score is only
recorded after evaluation on untouched source groups. Evaluation includes
accuracy, macro and weighted F1, top-3 accuracy, per-class metrics/support, and
a confusion matrix for both the LSTM and first-order Markov baseline.

To enable the real LSTM path:

```bash
python ml/sequence_detection/generate_rich_sequences.py
python ml/sequence_detection/train_lstm_model.py
python ml/sequence_detection/test_lstm_model.py
docker compose up -d --build investigation-agent
```

Training writes `sequence_dataset.npz`, `sequence_preprocessor.joblib`,
`sequence_model.keras`, and machine-readable `sequence_evaluation.json` beside
the versioned metadata. These generated artifacts are intentionally ignored by
Git. When the compatible model and preprocessor are loaded, predictions begin
after five telemetry events from the same source. If either artifact is absent
or retraining is required, no rule-based next-attack prediction is substituted;
alerts show `investigation_method: lstm_sequence_model_unavailable` and include
the exact `lstm_status`.

At runtime, Investigation stores each source identity in a separate bounded
Redis list named `soc:sequence:<source-ip>`. Lists retain at most the configured
sequence length and default to a one-hour TTL. State therefore survives agent
restarts without allowing two source IPs to share a window. Redis failure stops
processing and leaves the Kafka offset uncommitted for retry; it never falls
back to an incomplete in-memory sequence. Successful predictions persist the
top classes, primary confidence, sequence length, model version, and prediction
timestamp in the alert's investigation metadata.

## Dashboard Features

- Total alert, critical threat, and malware counters.
- Severity distribution chart powered by backend analytics.
- Live security alert table backed by PostgreSQL.
- WebSocket-based threat feed powered by Redis pub/sub.
- AI attack prediction panel for sequence-model outputs.
- Responsive dark SOC interface built for quick analyst scanning.

## API Surface

| Endpoint | Purpose |
| --- | --- |
| `GET /` | Backend status message |
| `GET /health` | Backend and Redis health |
| `GET /alerts/` | Recent persisted SOC alerts |
| `GET /alerts/stats` | Dashboard counters and severity chart data |
| `WS /ws/live-alerts` | Live threat feed stream |

## Development Commands

Apply database migrations without starting the full stack:

```bash
docker compose run --rm migrate
```

For a local Python environment with `DATABASE_URL` configured, the equivalent
commands are:

```bash
alembic upgrade head
alembic current
```

Create schema changes as new Alembic revisions. Runtime services only verify
database connectivity; they do not call `create_all()` or repair tables with
ad-hoc `ALTER TABLE` statements.

Run frontend checks:

```bash
cd frontend
npm run lint
npm run build
```

Run backend syntax checks:

```bash
python -m py_compile backend/main.py backend/database.py backend/routes/alerts.py
```

Run pipeline unit tests:

```bash
python -m unittest discover -s tests -v
```

Follow useful logs:

```bash
docker logs -f ai_soc_backend
docker logs -f ai_soc_detection
docker logs -f ai_soc_remediation
```

Stop everything:

```bash
docker compose down
```

## What This Demonstrates

- Building an event-driven system with multiple independently running workers.
- Designing a backend that serves both REST analytics and WebSocket updates.
- Evolving a replay-safe PostgreSQL incident schema through versioned Alembic migrations.
- Connecting ML-driven detection outputs to a real-time analyst dashboard.
- Packaging a complex system into a repeatable Docker Compose workflow.
- Presenting technical work with a clean, recruiter-friendly frontend experience.

## Author

**Immanuel P**  
B.Tech Computer Science Engineering  
Focused on AI engineering, distributed systems, and cybersecurity automation.
