# Autonomous Multi-Agent AI SOC

AI-driven distributed Security Operations Center (SOC) built using:

* Real-time streaming pipelines
* Machine learning-based intrusion detection
* Multi-agent orchestration
* Kafka event processing
* Distributed security workflows
* Cybersecurity traffic analysis

The system simulates a modern SOC architecture where AI models actively analyze network events, classify threats, estimate severity, and coordinate autonomous response agents.

---

# Architecture Overview

```text
                    ┌────────────────────┐
                    │ Attack Simulator   │
                    └─────────┬──────────┘
                              │
                              ▼
                    ┌────────────────────┐
                    │ Kafka: raw_logs    │
                    └─────────┬──────────┘
                              │
                              ▼
                  ┌─────────────────────────┐
                  │ Detection Agent         │
                  │                         │
                  │ - Feature Extraction    │
                  │ - Isolation Forest      │
                  │ - Random Forest/XGB     │
                  │ - Severity Prediction   │
                  └─────────┬──────────────┘
                            │
                            ▼
                 ┌─────────────────────────┐
                 │ Kafka: security_alerts  │
                 └─────────┬──────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌────────────────┐ ┌────────────────┐ ┌────────────────┐
│ Threat Intel   │ │ Remediation    │ │ Reporting      │
│ Agent          │ │ Agent          │ │ Agent          │
└────────────────┘ └────────────────┘ └────────────────┘
```

---

# Core Features

## Real-Time Streaming Infrastructure

* Apache Kafka event streaming
* Distributed event-driven architecture
* Dockerized services
* Redis caching layer
* PostgreSQL persistence
* FastAPI backend

---

## AI-Driven Threat Detection

### 1. Isolation Forest Anomaly Detection

The SOC uses an Isolation Forest model to:

* learn normal traffic behavior
* detect suspicious traffic patterns
* identify anomalous network flows

This enables:

* unknown attack detection
* behavioral anomaly analysis
* unsupervised threat discovery

---

### 2. Intrusion Classification Model

A supervised ML classifier predicts attack categories such as:

* DDoS
* Port Scan
* Brute Force
* Web Attacks
* Infiltration
* Botnet Activity

Model pipeline:

```text
Traffic Features
        ↓
ML Classifier
        ↓
Attack Type Prediction
```

---

### 3. AI-Driven Severity Prediction

Instead of static rules:

```python
if event == "DDoS":
    severity = "HIGH"
```

the system uses:

* anomaly scores
* attack confidence
* traffic patterns
* behavioral indicators

for contextual threat severity estimation.

---

# Dataset

The project uses the CICIDS2017 cybersecurity dataset.

Dataset includes:

* benign traffic
* DDoS attacks
* brute force attacks
* port scans
* infiltration attacks
* botnet activity

Dataset used for:

* anomaly detection training
* intrusion classification
* evaluation pipelines
* real-time inference testing

---

# Machine Learning Pipeline

## Data Processing

* data cleaning
* feature selection
* handling missing values
* scaling and normalization
* train/test splitting

---

## Evaluation Metrics

The project evaluates:

* accuracy
* precision
* recall
* F1 score
* false positive rate
* anomaly detection rate
* confusion matrices

This ensures realistic cybersecurity model evaluation.

---

# Project Structure

```text
ai-multi-agent-soc/
│
├── agents/
│   ├── detection_agent.py
│   ├── threat_intel_agent.py
│   ├── remediation_agent.py
│   └── reporting_agent.py
│
├── backend/
│
├── ml/
│   ├── datasets/
│   ├── models/
│   ├── inference/
│   └── training/
│
├── simulator/
│
├── docker-compose.yml
│
└── README.md
```

---

# Tech Stack

## Infrastructure

* Python
* Docker
* FastAPI
* PostgreSQL
* Redis
* Apache Kafka

---

## AI / Machine Learning

* Scikit-learn
* Isolation Forest
* Random Forest
* XGBoost
* Pandas
* NumPy

---

# Running the Project

## 1. Clone Repository

```bash
git clone https://github.com/ImmanuelP31/ai-multi-agent-soc.git
cd ai-multi-agent-soc
```

---

## 2. Create Virtual Environment

```bash
python -m venv venv
```

Activate:

### Windows

```bash
venv\Scripts\activate
```

### Linux/Mac

```bash
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Start Infrastructure

```bash
docker compose up -d
```

Services:

* Kafka
* PostgreSQL
* Redis
* FastAPI backend

---

## 5. Train ML Models

### Train Anomaly Detection Model

```bash
python ml/training/train_anomaly_model.py
```

### Evaluate Anomaly Model

```bash
python ml/training/evaluate_anomaly_model.py
```

### Train Intrusion Classifier

```bash
python ml/training/train_intrusion_classifier.py
```

---

## 6. Run Multi-Agent SOC System

Open separate terminals:

### Run Attack Simulator

```bash
python simulator/attack_simulator.py
```

### Run Detection Agent

```bash
python agents/detection_agent.py
```

### Run Threat Intelligence Agent

```bash
python agents/threat_intel_agent.py
```

### Run Remediation Agent

```bash
python agents/remediation_agent.py
```

### Run Reporting Agent

```bash
python agents/reporting_agent.py
```

---

# Example AI-Generated Alert

```json
{
  "attack_type": "DDoS",
  "confidence": 0.97,
  "severity": "CRITICAL",
  "anomaly_prediction": -1,
  "source_ip": "192.168.1.25",
  "timestamp": 1747269210
}
```

---

# Current Capabilities

* Real-time event streaming
* Distributed agent communication
* ML-powered anomaly detection
* AI-based intrusion classification
* Threat severity estimation
* Kafka-driven SOC workflows
* Dockerized deployment
* Multi-agent orchestration

---

# Future Improvements

Planned enhancements:

* LSTM-based sequence attack detection
* Behavioral threat analysis
* SIEM integrations
* Live dashboard visualization
* RAG-powered threat intelligence
* Autonomous remediation workflows
* Temporal transformer models
* Advanced threat hunting pipelines

---

# Why This Project Matters

Traditional SOC systems rely heavily on:

* static rules
* manual triage
* signature-based detection

This project explores:

```text
AI-driven autonomous cybersecurity operations
```

where machine learning models actively participate in:

* threat detection
* attack classification
* risk estimation
* distributed response coordination

---

# Author

Immanuel P

B.Tech Computer Science Engineering

Focused on:

* AI Engineering
* Distributed Systems
* Cybersecurity AI
* Real-Time ML Systems
