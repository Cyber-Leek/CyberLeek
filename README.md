# 🛡️ Adaptive AI Network Security Analyst
### Explainable Network Intrusion Detection System (X-NIDS)

An AI-powered and explainable Network Intrusion Detection System designed to detect suspicious network activity, store security incidents, and provide human-readable explanations for detected threats.

---

## 📌 Problem Statement

Modern computer networks generate a massive amount of network traffic every second. Detecting malicious activity within this traffic is difficult because traditional security systems often produce a large number of alerts without clearly explaining why an alert was generated.

Many machine-learning-based Intrusion Detection Systems can classify network traffic as benign or malicious, but their predictions can be difficult for security analysts to understand.

This creates several challenges:

- Large volumes of network traffic must be analyzed.
- Security teams need to identify malicious traffic quickly.
- Machine-learning predictions may not be easily understandable.
- Analysts need evidence behind security alerts.
- False positives can waste valuable investigation time.
- Security incidents need to be stored and tracked.
- Analysts should be able to provide feedback on detected incidents.

### 🎯 Objective

The objective of this project is to develop an **Explainable Network Intrusion Detection System** that combines machine learning, backend services, an investigation layer, and an interactive dashboard.

The system should not only detect suspicious network activity but also provide understandable information about the prediction and the important network features associated with it.

---

# 💡 Proposed Solution

We developed an **Adaptive AI Network Security Analyst** consisting of:

1. Machine Learning-based network traffic classification
2. Explainable prediction results
3. FastAPI backend
4. Incident database
5. AI investigation layer
6. Security knowledge base
7. Analyst feedback mechanism
8. Interactive Streamlit dashboard

The system uses a Random Forest model to classify network flows as:

- `BENIGN`
- `ATTACK`

For detected incidents, the backend stores:

- Prediction
- Confidence
- Attack type
- Risk level
- Evidence
- Explanation
- Analyst feedback

---

# 🏗️ System Architecture

```text
                    Network Traffic
                          │
                          ▼
                ┌───────────────────┐
                │   Network Flow    │
                │      Dataset      │
                └─────────┬─────────┘
                          │
                          ▼
                ┌───────────────────┐
                │   Random Forest   │
                │    ML Model       │
                └─────────┬─────────┘
                          │
                    Prediction
                  BENIGN / ATTACK
                          │
                          ▼
                ┌───────────────────┐
                │     FastAPI       │
                │     Backend       │
                └─────────┬─────────┘
                          │
             ┌────────────┼────────────┐
             │            │            │
             ▼            ▼            ▼
        ┌─────────┐  ┌──────────┐  ┌───────────┐
        │ SQLite  │  │    AI    │  │ Knowledge │
        │Database │  │Investigation│ │   Base   │
        └─────────┘  └─────┬────┘  └───────────┘
                           │
                           ▼
                    Explanation
                           │
                           ▼
                ┌───────────────────┐
                │ Streamlit         │
                │ Security          │
                │ Dashboard         │
                └─────────┬─────────┘
                          │
                          ▼
                    Security Analyst
