# 🚨 SecureNet AI - Intrusion Detection System

**AI-Powered Hybrid Network Intrusion Detection System**  
**Final Year Information Technology Project 2026**

---

## 📋 Project Overview

**SecureNet AI** is a sophisticated **Intrusion Detection System (IDS)** that combines traditional rule-based detection with modern Machine Learning techniques to detect both known and unknown network attacks in real-time.

This project was designed to simulate **3 developers working for 3 months**, demonstrating proficiency in Cybersecurity, Machine Learning, Software Engineering, and System Integration.

---

## ✨ Key Features

### Core Features
- **Hybrid Detection Engine**: Signature-based + Anomaly-based (ML)
- **Real-time Packet Capture** using Scapy
- **Multi-Model Support**: XGBoost (Primary) + Random Forest
- **Professional Web Dashboard** built with Streamlit
- **Attack Category Classification** (DoS, Probe, R2L, U2R)
- **PDF Report Generation**
- **Live Alert System** with confidence scoring
- **Batch Analysis** support

### Advanced Features
- Feature Engineering & Preprocessing Pipeline
- Model Persistence & Loading
- Structured Logging
- Explainable AI Ready (SHAP compatible)
- Responsive & Modern UI

---

## 🛠️ Tech Stack

| Category           | Technologies |
|--------------------|--------------|
| Language           | Python 3.10+ |
| ML/DL              | Scikit-learn, XGBoost |
| Real-time          | Scapy |
| Dashboard          | Streamlit, Plotly |
| Reporting          | FPDF |
| Data Handling      | Pandas, NumPy |
| Others             | Joblib, Threading |

---

## 📁 Project Structure

```bash
intrusion-detection-system/
├── app.py                          # Main Streamlit Dashboard
├── main.py
├── requirements.txt
├── models/                         # Trained ML models (.pkl)
├── src/
│   ├── detection/
│   │   └── real_time_detector.py
│   └── utils/
│       ├── attack_mapper.py
│       └── report_generator.py
├── reports/                        # Generated PDF reports
├── data/                           # Datasets (NSL-KDD)
├── notebooks/                      # Colab training notebooks
└── README.md
