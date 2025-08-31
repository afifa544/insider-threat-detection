# Insider Threat Detection System

A machine learning system to detect potential insider threats using behavioral analytics.

## Features
- Real-time user behavior monitoring
- Anomaly detection using machine learning
- Interactive Streamlit dashboard
- Risk scoring (0-1 probability)
- Automatic alert system
- Tor network usage detection

## Technologies Used
- Python
- Scikit-Learn
- Streamlit
- Pandas & NumPy
- Matplotlib/Seaborn

## Installation
```bash
pip install -r requirements.txt
streamlit run dashboard/lightweight_app.py
#PROJECT STRUCTURE
insider-threat-detection/
├── dashboard/
│   ├── lightweight_app.py
│   └── email_alerts.py
├── data/
├── src/
│   └── advanced_models.py
├── requirements.txt
├── create_json.py
└── README.md
