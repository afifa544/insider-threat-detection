# Insider Threat Detection Dashboard

## 🎯 Features

### 🔍 **Real-time Monitoring**
- Live threat detection and alerting
- Real-time user activity monitoring
- Instant security incident notifications

### 📊 **Advanced Analytics Dashboard**
- Interactive threat visualization
- User behavior analytics
- Risk scoring and heat maps
- Timeline-based threat tracking
- Multi-dimensional data analysis

### 🏢 **Enterprise Integration**
- Active Directory/LDAP user sync
- System monitor (Sysmon) data integration
- Enterprise user management
- Department-level threat analysis

### 🔐 **Security Features**
- Insider threat detection algorithms
- Anomaly detection (UEBA - User Entity Behavior Analytics)
- Data exfiltration monitoring
- Privilege escalation detection
- Suspicious login pattern recognition

### 📈 **Data Processing Pipeline**
- Automated data ingestion from multiple sources
- ETL (Extract, Transform, Load) processing
- Real-time data streaming
- Historical data analysis
- Batch processing capabilities

### 🐳 **Deployment & Infrastructure**
- Docker containerization
- ELK stack integration (Elasticsearch, Logstash, Kibana)
- REST API server
- Scalable microservices architecture

### 📱 **User Interface**
- Modern, responsive dashboard
- Dark/light mode support
- Role-based access control
- Customizable widgets and views
- Exportable reports (PDF, CSV, JSON)

---

## 🚀 How to Run

### **Prerequisites**
```bash
# Python 3.8+
python --version

# Git
git --version

# Recommended: Docker & Docker Compose
docker --version
docker-compose --version
```

### **Option 1: Quick Start (Recommended)**

```bash
# 1. Clone and navigate to project
git clone <repository-url>
cd insider-threat-detection

# 2. Set up Python environment
python -m venv venv

# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
pip install streamlit  # If not in requirements

# 4. Run the dashboard
cd dashboard
streamlit run enhanced_dashboard.py
```

### **Option 2: Using Docker**

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build individually
docker build -t insider-threat-dashboard .
docker run -p 8501:8501 insider-threat-dashboard
```

### **Option 3: Complete Setup with ELK Stack**

```bash
# 1. Start ELK stack
cd elk
docker-compose up -d

# 2. Initialize databases
python simple_db.py
python load_all_data.py

# 3. Start API server (in separate terminal)
python api_server.py

# 4. Run the dashboard (in another terminal)
cd dashboard
streamlit run enhanced_dashboard.py

# 5. Access Kibana (optional)
# Open browser to: http://localhost:5601
```

### **Option 4: Windows Batch File**
```bash
# Simply run:
run.bat
# This will activate venv and start all services
```

---

## 🌐 Access Points

| Service | URL | Port | Purpose |
|---------|-----|------|---------|
| **Dashboard** | http://localhost:8501 | 8501 | Main Streamlit interface |
| **API Server** | http://localhost:5000 | 5000 | REST API endpoints |
| **API Docs** | http://localhost:5000/docs | 5000 | Swagger/OpenAPI documentation |
| **Kibana** | http://localhost:5601 | 5601 | Advanced analytics & logs |
| **Elasticsearch** | http://localhost:9200 | 9200 | Search & analytics engine |

---

## ⚙️ Configuration

### **Environment Setup**
```bash
# Copy example secrets file
cp secrets.toml.example secrets.toml

# Edit configuration (add your values)
nano secrets.toml
```

### **Sample secrets.toml**
```toml
[database]
path = "insider_threats.db"
backup_path = "backups/"

[api]
host = "0.0.0.0"
port = 5000
debug = false

[elk]
elasticsearch_host = "localhost:9200"
kibana_host = "localhost:5601"
logstash_host = "localhost:5044"

[auth]
admin_user = "admin"
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
admin_password_hash = "your-hashed-password-here"
session_timeout = 3600

[enterprise]
company_name = "Your Company"
timezone = "UTC"
data_retention_days = 90
```

### **Dashboard Configuration**
Create `dashboard/config.py`:
```python
DASHBOARD_CONFIG = {
    "theme": "dark",  # "dark" or "light"
    "auto_refresh": True,
    "refresh_interval": 60,  # seconds
    "max_alerts": 100,
    "risk_thresholds": {
        "low": 0.3,
        "medium": 0.6,
        "high": 0.8
    }
}
```

---

## 📊 Data Sources Configuration

### **1. Sysmon Integration**
```python
# In enterprise_config.json
{
  "sysmon": {
    "enabled": true,
    "csv_path": "sysmon_users.csv",
    "update_interval": 300,
    "parse_rules": {
      "failed_logins": 5,
      "suspicious_processes": ["mimikatz", "powersploit", "netcat"]
    }
  }
}
```

### **2. Enterprise Users**
```python
# Load from Active Directory or CSV
python enterprise_setup/sync_users.py \
  --source ad \
  --domain yourcompany.com \
  --output enterprise_users.json
```

### **3. Threat Intelligence Feeds**
```python
# Configure in dashboard/threat_feeds.py
THREAT_FEEDS = [
    {
        "name": "Internal Threats",
        "source": "sample_threats.json",
        "type": "json",
        "refresh": 3600
    },
    {
        "name": "Sysmon Events",
        "source": "uploaded_sysmon.csv",
        "type": "csv",
        "refresh": 300
    }
]
```

---

## 🎮 Using the Dashboard

### **First-Time Setup**
1. Open http://localhost:8501
2. Login with default credentials (check `secrets.toml`)
3. Configure data sources in Settings
4. Import initial data using "Load Sample Data" button
5. Set up alert rules and thresholds

### **Main Dashboard Sections:**
1. **Overview** - Real-time threat summary
2. **Users** - User behavior and risk scores
3. **Alerts** - Active security incidents
4. **Analytics** - Advanced threat analysis
5. **Reports** - Generate and export reports
6. **Settings** - System configuration

### **Keyboard Shortcuts:**
- `r` - Refresh dashboard
- `f` - Toggle fullscreen
- `s` - Save current view
- `e` - Export data
- `?` - Show help

---

## 🔧 Troubleshooting

### **Common Issues:**

#### **1. Dashboard won't start**
```bash
# Check Streamlit installation
pip install --upgrade streamlit

# Check port availability
netstat -ano | findstr :8501  # Windows
lsof -i :8501  # Mac/Linux

# Use different port
streamlit run enhanced_dashboard.py --server.port 8502
```

#### **2. Database connection errors**
```bash
# Reinitialize database
python simple_db.py --reset

# Check file permissions
ls -la insider_threats.db
chmod 644 insider_threats.db  # Linux/Mac
```

#### **3. Missing dependencies**
```bash
# Update requirements
pip install -r requirements.txt --upgrade

# Install missing packages
pip install pandas numpy plotly streamlit-aggrid
```

#### **4. ELK stack not connecting**
```bash
# Check ELK services
cd elk
docker-compose ps

# Test Elasticsearch
curl http://localhost:9200

# Update configuration in elk_integration.py
```

### **Logs Location:**
- Dashboard logs: `~/.streamlit/logs/`
- Application logs: `platform.log`
- Error logs: `dashboard/error.log`

---

## 📈 Sample Queries & Usage

### **1. Check high-risk users:**
```python
# In dashboard analytics
SELECT * FROM users WHERE risk_score > 0.8 
ORDER BY last_activity DESC LIMIT 10
```

### **2. Generate daily report:**
```bash
python -m dashboard.reporting \
  --type daily \
  --start "2024-01-01" \
  --end "2024-01-02" \
  --output reports/daily_threat_report.pdf
```

### **3. Import new threat data:**
```bash
python load_all_data.py \
  --file new_threats.csv \
  --type sysmon \
  --merge true
```

### **4. Monitor in real-time:**
```bash
# Watch dashboard logs
tail -f platform.log | grep -E "(ALERT|THREAT|ERROR)"

# Or use the monitoring endpoint
curl http://localhost:5000/health
```

---

## 🛡️ Security Best Practices

1. **Change default credentials** immediately
2. **Enable HTTPS** in production
3. **Regularly update** dependencies
4. **Backup databases** daily
5. **Monitor access logs** for suspicious activity
6. **Use firewall rules** to restrict access
7. **Implement rate limiting** on API endpoints
8. **Regular security audits**

---

## 📚 API Usage Examples

### **Python Client:**
```python
import requests

# Get current threats
response = requests.get(
    "http://localhost:5000/api/threats",
    headers={"Authorization": "Bearer YOUR_TOKEN"}
)
threats = response.json()

# Add new alert
requests.post("http://localhost:5000/api/alerts", json={
    "user_id": "user123",
    "severity": "high",
    "description": "Multiple failed login attempts"
})
```

### **cURL Examples:**
```bash
# Get dashboard status
curl -X GET http://localhost:5000/api/status

# Export threats as CSV
curl -X GET http://localhost:5000/api/threats/export?format=csv \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o threats_export.csv
```

---
