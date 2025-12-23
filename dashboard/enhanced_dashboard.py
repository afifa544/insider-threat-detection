# dashboard/enterprise_dashboard.py - ENHANCED VERSION WITH REPORT GENERATION
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import os
import re
import hashlib
from typing import Dict, List, Optional
import io
import base64
import warnings
import sys
import tempfile

warnings.filterwarnings('ignore')

# ============================================
# ENTERPRISE CONFIGURATION
# ============================================

ENTERPRISE_CONFIG = {
    "company_name": "Insider Threat Detection",
    "departments": ["IT", "HR", "Finance", "Engineering", "Security", "Operations"],
    "alert_levels": {
        "Critical": {"min_score": 80, "color": "#DC2626"},
        "High": {"min_score": 60, "color": "#EA580C"},
        "Medium": {"min_score": 40, "color": "#F59E0B"},
        "Low": {"min_score": 0, "color": "#10B981"}
    },
    "compliance_frameworks": ["NIST CSF", "MITRE ATT&CK", "ISO 27001", "GDPR"],
    "elk_host": "http://localhost:9200",
    "kibana_url": "http://localhost:5601",
}

# ============================================
# DATABASE CONFIGURATION (PostgreSQL)
# ============================================

DB_CONFIG = {
    "enabled": False,
    "connection_string": "postgresql://postgres:postgres@localhost:5432/threat_detection"
}

# ============================================
# PAGE CONFIGURATION
# ============================================

st.set_page_config(
    page_title="Insider Threat Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/your-repo',
        'Report a bug': "https://github.com/your-repo/issues",
        'About': "### Insider Threat Detection System v2.0\nAdvanced threat monitoring and reporting platform"
    }
)

# ============================================
# CYBER THEME CSS STYLING
# ============================================

st.markdown("""
<style>
    /* Main Theme */
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 100%);
        color: #00ff41;
        font-family: 'Segoe UI', 'Courier New', monospace;
    }
    
    /* Headers */
    .main-header {
        background: linear-gradient(90deg, rgba(0, 255, 65, 0.1) 0%, rgba(0, 255, 65, 0.05) 100%);
        padding: 2rem;
        border-radius: 10px;
        color: #00ff41;
        text-align: center;
        margin-bottom: 2rem;
        border: 2px solid #00ff41;
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.2);
    }
    
    /* Cards */
    .cyber-card {
        background: rgba(0, 0, 0, 0.8);
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #00ff41;
        color: #00ff41;
        margin: 0.5rem;
        transition: all 0.3s ease;
        backdrop-filter: blur(10px);
    }
    
    .cyber-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.3);
    }
    
    /* Alert Cards */
    .alert-critical {
        border-color: #ff0033 !important;
        background: linear-gradient(135deg, rgba(255, 0, 51, 0.1) 0%, rgba(255, 0, 51, 0.05) 100%) !important;
    }
    
    .alert-high {
        border-color: #ff6600 !important;
        background: linear-gradient(135deg, rgba(255, 102, 0, 0.1) 0%, rgba(255, 102, 0, 0.05) 100%) !important;
    }
    
    .alert-medium {
        border-color: #ffcc00 !important;
        background: linear-gradient(135deg, rgba(255, 204, 0, 0.1) 0%, rgba(255, 204, 0, 0.05) 100%) !important;
    }
    
    .alert-low {
        border-color: #00ff41 !important;
        background: linear-gradient(135deg, rgba(0, 255, 65, 0.1) 0%, rgba(0, 255, 65, 0.05) 100%) !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #00ff41 0%, #008f11 100%);
        color: #000000 !important;
        border: 1px solid #00ff41;
        border-radius: 5px;
        font-weight: bold;
        padding: 0.5rem 1rem;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #00ff88 0%, #00cc00 100%);
        border-color: #00ff88;
        transform: scale(1.05);
    }
    
    /* Metrics */
    .stMetric {
        background: rgba(0, 0, 0, 0.7);
        padding: 1rem;
        border-radius: 5px;
        border: 1px solid #00ff41;
    }
    
    /* DataFrames */
    .dataframe {
        background: rgba(0, 0, 0, 0.8) !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        border-radius: 5px !important;
    }
    
    .dataframe th {
        background: rgba(0, 255, 65, 0.2) !important;
        color: #00ff41 !important;
        font-weight: bold;
        border-bottom: 2px solid #00ff41 !important;
    }
    
    .dataframe td {
        border-bottom: 1px solid rgba(0, 255, 65, 0.1) !important;
    }
    
    /* Inputs */
    .stTextInput > div > div > input {
        background: rgba(0, 0, 0, 0.7);
        color: #00ff41 !important;
        border: 1px solid #00ff41;
        border-radius: 5px;
    }
    
    .stSelectbox > div > div {
        background: rgba(0, 0, 0, 0.7);
        color: #00ff41 !important;
        border: 1px solid #00ff41;
        border-radius: 5px;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0a0a 0%, #1a1a1a 100%);
        border-right: 1px solid #00ff41;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: rgba(0, 0, 0, 0.7);
        color: #00ff41;
        border: 1px solid #00ff41;
        border-radius: 5px 5px 0 0;
        padding: 10px 20px;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #00ff41 0%, #008f11 100%) !important;
        color: #000000 !important;
    }
    
    /* Progress bars */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #00ff41 0%, #008f11 100%);
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# REPORT GENERATION FUNCTIONS
# ============================================

def generate_html_report(data, title="Threat Analysis Report"):
    """Generate HTML report"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 40px;
                background: #0a0a0a;
                color: #00ff41;
            }}
            .header {{
                background: linear-gradient(90deg, rgba(0,255,65,0.1) 0%, rgba(0,255,65,0.05) 100%);
                padding: 30px;
                border-radius: 10px;
                border: 2px solid #00ff41;
                margin-bottom: 30px;
            }}
            .section {{
                background: rgba(0,0,0,0.8);
                padding: 20px;
                margin: 20px 0;
                border-radius: 10px;
                border: 1px solid #00ff41;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 10px 0;
            }}
            th, td {{
                border: 1px solid #00ff41;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background: rgba(0,255,65,0.2);
            }}
            .critical {{ color: #ff0033; font-weight: bold; }}
            .high {{ color: #ff6600; font-weight: bold; }}
            .medium {{ color: #ffcc00; }}
            .low {{ color: #00ff41; }}
            .metric {{
                background: rgba(0,255,65,0.1);
                padding: 15px;
                border-radius: 5px;
                margin: 10px;
                display: inline-block;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ {title}</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    """
    
    # Add metrics section
    if 'metrics' in data:
        html += "<div class='section'><h2>📊 Executive Summary</h2>"
        for metric in data['metrics']:
            html += f"<div class='metric'><strong>{metric['label']}:</strong> {metric['value']}</div>"
        html += "</div>"
    
    # Add threats section
    if 'threats' in data:
        html += "<div class='section'><h2>🚨 Threat Analysis</h2>"
        html += f"<p>Total Threats: {len(data['threats'])}</p>"
        
        if len(data['threats']) > 0:
            html += "<table><tr><th>User</th><th>Action</th><th>Severity</th><th>Risk</th><th>Department</th></tr>"
            for threat in data['threats']:
                severity_class = threat.get('severity', '').lower()
                html += f"""
                <tr>
                    <td>{threat.get('user', 'N/A')}</td>
                    <td>{threat.get('action', 'N/A')}</td>
                    <td class='{severity_class}'>{threat.get('severity', 'N/A')}</td>
                    <td>{threat.get('risk_score', 'N/A')}</td>
                    <td>{threat.get('department', 'N/A')}</td>
                </tr>
                """
            html += "</table>"
        html += "</div>"
    
    # Add recommendations
    if 'recommendations' in data:
        html += "<div class='section'><h2>💡 Recommendations</h2><ul>"
        for rec in data['recommendations']:
            html += f"<li>{rec}</li>"
        html += "</ul></div>"
    
    html += """
        <div class="section">
            <h2>📝 Report Information</h2>
            <p><strong>Generated By:</strong> Security Operations Center</p>
            <p><strong>Report ID:</strong> """ + str(hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]) + """</p>
            <p><strong>Confidentiality:</strong> Internal Use Only</p>
        </div>
    </body>
    </html>
    """
    
    return html

def generate_excel_report(data, filename=None):
    """Generate Excel report"""
    import tempfile
    
    if filename is None:
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
        filename = temp_file.name
    
    try:
        # Create Excel writer
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            # Summary sheet
            if 'metrics' in data:
                summary_data = []
                for metric in data['metrics']:
                    summary_data.append([metric['label'], metric['value']])
                
                summary_df = pd.DataFrame(summary_data, columns=['Metric', 'Value'])
                summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Threats sheet
            if 'threats' in data and data['threats']:
                threats_df = pd.DataFrame(data['threats'])
                if not threats_df.empty:
                    threats_df.to_excel(writer, sheet_name='Threats', index=False)
            
            # Recommendations sheet
            if 'recommendations' in data:
                rec_df = pd.DataFrame({'Recommendations': data['recommendations']})
                rec_df.to_excel(writer, sheet_name='Recommendations', index=False)
            
            # Analysis sheet
            if 'analysis' in data:
                analysis_data = []
                for category, values in data['analysis'].items():
                    for key, value in values.items():
                        analysis_data.append([category.replace('_', ' ').title(), key, value])
                
                if analysis_data:
                    analysis_df = pd.DataFrame(analysis_data, columns=['Category', 'Item', 'Count'])
                    analysis_df.to_excel(writer, sheet_name='Analysis', index=False)
        
        return filename
        
    except Exception as e:
        st.error(f"Excel generation error: {str(e)}")
        return None

# ============================================
# HELPER FUNCTIONS
# ============================================

def init_database():
    """Initialize database connection"""
    if not DB_CONFIG["enabled"]:
        return None
    
    try:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        engine = create_engine(DB_CONFIG["connection_string"])
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return SessionLocal()
    except Exception as e:
        st.error(f"❌ Database connection failed: {str(e)[:100]}")
        return None

def save_threats_to_db(threats_df):
    """Save threats to PostgreSQL database"""
    if not DB_CONFIG["enabled"]:
        return False
    
    try:
        session = init_database()
        if not session:
            return False
        
        from sqlalchemy import text
        
        success_count = 0
        error_count = 0
        
        for _, threat in threats_df.iterrows():
            try:
                username = threat['user'].split('@')[0] if '@' in threat['user'] else threat['user']
                
                # Insert or update user
                user_query = text("""
                    INSERT INTO users (username, email, department, role, risk_score, status)
                    VALUES (:username, :email, :department, 'employee', :risk_score, 'active')
                    ON CONFLICT (username) DO UPDATE SET
                        department = EXCLUDED.department,
                        risk_score = EXCLUDED.risk_score,
                        last_risk_assessment = NOW()
                    RETURNING user_id
                """)
                
                user_result = session.execute(user_query, {
                    'username': username,
                    'email': threat['user'],
                    'department': threat['department'],
                    'risk_score': float(threat['risk_score'])
                }).fetchone()
                
                user_id = user_result[0] if user_result else None
                
                # Insert threat
                threat_query = text("""
                    INSERT INTO threats (
                        user_id, timestamp, threat_type, severity, description,
                        source_ip, department, confidence_score, investigation_status
                    ) VALUES (
                        :user_id, :timestamp, :threat_type, :severity, :description,
                        :source_ip, :department, :confidence_score, 'new'
                    )
                    RETURNING threat_id
                """)
                
                severity = threat['severity'].lower() if isinstance(threat['severity'], str) else 'medium'
                
                session.execute(threat_query, {
                    'user_id': user_id,
                    'timestamp': pd.to_datetime(threat['timestamp']),
                    'threat_type': str(threat['action']),
                    'severity': severity,
                    'description': f"{threat['action']} by {threat['user']} in {threat['department']}",
                    'source_ip': str(threat['source_ip']),
                    'department': str(threat['department']),
                    'confidence_score': float(threat['risk_score']) / 100.0 * 90.0
                })
                
                success_count += 1
                
            except Exception as e:
                error_count += 1
                continue
        
        session.commit()
        session.close()
        
        if success_count > 0:
            st.session_state.last_save_count = success_count
            return True
        else:
            return False
        
    except Exception as e:
        st.error(f"❌ Save failed: {str(e)[:100]}")
        return False

def get_database_stats():
    """Get database statistics"""
    if not DB_CONFIG["enabled"]:
        return {}
    
    try:
        session = init_database()
        if not session:
            return {}
        
        from sqlalchemy import text
        
        stats = {}
        
        # Get user count
        user_query = text("SELECT COUNT(*) FROM users WHERE status = 'active'")
        stats['user_count'] = pd.read_sql(user_query, session.bind).iloc[0, 0]
        
        # Get threat count
        threat_query = text("SELECT COUNT(*) FROM threats")
        stats['threat_count'] = pd.read_sql(threat_query, session.bind).iloc[0, 0]
        
        # Get recent threats
        recent_query = text("SELECT COUNT(*) FROM threats WHERE timestamp >= NOW() - INTERVAL '24 hours'")
        stats['recent_threats'] = pd.read_sql(recent_query, session.bind).iloc[0, 0]
        
        # Get threat distribution
        dist_query = text("""
            SELECT severity, COUNT(*) as count 
            FROM threats 
            GROUP BY severity 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """)
        stats['threat_distribution'] = pd.read_sql(dist_query, session.bind)
        
        session.close()
        return stats
        
    except Exception as e:
        return {}

# ============================================
# DATA GENERATION FUNCTIONS
# ============================================

def generate_sample_threats(num=100):
    """Generate sample threat data"""
    np.random.seed(42)
    
    threats = []
    for i in range(num):
        threat = {
            "id": f"THR{i:04d}",
            "timestamp": (datetime.now() - timedelta(hours=np.random.randint(0, 72))).isoformat(),
            "user": f"user{np.random.randint(1000, 9999)}@company.com",
            "action": np.random.choice(["Unauthorized Access", "Data Export", "Suspicious Login", 
                                       "File Modification", "Process Execution", "Privilege Escalation",
                                       "Data Exfiltration", "Malware Execution", "Credential Dumping"]),
            "severity": np.random.choice(["Critical", "High", "Medium", "Low"], p=[0.1, 0.2, 0.3, 0.4]),
            "department": np.random.choice(ENTERPRISE_CONFIG["departments"]),
            "risk_score": np.random.randint(10, 95),
            "status": np.random.choice(["Investigating", "Contained", "Resolved", "Pending"], p=[0.4, 0.2, 0.2, 0.2]),
            "source_ip": f"192.168.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "destination_ip": f"10.0.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "asset": f"Workstation-{np.random.randint(100, 999)}",
            "mitre_technique": np.random.choice(["T1078", "T1059", "T1566", "T1027", "T1003"])
        }
        threats.append(threat)
    
    return pd.DataFrame(threats)

def generate_sysmon_sample(num=50):
    """Generate sample Sysmon data"""
    events = []
    for i in range(num):
        event = {
            "timestamp": (datetime.now() - timedelta(minutes=np.random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": np.random.choice(["Process Creation", "Network Connection", "File Creation", 
                                          "Process Termination", "Registry Event", "DNS Query"]),
            "process_name": np.random.choice(["powershell.exe", "cmd.exe", "chrome.exe", "explorer.exe", 
                                            "svchost.exe", "code.exe", "python.exe", "git.exe"]),
            "user": f"user{np.random.randint(1, 100)}",
            "source_ip": f"192.168.{np.random.randint(1,254)}.{np.random.randint(1,254)}",
            "dest_ip": f"{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            "port": np.random.choice([80, 443, 22, 3389, 445, 53, 8080]),
            "risk_score": np.random.randint(10, 90),
            "severity": np.random.choice(["Low", "Medium", "High", "Critical"], p=[0.5, 0.3, 0.15, 0.05])
        }
        events.append(event)
    
    return pd.DataFrame(events)

# ============================================
# MAIN DASHBOARD CLASS
# ============================================

class InsiderThreatDashboard:
    """Main dashboard class with enhanced features"""
    
    def __init__(self):
        # Initialize session state
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = True
        if 'current_user' not in st.session_state:
            st.session_state.current_user = {
                "username": "soc_analyst",
                "role": "Security Analyst",
                "department": "Security",
                "avatar": "👨‍💻"
            }
        if 'threat_data' not in st.session_state:
            st.session_state.threat_data = generate_sample_threats(200)
        if 'sysmon_data' not in st.session_state:
            st.session_state.sysmon_data = generate_sysmon_sample(100)
        if 'favorites' not in st.session_state:
            st.session_state.favorites = []
        if 'recent_reports' not in st.session_state:
            st.session_state.recent_reports = []
        if 'notifications' not in st.session_state:
            st.session_state.notifications = [
                {"id": 1, "type": "info", "message": "Welcome to the Insider Threat Dashboard!", "time": "Just now"},
                {"id": 2, "type": "warning", "message": "3 critical threats detected", "time": "5 min ago"}
            ]
    
    def create_header(self):
        """Create enhanced dashboard header"""
        user = st.session_state.current_user
        
        # Header with notifications
        col1, col2, col3 = st.columns([3, 1, 1])
        
        with col1:
            st.markdown(f"""
            <div class="main-header">
                <h1>🛡️ {ENTERPRISE_CONFIG["company_name"]}</h1>
                <p>Advanced Threat Intelligence & Reporting Platform</p>
                <div style="margin-top: 1rem; display: flex; justify-content: center; gap: 15px; flex-wrap: wrap;">
                    <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                        {user['avatar']} {user['username']}
                    </span>
                    <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                        🏢 {user['department']}
                    </span>
                    <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                        {'⚡ DATABASE: ONLINE' if DB_CONFIG['enabled'] else '⚠️ DATABASE: OFFLINE'}
                    </span>
                    <span style="background: rgba(0,255,65,0.2); padding: 5px 15px; border-radius: 20px; border: 1px solid #00ff41;">
                        🕐 {datetime.now().strftime('%H:%M')}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            # Quick stats
            if st.session_state.threat_data is not None:
                df = st.session_state.threat_data
                critical = len(df[df['severity'] == 'Critical'])
                st.markdown(f"""
                <div style="text-align: center;">
                    <div style="font-size: 24px; color: #ff0033;">{critical}</div>
                    <div style="font-size: 12px;">Critical Threats</div>
                </div>
                """, unsafe_allow_html=True)
        
        with col3:
            # Notification bell
            notification_count = len([n for n in st.session_state.notifications if n['type'] == 'warning'])
            if st.button(f"🔔 ({notification_count})", help="View notifications", key="notif_btn"):
                st.session_state.show_notifications = not st.session_state.get('show_notifications', False)
        
        # Notifications panel
        if st.session_state.get('show_notifications', False):
            with st.expander("📢 Notifications", expanded=True):
                for notification in st.session_state.notifications:
                    icon = "ℹ️" if notification['type'] == 'info' else "⚠️" if notification['type'] == 'warning' else "✅"
                    st.markdown(f"{icon} **{notification['message']}** - *{notification['time']}*")
                
                if st.button("Clear All", key="clear_notifs"):
                    st.session_state.notifications = []
                    st.rerun()
    
    def create_sidebar(self):
        """Create enhanced sidebar with quick actions"""
        with st.sidebar:
            # User profile
            st.markdown("### 👤 USER PROFILE")
            user = st.session_state.current_user
            
            col1, col2 = st.columns([1, 3])
            with col1:
                st.markdown(f"<div style='font-size: 32px;'>{user['avatar']}</div>", unsafe_allow_html=True)
            with col2:
                st.markdown(f"**{user['username']}**")
                st.caption(f"{user['role']} | {user['department']}")
            
            st.markdown("---")
            
            # Navigation
            st.markdown("### 🗺️ NAVIGATION")
            
            tabs = [
                {"icon": "📊", "name": "Dashboard", "key": "dashboard"},
                {"icon": "🔍", "name": "Threat Analysis", "key": "analysis"},
                {"icon": "📡", "name": "Sysmon Logs", "key": "sysmon"},
                {"icon": "📋", "name": "Reports", "key": "reports"},
                {"icon": "⚙️", "name": "Configuration", "key": "config"}
            ]
            
            selected_tab = st.radio(
                "Select Section",
                [f"{tab['icon']} {tab['name']}" for tab in tabs],
                label_visibility="collapsed",
                key="sidebar_nav"
            )
            
            selected_key = next(tab['key'] for tab in tabs if f"{tab['icon']} {tab['name']}" == selected_tab)
            st.session_state.current_tab = selected_key
            
            st.markdown("---")
            
            # Quick Actions
            st.markdown("### ⚡ QUICK ACTIONS")
            
            action_cols = st.columns(2)
            with action_cols[0]:
                if st.button("🔄", help="Refresh Data", use_container_width=True):
                    st.session_state.threat_data = generate_sample_threats(200)
                    st.session_state.sysmon_data = generate_sysmon_sample(100)
                    st.session_state.notifications.append({
                        "id": len(st.session_state.notifications) + 1,
                        "type": "info",
                        "message": "Data refreshed successfully",
                        "time": "Just now"
                    })
                    st.rerun()
            
            with action_cols[1]:
                if st.button("🚨", help="New Alert", use_container_width=True):
                    st.session_state.notifications.append({
                        "id": len(st.session_state.notifications) + 1,
                        "type": "warning",
                        "message": "Test alert generated",
                        "time": "Just now"
                    })
                    st.rerun()
            
            st.markdown("---")
            
            # System Status
            st.markdown("### 🔌 SYSTEM STATUS")
            
            if st.session_state.threat_data is not None:
                df = st.session_state.threat_data
                
                # Status indicators
                status_items = [
                    ("Total Threats", len(df), "#00ff41"),
                    ("Active", len(df[df['status'] == 'Investigating']), "#ffcc00"),
                    ("Critical", len(df[df['severity'] == 'Critical']), "#ff0033"),
                    ("Avg Risk", f"{df['risk_score'].mean():.1f}", "#00ff41")
                ]
                
                for label, value, color in status_items:
                    st.markdown(f"""
                    <div style="display: flex; justify-content: space-between; margin: 5px 0;">
                        <span>{label}:</span>
                        <span style="color: {color}; font-weight: bold;">{value}</span>
                    </div>
                    """, unsafe_allow_html=True)
            
            # Database Status
            st.markdown("### 🗄️ DATABASE STATUS")
            if DB_CONFIG["enabled"]:
                try:
                    stats = get_database_stats()
                    if stats:
                        st.progress(stats.get('recent_threats', 0) / max(stats.get('threat_count', 1), 1), 
                                   text=f"24h: {stats.get('recent_threats', 0)} threats")
                    else:
                        st.caption("Connected - No data")
                except Exception as e:
                    st.caption("Connection error")
            else:
                st.warning("Database disabled")
            
            st.markdown("---")
            
            # Help & Support
            with st.expander("❓ Help & Support"):
                st.markdown("""
                **Quick Tips:**
                - Click on any chart for details
                - Use filters to narrow down threats
                - Export reports in multiple formats
                - Bookmark important views
                
                **Support:**
                - Email: soc@company.com
                - Phone: x1234
                - Documentation: [View Docs](#)
                """)
    
    def create_dashboard_tab(self):
        """Create enhanced dashboard tab"""
        st.header("📊 EXECUTIVE DASHBOARD")
        
        if st.session_state.threat_data is None:
            st.warning("No threat data available")
            return
        
        df = st.session_state.threat_data
        
        # Top Metrics Row
        metrics_cols = st.columns(5)
        metrics = [
            ("🚨 CRITICAL", len(df[df['severity'] == 'Critical']), "#ff0033"),
            ("⚠️ HIGH", len(df[df['severity'] == 'High']), "#ff6600"),
            ("⚡ MEDIUM", len(df[df['severity'] == 'Medium']), "#ffcc00"),
            ("📈 AVG RISK", f"{df['risk_score'].mean():.1f}", "#00ff41"),
            ("🔍 INVESTIGATING", len(df[df['status'] == 'Investigating']), "#00ff41")
        ]
        
        for idx, (label, value, color) in enumerate(metrics):
            with metrics_cols[idx]:
                st.markdown(f"""
                <div class="cyber-card" style="border-color: {color};">
                    <h3 style="color: {color};">{label}</h3>
                    <h2>{value}</h2>
                </div>
                """, unsafe_allow_html=True)
        
        # Charts Row
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Threat Distribution")
            severity_counts = df['severity'].value_counts().reset_index()
            severity_counts.columns = ['Severity', 'Count']
            
            fig = px.pie(severity_counts, values='Count', names='Severity',
                        color='Severity',
                        color_discrete_map={
                            'Critical': '#DC2626',
                            'High': '#EA580C',
                            'Medium': '#F59E0B',
                            'Low': '#10B981'
                        })
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📈 Risk Timeline")
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            timeline = df.groupby('hour').agg({
                'risk_score': 'mean',
                'id': 'count'
            }).reset_index()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=timeline['hour'], 
                y=timeline['risk_score'],
                mode='lines+markers',
                line=dict(color='#00ff41', width=3),
                name='Risk Score'
            ))
            fig.add_trace(go.Bar(
                x=timeline['hour'],
                y=timeline['id'],
                name='Threat Count',
                yaxis='y2',
                opacity=0.3
            ))
            
            fig.update_layout(
                title="Risk Score & Threat Count by Hour",
                xaxis_title="Hour of Day",
                yaxis_title="Risk Score",
                yaxis2=dict(
                    title="Threat Count",
                    overlaying='y',
                    side='right'
                )
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Department Analysis
        st.subheader("🏢 DEPARTMENT ANALYSIS")
        dept_cols = st.columns(2)
        
        with dept_cols[0]:
            dept_counts = df['department'].value_counts().reset_index()
            dept_counts.columns = ['Department', 'Count']
            
            fig = px.bar(dept_counts, x='Department', y='Count',
                        color='Count',
                        color_continuous_scale='reds')
            st.plotly_chart(fig, use_container_width=True)
        
        with dept_cols[1]:
            dept_risk = df.groupby('department').agg({
                'risk_score': 'mean',
                'id': 'count'
            }).rename(columns={'id': 'threat_count'}).reset_index()
            
            fig = px.scatter(dept_risk, x='threat_count', y='risk_score',
                            size='threat_count', color='department',
                            hover_name='department',
                            title="Department Risk vs Threat Count")
            st.plotly_chart(fig, use_container_width=True)
        
        # Recent Threats with Actions
        st.subheader("🚨 RECENT THREATS")
        
        recent_threats = df.sort_values('timestamp', ascending=False).head(8)
        
        for idx, threat in recent_threats.iterrows():
            severity_color = ENTERPRISE_CONFIG['alert_levels'][threat['severity']]['color']
            
            col1, col2 = st.columns([4, 1])
            with col1:
                st.markdown(f"""
                <div style="
                    background: rgba(0,0,0,0.7);
                    border-left: 4px solid {severity_color};
                    padding: 1rem;
                    border-radius: 5px;
                    margin: 0.5rem 0;
                    color: #00ff41;
                    border: 1px solid {severity_color};
                ">
                    <strong>{threat['action']}</strong> | <code>{threat['id']}</code><br>
                    <small>👤 {threat['user']} | 🏢 {threat['department']}</small><br>
                    <small>Severity: {threat['severity']} | Risk: {threat['risk_score']} | Status: {threat['status']}</small>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if st.button("📝", key=f"action_{threat['id']}", help="Take action"):
                    st.session_state.selected_threat = threat
                    st.rerun()
    
    def create_threat_analysis_tab(self):
        """Create enhanced threat analysis tab"""
        st.header("🔍 THREAT INTELLIGENCE CENTER")
        
        if st.session_state.threat_data is None:
            st.warning("No data available")
            return
        
        df = st.session_state.threat_data
        
        # Advanced Filtering Panel
        with st.expander("🔎 ADVANCED FILTERS", expanded=True):
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                severity_filter = st.multiselect(
                    "Severity Level",
                    options=["Critical", "High", "Medium", "Low"],
                    default=["Critical", "High"],
                    help="Select threat severity levels"
                )
            
            with col2:
                department_filter = st.multiselect(
                    "Department",
                    options=ENTERPRISE_CONFIG["departments"],
                    default=ENTERPRISE_CONFIG["departments"],
                    help="Filter by department"
                )
            
            with col3:
                status_filter = st.multiselect(
                    "Investigation Status",
                    options=["Investigating", "Contained", "Resolved", "Pending"],
                    default=["Investigating", "Pending"],
                    help="Filter by investigation status"
                )
            
            with col4:
                date_range = st.date_input(
                    "Date Range",
                    value=[datetime.now() - timedelta(days=7), datetime.now()],
                    help="Select date range for threats"
                )
            
            # Additional filters
            col5, col6 = st.columns(2)
            with col5:
                risk_range = st.slider(
                    "Risk Score Range",
                    0, 100,
                    (60, 100),
                    help="Filter by risk score"
                )
            
            with col6:
                threat_type = st.multiselect(
                    "Threat Type",
                    options=df['action'].unique() if 'action' in df.columns else [],
                    help="Select specific threat types"
                )
        
        # Apply filters
        filtered_df = df.copy()
        filtered_df['date'] = pd.to_datetime(filtered_df['timestamp']).dt.date
        
        if severity_filter:
            filtered_df = filtered_df[filtered_df['severity'].isin(severity_filter)]
        if department_filter:
            filtered_df = filtered_df[filtered_df['department'].isin(department_filter)]
        if status_filter:
            filtered_df = filtered_df[filtered_df['status'].isin(status_filter)]
        if threat_type:
            filtered_df = filtered_df[filtered_df['action'].isin(threat_type)]
        
        filtered_df = filtered_df[
            (filtered_df['risk_score'] >= risk_range[0]) &
            (filtered_df['risk_score'] <= risk_range[1])
        ]
        
        if len(date_range) == 2:
            filtered_df = filtered_df[
                (filtered_df['date'] >= date_range[0]) &
                (filtered_df['date'] <= date_range[1])
            ]
        
        # Display Results
        st.markdown(f"### 📊 Results: {len(filtered_df)} threats found")
        
        if not filtered_df.empty:
            # Summary metrics
            metrics_cols = st.columns(4)
            summary_metrics = [
                ("Critical", len(filtered_df[filtered_df['severity'] == 'Critical'])),
                ("High Risk", len(filtered_df[filtered_df['severity'] == 'High'])),
                ("Avg Score", f"{filtered_df['risk_score'].mean():.1f}"),
                ("Investigating", len(filtered_df[filtered_df['status'] == 'Investigating']))
            ]
            
            for idx, (label, value) in enumerate(summary_metrics):
                with metrics_cols[idx]:
                    st.metric(label, value)
            
            # Interactive Data Table
            st.subheader("📋 THREAT DETAILS")
            
            # Column selection
            available_cols = ['timestamp', 'user', 'action', 'severity', 
                            'department', 'risk_score', 'status', 'source_ip',
                            'destination_ip', 'asset']
            selected_cols = st.multiselect(
                "Select columns to display",
                options=available_cols,
                default=['timestamp', 'user', 'action', 'severity', 'department', 'risk_score', 'status']
            )
            
            if selected_cols:
                display_df = filtered_df[selected_cols].sort_values(
                    ['risk_score', 'timestamp'], 
                    ascending=[False, False]
                )
                
                # Pagination
                page_size = st.select_slider(
                    "Rows per page",
                    options=[10, 25, 50, 100],
                    value=25
                )
                
                total_pages = max(1, len(display_df) // page_size + (1 if len(display_df) % page_size else 0))
                page_number = st.number_input(
                    "Page",
                    min_value=1,
                    max_value=total_pages,
                    value=1
                )
                
                start_idx = (page_number - 1) * page_size
                end_idx = min(page_number * page_size, len(display_df))
                
                # Display paginated data
                st.dataframe(
                    display_df.iloc[start_idx:end_idx],
                    use_container_width=True,
                    height=400
                )
                
                st.caption(f"Showing rows {start_idx + 1} to {end_idx} of {len(display_df)}")
                
                # Export options
                export_col1, export_col2, export_col3 = st.columns(3)
                
                with export_col1:
                    if st.button("📥 Export CSV", use_container_width=True):
                        csv = filtered_df.to_csv(index=False)
                        st.download_button(
                            label="Download CSV",
                            data=csv,
                            file_name=f"threats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                
                with export_col2:
                    if st.button("📊 Quick Report", use_container_width=True):
                        report_data = {
                            'metrics': [
                                {'label': 'Total Threats', 'value': len(filtered_df)},
                                {'label': 'Critical Threats', 'value': len(filtered_df[filtered_df['severity'] == 'Critical'])},
                                {'label': 'Average Risk Score', 'value': f"{filtered_df['risk_score'].mean():.1f}"}
                            ],
                            'threats': filtered_df.head(50).to_dict('records'),
                            'recommendations': [
                                "Review critical threats immediately",
                                "Implement additional monitoring for high-risk departments",
                                "Schedule security awareness training"
                            ]
                        }
                        
                        html_report = generate_html_report(report_data)
                        st.download_button(
                            label="Download HTML Report",
                            data=html_report,
                            file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html",
                            use_container_width=True
                        )
                
                with export_col3:
                    if st.button("⭐ Save View", use_container_width=True):
                        st.session_state.favorites.append({
                            'name': "My Threat View",
                            'filters': {
                                'severity': severity_filter,
                                'department': department_filter,
                                'status': status_filter,
                                'risk_range': risk_range
                            },
                            'timestamp': datetime.now().isoformat()
                        })
                        st.success("View saved to favorites!")
            
            # Threat Intelligence Panel
            with st.expander("🔬 THREAT INTELLIGENCE", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    # Top users by threat count
                    top_users = filtered_df['user'].value_counts().head(10).reset_index()
                    top_users.columns = ['User', 'Threat Count']
                    st.write("**Top Users by Threat Count**")
                    st.dataframe(top_users, hide_index=True, use_container_width=True)
                
                with col2:
                    # Threat patterns
                    threat_patterns = filtered_df['action'].value_counts().head(10).reset_index()
                    threat_patterns.columns = ['Threat Type', 'Count']
                    st.write("**Most Common Threat Types**")
                    st.dataframe(threat_patterns, hide_index=True, use_container_width=True)
        
        else:
            st.info("No threats match the selected filters")
    
    def parse_sysmon_message(self, message):
        """Parse Sysmon message field to extract IP addresses and other fields"""
        if pd.isna(message):
            return {}
        
        result = {}
        lines = str(message).split('\n')
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                # Extract different fields
                if key == 'SourceIp':
                    result['source_ip'] = value
                elif key == 'DestinationIp':
                    result['destination_ip'] = value
                elif key == 'Image':
                    result['process_name'] = value
                elif key == 'User':
                    result['user'] = value
                elif key == 'Protocol':
                    result['protocol'] = value
                elif key == 'SourcePort':
                    result['source_port'] = value
                elif key == 'DestinationPort':
                    result['destination_port'] = value
                elif key == 'ProcessId':
                    result['process_id'] = value
                elif key == 'UtcTime':
                    result['utc_time'] = value
                elif key == 'EventID' or key == 'Id':
                    result['event_id'] = value
        
        return result
    
    def create_sysmon_tab(self):
        """Create enhanced Sysmon analysis tab"""
        st.header("📡 ADVANCED LOG ANALYSIS")
        
        # File upload with drag & drop
        uploaded_file = st.file_uploader(
            "Drag & drop or click to upload Sysmon CSV/JSON/Log files",
            type=['csv', 'json', 'txt', 'log'],
            help="Supports multiple file formats including CSV, JSON, and raw logs"
        )
        
        if uploaded_file is not None:
            try:
                if uploaded_file.name.endswith('.csv'):
                    sysmon_df = pd.read_csv(uploaded_file)
                    file_type = "CSV"
                elif uploaded_file.name.endswith('.json'):
                    sysmon_df = pd.read_json(uploaded_file)
                    file_type = "JSON"
                else:
                    # Try to parse as log file
                    lines = uploaded_file.getvalue().decode().split('\n')
                    sysmon_df = pd.DataFrame({'log_entry': lines})
                    file_type = "LOG"
                
                st.success(f"✅ Loaded {len(sysmon_df)} events from {file_type} file")
                
                # Parse Message field if it exists
                if 'Message' in sysmon_df.columns:
                    def parse_message(msg):
                        result = {}
                        if pd.isna(msg):
                            return result
                        
                        lines = str(msg).split('\n')
                        for line in lines:
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                if key in ['SourceIp', 'DestinationIp', 'Image', 'User', 'Protocol', 'ProcessId']:
                                    result[key] = value
                        return result
                    
                    parsed_data = sysmon_df['Message'].apply(parse_message)
                    parsed_df = pd.DataFrame(parsed_data.tolist())
                    sysmon_df = pd.concat([sysmon_df, parsed_df], axis=1)
                    st.info(f"✅ Parsed {len(parsed_df)} events from Message field")
                
                st.session_state.uploaded_sysmon = sysmon_df
                
            except Exception as e:
                st.error(f"❌ Error loading file: {str(e)}")
                sysmon_df = st.session_state.sysmon_data
        elif hasattr(st.session_state, 'uploaded_sysmon'):
            sysmon_df = st.session_state.uploaded_sysmon
        else:
            sysmon_df = st.session_state.sysmon_data
            st.info("💡 Using sample data. Upload a file for real analysis.")
        
        # Quick Metrics with Tooltips
        metrics_cols = st.columns(4)
        
        with metrics_cols[0]:
            st.metric("Total Events", len(sysmon_df), 
                     help="Total number of log events")
        
        with metrics_cols[1]:
            # Count unique IPs safely
            ip_count = 0
            ip_columns = [col for col in sysmon_df.columns if 'ip' in col.lower()]
            if ip_columns:
                unique_ips = set()
                for col in ip_columns:
                    unique_ips.update(sysmon_df[col].dropna().astype(str).unique())
                ip_count = len(unique_ips)
            st.metric("Unique IPs", ip_count, 
                     help="Unique IP addresses found in logs")
        
        with metrics_cols[2]:
            # Count unique processes
            process_cols = [col for col in sysmon_df.columns if 'process' in col.lower() or 'image' in col.lower()]
            process_count = len(sysmon_df[process_cols[0]].unique()) if process_cols else 0
            st.metric("Unique Processes", process_count,
                     help="Unique processes detected")
        
        with metrics_cols[3]:
            # Event rate
            if 'timestamp' in sysmon_df.columns:
                try:
                    sysmon_df['timestamp_dt'] = pd.to_datetime(sysmon_df['timestamp'])
                    time_range = (sysmon_df['timestamp_dt'].max() - sysmon_df['timestamp_dt'].min()).total_seconds() / 3600
                    events_per_hour = len(sysmon_df) / max(time_range, 1)
                    st.metric("Events/Hour", f"{events_per_hour:.1f}",
                             help="Average events per hour")
                except:
                    st.metric("Events/Hour", "N/A")
        
        # Data Preview
        with st.expander("📋 DATA PREVIEW", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Column Information**")
                col_info = pd.DataFrame({
                    'Column': sysmon_df.columns,
                    'Type': sysmon_df.dtypes.astype(str),
                    'Non-Null': sysmon_df.notna().sum(),
                    'Unique': [sysmon_df[col].nunique() for col in sysmon_df.columns]
                })
                st.dataframe(col_info, hide_index=True, use_container_width=True)
            
            with col2:
                st.write("**Sample Data**")
                st.dataframe(sysmon_df.head(10), use_container_width=True)
        
        # Analysis Options
        analysis_type = st.selectbox(
            "Select Analysis Type",
            ["Network Analysis", "Process Analysis", "User Behavior", "Threat Hunting"],
            help="Choose the type of analysis to perform"
        )
        
        if analysis_type == "Network Analysis":
            self._network_analysis(sysmon_df)
        elif analysis_type == "Process Analysis":
            self._process_analysis(sysmon_df)
        elif analysis_type == "User Behavior":
            self._user_behavior_analysis(sysmon_df)
        elif analysis_type == "Threat Hunting":
            self._threat_hunting_analysis(sysmon_df)
        
        # Export Options
        with st.expander("📤 EXPORT OPTIONS"):
            export_format = st.radio(
                "Export Format",
                ["CSV", "JSON", "Excel"],
                horizontal=True
            )
            
            if st.button("Generate Export", use_container_width=True):
                if export_format == "CSV":
                    csv = sysmon_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"sysmon_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                elif export_format == "JSON":
                    json_str = sysmon_df.to_json(orient='records', indent=2)
                    st.download_button(
                        label="Download JSON",
                        data=json_str,
                        file_name=f"sysmon_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                elif export_format == "Excel":
                    report_data = {
                        'threats': sysmon_df.to_dict('records'),
                        'metrics': [
                            {'label': 'Total Events', 'value': len(sysmon_df)},
                            {'label': 'Unique IPs', 'value': ip_count},
                            {'label': 'Unique Processes', 'value': process_count}
                        ]
                    }
                    
                    excel_file = generate_excel_report(report_data)
                    if excel_file:
                        with open(excel_file, 'rb') as f:
                            st.download_button(
                                label="Download Excel",
                                data=f,
                                file_name=f"sysmon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                        # Clean up temp file
                        try:
                            os.unlink(excel_file)
                        except:
                            pass
    
    def _network_analysis(self, df):
        """Network analysis visualization"""
        st.subheader("🌐 NETWORK ANALYSIS")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Find IP columns
            ip_cols = [col for col in df.columns if 'ip' in col.lower()]
            if ip_cols:
                selected_ip_col = st.selectbox("Select IP Column", ip_cols)
                
                # Top IPs
                top_ips = df[selected_ip_col].value_counts().head(15).reset_index()
                top_ips.columns = ['IP Address', 'Count']
                
                fig = px.bar(top_ips, x='Count', y='IP Address', orientation='h',
                            title=f"Top IP Addresses ({selected_ip_col})",
                            color='Count',
                            color_continuous_scale='reds')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No IP columns found for network analysis")
        
        with col2:
            # Port analysis if available
            port_cols = [col for col in df.columns if 'port' in col.lower()]
            if port_cols:
                selected_port_col = st.selectbox("Select Port Column", port_cols)
                
                # Port distribution
                port_counts = df[selected_port_col].value_counts().head(10).reset_index()
                port_counts.columns = ['Port', 'Count']
                
                fig = px.pie(port_counts, values='Count', names='Port',
                            title=f"Top Ports ({selected_port_col})", hole=0.3)
                st.plotly_chart(fig, use_container_width=True)
    
    def _process_analysis(self, df):
        """Process analysis visualization"""
        st.subheader("⚙️ PROCESS ANALYSIS")
        
        # Find process columns
        process_cols = [col for col in df.columns if 'process' in col.lower() or 'image' in col.lower()]
        
        if process_cols:
            selected_col = st.selectbox("Select Process Column", process_cols)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Top processes
                top_processes = df[selected_col].value_counts().head(15).reset_index()
                top_processes.columns = ['Process', 'Count']
                
                fig = px.bar(top_processes, x='Count', y='Process', orientation='h',
                            title=f"Top Processes ({selected_col})",
                            color='Count',
                            color_continuous_scale='reds')
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Process tree
                st.write("**Process Relationships**")
                st.info("Process relationship visualization coming soon...")
        else:
            st.info("No process columns found for analysis")
    
    def _user_behavior_analysis(self, df):
        """User behavior analysis"""
        st.subheader("👤 USER BEHAVIOR ANALYSIS")
        
        # Find user columns
        user_cols = [col for col in df.columns if 'user' in col.lower()]
        
        if user_cols:
            selected_col = st.selectbox("Select User Column", user_cols)
            
            # User activity over time
            if 'timestamp' in df.columns:
                try:
                    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
                    user_activity = df.groupby([selected_col, 'hour']).size().reset_index()
                    user_activity.columns = ['User', 'Hour', 'Activity']
                    
                    # Select top users
                    top_users = df[selected_col].value_counts().head(5).index.tolist()
                    filtered_activity = user_activity[user_activity['User'].isin(top_users)]
                    
                    fig = px.line(filtered_activity, x='Hour', y='Activity', color='User',
                                title="User Activity by Hour",
                                markers=True)
                    st.plotly_chart(fig, use_container_width=True)
                except:
                    st.info("Could not analyze temporal patterns")
            
            # User statistics
            user_stats = df[selected_col].value_counts().reset_index()
            user_stats.columns = ['User', 'Activity Count']
            st.dataframe(user_stats.head(10), hide_index=True, use_container_width=True)
        else:
            st.info("No user columns found for analysis")
    
    def _threat_hunting_analysis(self, df):
        """Threat hunting analysis"""
        st.subheader("🔍 THREAT HUNTING")
        
        # Suspicious patterns
        st.write("### 🚨 Suspicious Activity Detection")
        
        suspicious_patterns = []
        
        # Check for suspicious process names
        suspicious_processes = ['powershell', 'cmd', 'wmic', 'schtasks', 'regsvr32']
        if any(col.lower().startswith('process') for col in df.columns):
            process_col = [col for col in df.columns if col.lower().startswith('process')][0]
            for process in suspicious_processes:
                matches = df[df[process_col].str.contains(process, case=False, na=False)]
                if len(matches) > 0:
                    suspicious_patterns.append(f"Found {len(matches)} instances of '{process}'")
        
        # Check for high port numbers
        port_cols = [col for col in df.columns if 'port' in col.lower()]
        if port_cols:
            port_col = port_cols[0]
            high_ports = df[pd.to_numeric(df[port_col], errors='coerce') > 1024]
            if len(high_ports) > 0:
                suspicious_patterns.append(f"Found {len(high_ports)} connections to high ports (>1024)")
        
        # Display findings
        if suspicious_patterns:
            for pattern in suspicious_patterns:
                st.warning(pattern)
            
            # Detailed analysis
            with st.expander("📊 Detailed Analysis"):
                st.write("**Suspicious Process Analysis**")
                # Add detailed analysis here
        else:
            st.success("✅ No suspicious patterns detected")
    
    def create_reports_tab(self):
        """Create comprehensive report generation tab"""
        st.header("📋 ADVANCED REPORT GENERATION")
        
        # Report Templates
        st.subheader("📄 REPORT TEMPLATES")
        
        templates = st.columns(3)
        
        with templates[0]:
            if st.button("🚨 Executive Summary", use_container_width=True):
                st.session_state.report_type = "executive"
                st.rerun()
        
        with templates[1]:
            if st.button("🔍 Detailed Analysis", use_container_width=True):
                st.session_state.report_type = "detailed"
                st.rerun()
        
        with templates[2]:
            if st.button("📊 Compliance Report", use_container_width=True):
                st.session_state.report_type = "compliance"
                st.rerun()
        
        # Report Configuration
        st.subheader("⚙️ REPORT CONFIGURATION")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_title = st.text_input(
                "Report Title",
                value="Threat Intelligence Report",
                help="Enter a title for your report"
            )
            
            report_period = st.selectbox(
                "Report Period",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "Custom Range"],
                help="Select the time period for the report"
            )
            
            if report_period == "Custom Range":
                start_date = st.date_input("Start Date")
                end_date = st.date_input("End Date")
        
        with col2:
            report_format = st.selectbox(
                "Report Format",
                ["HTML", "Excel"],
                help="Select output format"
            )
            
            include_sections = st.multiselect(
                "Include Sections",
                ["Executive Summary", "Threat Analysis", "Risk Assessment", 
                 "Recommendations", "Appendix", "Charts & Graphs"],
                default=["Executive Summary", "Threat Analysis", "Recommendations"],
                help="Select sections to include in the report"
            )
        
        # Advanced Options
        with st.expander("🔧 ADVANCED OPTIONS"):
            col3, col4 = st.columns(2)
            
            with col3:
                confidentiality = st.selectbox(
                    "Confidentiality Level",
                    ["Internal Use", "Confidential", "Restricted"],
                    help="Set report confidentiality level"
                )
                
                auto_refresh = st.checkbox(
                    "Enable Auto-Refresh",
                    help="Automatically update report data"
                )
            
            with col4:
                branding = st.checkbox(
                    "Include Company Branding",
                    value=True,
                    help="Add company logo and branding"
                )
                
                timestamp = st.checkbox(
                    "Include Timestamp",
                    value=True,
                    help="Add generation timestamp"
                )
        
        # Generate Report Button
        if st.button("🚀 GENERATE REPORT", use_container_width=True, type="primary"):
            with st.spinner("Generating report..."):
                # Prepare report data
                df = st.session_state.threat_data
                
                report_data = {
                    'title': report_title,
                    'generated_at': datetime.now().isoformat(),
                    'period': report_period,
                    'confidentiality': confidentiality,
                    'sections': include_sections,
                    'metrics': [
                        {'label': 'Total Threats', 'value': len(df)},
                        {'label': 'Critical Threats', 'value': len(df[df['severity'] == 'Critical'])},
                        {'label': 'Average Risk Score', 'value': f"{df['risk_score'].mean():.1f}"},
                        {'label': 'Active Investigations', 'value': len(df[df['status'] == 'Investigating'])}
                    ],
                    'threats': df.sort_values('risk_score', ascending=False).head(50).to_dict('records'),
                    'recommendations': [
                        "Immediate review of all critical threats",
                        "Enhanced monitoring for high-risk departments",
                        "Security awareness training for affected users",
                        "Implementation of additional security controls",
                        "Regular threat hunting exercises"
                    ],
                    'analysis': {
                        'top_users': df['user'].value_counts().head(10).to_dict(),
                        'top_departments': df['department'].value_counts().head(5).to_dict(),
                        'threat_types': df['action'].value_counts().head(8).to_dict()
                    }
                }
                
                # Generate based on format
                if report_format == "HTML":
                    html_report = generate_html_report(report_data, report_title)
                    
                    # Show download button
                    st.markdown("---")
                    st.subheader("📥 Download Report")
                    
                    col_d1, col_d2 = st.columns(2)
                    with col_d1:
                        st.download_button(
                            label="📥 Download HTML Report",
                            data=html_report,
                            file_name=f"{report_title.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html",
                            use_container_width=True
                        )
                    with col_d2:
                        # Preview
                        if st.button("👁️ Preview", use_container_width=True):
                            with st.expander("Report Preview", expanded=True):
                                st.markdown(html_report, unsafe_allow_html=True)
                
                elif report_format == "Excel":
                    try:
                        excel_file = generate_excel_report(report_data)
                        
                        if excel_file:
                            st.markdown("---")
                            st.subheader("📥 Download Report")
                            
                            col_d1, col_d2 = st.columns(2)
                            with col_d1:
                                with open(excel_file, 'rb') as f:
                                    st.download_button(
                                        label="📥 Download Excel Report",
                                        data=f,
                                        file_name=f"{report_title.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                        use_container_width=True
                                    )
                            with col_d2:
                                # Show preview of data
                                if st.button("📊 Preview Data", use_container_width=True):
                                    with st.expander("Data Preview", expanded=True):
                                        st.dataframe(df.head(20))
                            
                            # Clean up temp file
                            try:
                                os.unlink(excel_file)
                            except:
                                pass
                    
                    except Exception as e:
                        st.error(f"❌ Excel generation failed: {str(e)}")
                
                # Add to recent reports
                st.session_state.recent_reports.append({
                    'title': report_title,
                    'format': report_format,
                    'timestamp': datetime.now().isoformat(),
                    'size': 'Medium'
                })
                
                st.success("✅ Report generated successfully!")
        
        # Recent Reports
        if st.session_state.recent_reports:
            st.markdown("---")
            st.subheader("📜 RECENT REPORTS")
            
            for i, report in enumerate(st.session_state.recent_reports[-5:]):  # Show last 5 reports
                col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                with col1:
                    st.write(f"**{report['title']}**")
                    st.caption(f"Generated: {report['timestamp'].split('T')[0]} | Format: {report['format']}")
                with col2:
                    format_icon = "🌐" if report['format'] == "HTML" else "📊"
                    st.write(format_icon)
                with col3:
                    if st.button("📋", key=f"view_{i}", help="View Report Details"):
                        st.session_state.selected_report = report
                with col4:
                    if st.button("🗑️", key=f"delete_{i}", help="Delete Report"):
                        st.session_state.recent_reports.remove(report)
                        st.rerun()
        
        # Report Analytics
        with st.expander("📈 REPORT ANALYTICS"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write("**Report Statistics**")
                if st.session_state.recent_reports:
                    stats = {
                        "Total Reports": len(st.session_state.recent_reports),
                        "Most Used Format": max(set([r['format'] for r in st.session_state.recent_reports]), 
                                               key=[r['format'] for r in st.session_state.recent_reports].count) 
                                               if st.session_state.recent_reports else "N/A",
                        "Avg Report Size": "Medium"
                    }
                    
                    for key, value in stats.items():
                        st.metric(key, value)
                else:
                    st.info("No reports generated yet")
            
            with col2:
                st.write("**Quick Actions**")
                action_cols = st.columns(2)
                with action_cols[0]:
                    if st.button("🔄 Refresh", use_container_width=True):
                        st.rerun()
                with action_cols[1]:
                    if st.button("🗑️ Clear All", use_container_width=True):
                        st.session_state.recent_reports = []
                        st.rerun()
    
    def create_configuration_tab(self):
        """Create enhanced configuration tab"""
        st.header("⚙️ SYSTEM CONFIGURATION")
        
        # Configuration Tabs
        config_tabs = st.tabs(["🔐 Security", "📊 Dashboard", "🔔 Notifications", "🗄️ Database", "👥 Users"])
        
        with config_tabs[0]:
            st.subheader("🔐 SECURITY SETTINGS")
            
            col1, col2 = st.columns(2)
            
            with col1:
                auth_method = st.selectbox(
                    "Authentication Method",
                    ["Local", "LDAP", "Active Directory", "SSO"],
                    help="Select authentication method"
                )
                
                session_timeout = st.slider(
                    "Session Timeout (minutes)",
                    15, 240, 60,
                    help="Set session timeout duration"
                )
                
                enable_mfa = st.checkbox(
                    "Enable Multi-Factor Authentication",
                    value=True,
                    help="Require MFA for login"
                )
            
            with col2:
                password_policy = st.selectbox(
                    "Password Policy",
                    ["Basic", "Standard", "Strict", "Custom"],
                    help="Set password complexity requirements"
                )
                
                if password_policy == "Custom":
                    min_length = st.number_input("Minimum Length", 8, 20, 12)
                    require_special = st.checkbox("Require Special Characters", True)
                    require_numbers = st.checkbox("Require Numbers", True)
                    require_uppercase = st.checkbox("Require Uppercase", True)
                
                audit_logging = st.checkbox(
                    "Enable Audit Logging",
                    value=True,
                    help="Log all configuration changes"
                )
        
        with config_tabs[1]:
            st.subheader("📊 DASHBOARD SETTINGS")
            
            col1, col2 = st.columns(2)
            
            with col1:
                theme = st.selectbox(
                    "Theme",
                    ["Cyber (Default)", "Dark", "Light", "High Contrast"],
                    help="Select dashboard theme"
                )
                
                refresh_rate = st.selectbox(
                    "Auto-Refresh Rate",
                    ["None", "30 seconds", "1 minute", "5 minutes", "15 minutes"],
                    help="Set automatic data refresh rate"
                )
                
                default_view = st.selectbox(
                    "Default View",
                    ["Dashboard", "Threat Analysis", "Reports"],
                    help="Set default landing page"
                )
            
            with col2:
                chart_quality = st.select_slider(
                    "Chart Quality",
                    options=["Low", "Medium", "High", "Ultra"],
                    value="High",
                    help="Set chart rendering quality"
                )
                
                data_points = st.slider(
                    "Max Data Points",
                    100, 10000, 1000,
                    help="Maximum data points to display"
                )
                
                tooltips = st.checkbox(
                    "Show Tooltips",
                    value=True,
                    help="Display tooltips on hover"
                )
        
        with config_tabs[2]:
            st.subheader("🔔 NOTIFICATION SETTINGS")
            
            col1, col2 = st.columns(2)
            
            with col1:
                email_notifications = st.checkbox(
                    "Email Notifications",
                    value=True,
                    help="Send notifications via email"
                )
                
                if email_notifications:
                    email_frequency = st.selectbox(
                        "Email Frequency",
                        ["Immediate", "Hourly Digest", "Daily Digest", "Weekly Digest"]
                    )
                
                slack_integration = st.checkbox(
                    "Slack Integration",
                    value=False,
                    help="Send notifications to Slack"
                )
            
            with col2:
                alert_levels = st.multiselect(
                    "Alert Levels to Notify",
                    ["Critical", "High", "Medium", "Low"],
                    default=["Critical", "High"],
                    help="Select which alert levels trigger notifications"
                )
                
                push_notifications = st.checkbox(
                    "Push Notifications",
                    value=True,
                    help="Enable browser push notifications"
                )
        
        with config_tabs[3]:
            st.subheader("🗄️ DATABASE CONFIGURATION")
            
            db_enabled = st.toggle(
                "Enable PostgreSQL Storage",
                value=DB_CONFIG["enabled"],
                help="Store threats in PostgreSQL database"
            )
            
            if db_enabled:
                col1, col2 = st.columns(2)
                
                with col1:
                    connection_string = st.text_input(
                        "Connection String",
                        value=DB_CONFIG["connection_string"],
                        help="PostgreSQL connection string"
                    )
                    
                    backup_frequency = st.selectbox(
                        "Backup Frequency",
                        ["Daily", "Weekly", "Monthly", "Manual"],
                        help="Set database backup schedule"
                    )
                
                with col2:
                    retention_days = st.number_input(
                        "Data Retention (days)",
                        30, 365*5, 365,
                        help="Days to retain data before archiving"
                    )
                    
                    max_connections = st.number_input(
                        "Max Connections",
                        5, 100, 20,
                        help="Maximum database connections"
                    )
                
                # Test Connection
                if st.button("🔗 Test Database Connection", use_container_width=True):
                    try:
                        import psycopg2
                        conn = psycopg2.connect(connection_string)
                        cursor = conn.cursor()
                        cursor.execute("SELECT version();")
                        version = cursor.fetchone()[0]
                        conn.close()
                        st.success(f"✅ Connected successfully!\nPostgreSQL Version: {version}")
                    except Exception as e:
                        st.error(f"❌ Connection failed: {str(e)[:100]}")
        
        with config_tabs[4]:
            st.subheader("👥 USER MANAGEMENT")
            
            # Current Users
            st.write("**Current Users**")
            users = [
                {"name": "soc_analyst", "role": "Security Analyst", "status": "Active"},
                {"name": "admin", "role": "Administrator", "status": "Active"},
                {"name": "auditor", "role": "Auditor", "status": "Inactive"}
            ]
            
            for user in users:
                col1, col2, col3 = st.columns([3, 2, 1])
                with col1:
                    st.write(f"👤 {user['name']}")
                with col2:
                    st.caption(f"{user['role']} | {user['status']}")
                with col3:
                    st.button("✏️", key=f"edit_{user['name']}", help="Edit User")
            
            # Add New User
            with st.expander("➕ ADD NEW USER"):
                new_user_cols = st.columns(2)
                
                with new_user_cols[0]:
                    new_username = st.text_input("Username")
                    new_email = st.text_input("Email")
                    new_department = st.selectbox("Department", ENTERPRISE_CONFIG["departments"])
                
                with new_user_cols[1]:
                    new_role = st.selectbox("Role", ["Viewer", "Analyst", "Administrator", "Auditor"])
                    new_status = st.selectbox("Status", ["Active", "Inactive", "Pending"])
                    send_invite = st.checkbox("Send Invitation Email")
                
                if st.button("Create User", use_container_width=True):
                    st.success(f"User '{new_username}' created successfully!")
        
        # Save Configuration
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("💾 Save Configuration", use_container_width=True, type="primary"):
                # Update global DB_CONFIG
                import sys
                current_module = sys.modules[__name__]
                current_module.DB_CONFIG["enabled"] = db_enabled
                if db_enabled:
                    current_module.DB_CONFIG["connection_string"] = connection_string
                st.success("✅ Configuration saved successfully!")
                
                # Add notification
                st.session_state.notifications.append({
                    "id": len(st.session_state.notifications) + 1,
                    "type": "info",
                    "message": "Configuration updated successfully",
                    "time": "Just now"
                })
        
        with col2:
            if st.button("🔄 Reset to Defaults", use_container_width=True, type="secondary"):
                st.session_state.notifications.append({
                    "id": len(st.session_state.notifications) + 1,
                    "type": "warning",
                    "message": "Configuration reset to defaults",
                    "time": "Just now"
                })
                st.info("⚠️ Configuration reset to defaults")
    
    def run(self):
        """Main dashboard runner"""
        if not st.session_state.authenticated:
            st.session_state.authenticated = True
            st.rerun()
        
        self.create_header()
        self.create_sidebar()
        
        tab = st.session_state.get('current_tab', 'dashboard')
        
        if tab == "dashboard":
            self.create_dashboard_tab()
        elif tab == "analysis":
            self.create_threat_analysis_tab()
        elif tab == "sysmon":
            self.create_sysmon_tab()
        elif tab == "reports":
            self.create_reports_tab()
        elif tab == "config":
            self.create_configuration_tab()

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main application entry point"""
    # Initialize and run dashboard
    dashboard = InsiderThreatDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()
