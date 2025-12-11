# enterprise_security_dashboard.py - COMPLETE WORKING VERSION
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import warnings
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import json
import requests
from fpdf import FPDF
import base64
import os
import re
from elasticsearch import Elasticsearch, exceptions
import random
import redis
from urllib.parse import urljoin
import hashlib
import uuid
from typing import Dict, List, Optional
import io
import tempfile
import pickle
import csv
from io import StringIO
import zipfile
from pathlib import Path
import subprocess
import ipaddress

warnings.filterwarnings('ignore')

# ============================================
# ENTERPRISE CONFIGURATION
# ============================================

ENTERPRISE_CONFIG = {
    "company_name": "CYBER SECURITY OPS CENTER",
    "departments": ["SOC", "Threat Intel", "Incident Response", "Forensics", "Compliance", "Engineering", "Operations", "Management"],
    "alert_levels": {
        "Critical": {"min_score": 80, "color": "#DC2626"},
        "High": {"min_score": 60, "color": "#EA580C"},
        "Medium": {"min_score": 40, "color": "#F59E0B"},
        "Low": {"min_score": 0, "color": "#10B981"}
    },
    "compliance_frameworks": ["NIST CSF", "MITRE ATT&CK", "ISO 27001", "SOC 2", "PCI DSS", "GDPR"],
    
    # ELK Stack Configuration
    "elk_host": "http://localhost:9200",
    "elk_indices": ["threat-events-*", "user-activities-*", "system-logs-*", "firewall-*"],
    "kibana_url": "http://localhost:5601",
    
    # Admin Configuration
    "admin_email": "soc@cyberops.com",
    "support_email": "support@cyberops.com",
    
    # Data Configuration
    "sysmon_file": "uploaded_sysmon.csv",
    "data_retention_days": 90,
    
    # Security Settings
    "session_timeout_minutes": 30,
    "max_login_attempts": 5,
    "mfa_required": True
}

# ============================================
# PAGE CONFIGURATION
# ============================================

st.set_page_config(
    page_title="Cyber SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================
# CYBER THEME CSS STYLING
# ============================================

st.markdown("""
<style>
    /* Main Background - Cyber Theme */
    .stApp {
        background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
        color: #00ff41;
        font-family: 'Courier New', monospace;
    }
    
    /* Cyber Header */
    .cyber-header {
        background: linear-gradient(135deg, #0a0a0a 0%, #00ff41 150%);
        padding: 2.5rem;
        border-radius: 5px;
        color: #00ff41;
        text-align: center;
        margin-bottom: 2rem;
        border: 1px solid #00ff41;
        box-shadow: 0 0 25px rgba(0, 255, 65, 0.3);
        position: relative;
        overflow: hidden;
    }
    
    .cyber-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00ff41, transparent);
        animation: scanline 3s linear infinite;
    }
    
    @keyframes scanline {
        0% { left: -100%; }
        100% { left: 100%; }
    }
    
    /* Cyber Metrics Cards */
    .cyber-card {
        background: rgba(0, 0, 0, 0.7);
        padding: 1.5rem;
        border-radius: 8px;
        border: 1px solid #00ff41;
        color: #00ff41;
        margin: 0.5rem;
        transition: all 0.3s ease;
        position: relative;
        overflow: hidden;
    }
    
    .cyber-card::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(0, 255, 65, 0.1) 0%, transparent 70%);
        opacity: 0;
        transition: opacity 0.3s;
    }
    
    .cyber-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
        border-color: #00ff41;
    }
    
    .cyber-card:hover::before {
        opacity: 1;
    }
    
    .cyber-card h3 {
        color: #00ff41;
        font-size: 0.9rem;
        margin-bottom: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: bold;
    }
    
    .cyber-card h2 {
        color: #ffffff;
        font-size: 2rem;
        font-weight: 700;
        margin: 0.5rem 0;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    }
    
    /* Cyber Alert Cards */
    .alert-critical {
        border-color: #ff0033 !important;
        background: rgba(255, 0, 51, 0.1) !important;
    }
    
    .alert-high {
        border-color: #ff6600 !important;
        background: rgba(255, 102, 0, 0.1) !important;
    }
    
    .alert-medium {
        border-color: #ffcc00 !important;
        background: rgba(255, 204, 0, 0.1) !important;
    }
    
    .alert-low {
        border-color: #00ff41 !important;
        background: rgba(0, 255, 65, 0.1) !important;
    }
    
    /* Cyber Terminal Style */
    .terminal {
        background: rgba(0, 0, 0, 0.9);
        border: 1px solid #00ff41;
        border-radius: 5px;
        padding: 1rem;
        font-family: 'Courier New', monospace;
        color: #00ff41;
        height: 400px;
        overflow-y: auto;
        position: relative;
    }
    
    .terminal::before {
        content: '>>> ';
        color: #00ff41;
        font-weight: bold;
    }
    
    .terminal-line {
        margin: 5px 0;
        padding-left: 20px;
        position: relative;
    }
    
    .terminal-line::before {
        content: '$';
        position: absolute;
        left: 0;
        color: #00ff41;
    }
    
    /* Form Styling */
    .stForm {
        background: rgba(0, 0, 0, 0.7);
        padding: 1.5rem;
        border-radius: 5px;
        border: 1px solid #00ff41;
    }
    
    /* Button Styling - Cyber Theme */
    .stButton > button {
        background: linear-gradient(135deg, #00ff41 0%, #008f11 100%);
        color: #000000 !important;
        border: 1px solid #00ff41;
        border-radius: 3px;
        padding: 0.5rem 1.5rem;
        font-weight: bold;
        font-family: 'Courier New', monospace;
        transition: all 0.3s;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #00ff41 0%, #00cc33 100%);
        transform: translateY(-2px);
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.5);
        color: #000000 !important;
    }
    
    .danger-button {
        background: linear-gradient(135deg, #ff0033 0%, #cc0029 100%) !important;
        border-color: #ff0033 !important;
    }
    
    .success-button {
        background: linear-gradient(135deg, #00ff41 0%, #008f11 100%) !important;
        border-color: #00ff41 !important;
    }
    
    /* Table Styling */
    .dataframe {
        background-color: rgba(0, 0, 0, 0.7) !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
    }
    
    .dataframe th {
        background-color: rgba(0, 255, 65, 0.2) !important;
        color: #00ff41 !important;
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .dataframe tr:nth-child(even) {
        background-color: rgba(0, 255, 65, 0.05) !important;
    }
    
    .dataframe tr:nth-child(odd) {
        background-color: rgba(0, 0, 0, 0.7) !important;
    }
    
    /* Custom Scrollbar */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    
    ::-webkit-scrollbar-track {
        background: #0a0a0a;
    }
    
    ::-webkit-scrollbar-thumb {
        background: #00ff41;
        border-radius: 4px;
    }
    
    ::-webkit-scrollbar-thumb:hover {
        background: #00cc33;
    }
    
    /* Cyber Glitch Effect */
    .glitch {
        position: relative;
        animation: glitch 5s infinite;
    }
    
    @keyframes glitch {
        0% { text-shadow: 0.05em 0 0 #00ff41, -0.03em -0.04em 0 #ff0033; }
        2% { text-shadow: 0.05em 0 0 #00ff41, -0.03em -0.04em 0 #ff0033; }
        4% { text-shadow: -0.05em -0.025em 0 #00ff41, 0.025em 0.035em 0 #ff0033; }
        6% { text-shadow: -0.05em -0.025em 0 #00ff41, 0.025em 0.035em 0 #ff0033; }
        8% { text-shadow: 0.05em 0 0 #00ff41, -0.03em -0.04em 0 #ff0033; }
        10% { text-shadow: 0.05em 0 0 #00ff41, -0.03em -0.04em 0 #ff0033; }
        12% { text-shadow: -0.05em -0.025em 0 #00ff41, 0.025em 0.035em 0 #ff0033; }
        100% { text-shadow: -0.05em -0.025em 0 #00ff41, 0.025em 0.035em 0 #ff0033; }
    }
    
    /* Responsive adjustments */
    @media (max-width: 768px) {
        .cyber-card h2 {
            font-size: 1.5rem;
        }
        .cyber-header {
            padding: 1.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# ============================================
# ENTERPRISE ADMIN MANAGEMENT
# ============================================

class EnterpriseAdminManager:
    """Enterprise User and System Management"""
    
    def __init__(self):
        self.users_file = "enterprise_users.json"
        self.settings_file = "enterprise_settings.json"
        self.audit_log_file = "audit_log.json"
        self._load_data()
    
    def _load_data(self):
        """Load all admin data"""
        # Load users
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                self.users = json.load(f)
        else:
            self.users = self._create_default_users()
            self._save_users()
        
        # Load settings
        if os.path.exists(self.settings_file):
            with open(self.settings_file, 'r') as f:
                self.settings = json.load(f)
        else:
            self.settings = self._create_default_settings()
            self._save_settings()
    
    def _create_default_users(self):
        """Create default enterprise users"""
        return [
            {
                "id": "SOC001",
                "username": "soc_analyst",
                "email": "soc@cyberops.com",
                "password_hash": self._hash_password("Cyber@123"),
                "role": "SOC Analyst",
                "department": "SOC",
                "permissions": ["view", "analyze", "alert", "report", "investigate"],
                "status": "active",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "mfa_enabled": True,
                "session_timeout": 30
            },
            {
                "id": "THR001",
                "username": "threat_hunter",
                "email": "threat@cyberops.com",
                "password_hash": self._hash_password("Hunter@123"),
                "role": "Threat Hunter",
                "department": "Threat Intel",
                "permissions": ["view", "analyze", "alert", "report", "investigate", "hunt"],
                "status": "active",
                "created_at": datetime.now().isoformat(),
                "last_login": None,
                "mfa_enabled": True,
                "session_timeout": 30
            }
        ]
    
    def _create_default_settings(self):
        """Create default system settings"""
        return {
            "system": {
                "auto_refresh": True,
                "refresh_interval": 60,
                "data_retention_days": 90,
                "session_timeout": 30,
                "max_login_attempts": 5,
                "mfa_required": True
            },
            "alerts": {
                "email_enabled": True,
                "slack_enabled": False,
                "sms_enabled": False,
                "critical_threshold": 80,
                "high_threshold": 60
            },
            "elk": {
                "elk_host": "http://localhost:9200",
                "kibana_url": "http://localhost:5601",
                "indices": ["threat-events-*", "user-activities-*"],
                "auto_sync": True,
                "sync_interval": 300
            }
        }
    
    def _hash_password(self, password):
        """Hash password for storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _save_users(self):
        """Save users to file"""
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def _save_settings(self):
        """Save settings to file"""
        with open(self.settings_file, 'w') as f:
            json.dump(self.settings, f, indent=2)
    
    def _log_audit(self, action, user, details):
        """Log audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user": user,
            "details": details,
            "ip_address": "127.0.0.1"
        }
        
        logs = []
        if os.path.exists(self.audit_log_file):
            with open(self.audit_log_file, 'r') as f:
                logs = json.load(f)
        
        logs.append(log_entry)
        
        with open(self.audit_log_file, 'w') as f:
            json.dump(logs[-1000:], f, indent=2)
    
    def authenticate_user(self, username, password):
        """Authenticate user"""
        for user in self.users:
            if user["username"] == username and user["status"] == "active":
                if user["password_hash"] == self._hash_password(password):
                    user["last_login"] = datetime.now().isoformat()
                    self._save_users()
                    self._log_audit("LOGIN", username, "Successful login")
                    return {
                        "success": True,
                        "user": {
                            "id": user["id"],
                            "username": user["username"],
                            "email": user["email"],
                            "role": user["role"],
                            "permissions": user["permissions"],
                            "department": user.get("department", "")
                        }
                    }
        
        self._log_audit("LOGIN_FAILED", username, "Failed login attempt")
        return {"success": False, "message": "Invalid credentials"}
    
    def add_user(self, user_data, admin_user):
        """Add new enterprise user"""
        user_id = f"USR{len(self.users)+1:03d}"
        
        new_user = {
            "id": user_id,
            "username": user_data["username"],
            "email": user_data["email"],
            "password_hash": self._hash_password(user_data["password"]),
            "role": user_data["role"],
            "department": user_data["department"],
            "permissions": user_data.get("permissions", ["view"]),
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "mfa_enabled": user_data.get("mfa_enabled", True),
            "session_timeout": user_data.get("session_timeout", 30)
        }
        
        self.users.append(new_user)
        self._save_users()
        self._log_audit("USER_ADDED", admin_user, 
                       f"Added user {user_data['username']} with role {user_data['role']}")
        return user_id
    
    def update_user(self, user_id, updates, admin_user):
        """Update user information"""
        for user in self.users:
            if user["id"] == user_id:
                user.update(updates)
                user["updated_at"] = datetime.now().isoformat()
                self._save_users()
                self._log_audit("USER_UPDATED", admin_user, 
                              f"Updated user {user['username']}: {list(updates.keys())}")
                return True
        return False
    
    def delete_user(self, user_id, admin_user):
        """Delete user (soft delete)"""
        for user in self.users:
            if user["id"] == user_id and user["username"] != "soc_analyst":
                user["status"] = "deleted"
                user["deleted_at"] = datetime.now().isoformat()
                self._save_users()
                self._log_audit("USER_DELETED", admin_user, 
                              f"Deleted user {user['username']}")
                return True
        return False
    
    def get_user_roles(self):
        """Get available user roles"""
        return [
            "SOC Analyst",
            "Threat Hunter", 
            "Incident Responder",
            "Forensics Analyst",
            "Compliance Officer",
            "Security Engineer",
            "Viewer"
        ]
    
    def get_permissions_by_role(self, role):
        """Get permissions for a role"""
        permissions = {
            "SOC Analyst": ["view", "analyze", "alert", "report", "investigate"],
            "Threat Hunter": ["view", "analyze", "alert", "report", "investigate", "hunt"],
            "Incident Responder": ["view", "analyze", "alert", "report", "investigate", "respond"],
            "Forensics Analyst": ["view", "analyze", "report", "investigate", "forensics"],
            "Compliance Officer": ["view", "report", "audit", "export"],
            "Security Engineer": ["view", "analyze", "alert", "report", "investigate", "engineer"],
            "Viewer": ["view"]
        }
        return permissions.get(role, ["view"])
    
    def get_audit_logs(self, limit=50):
        """Get recent audit logs"""
        if os.path.exists(self.audit_log_file):
            with open(self.audit_log_file, 'r') as f:
                logs = json.load(f)
            return logs[-limit:]
        return []
    
    def update_settings(self, section, updates, admin_user):
        """Update system settings"""
        if section in self.settings:
            self.settings[section].update(updates)
            self._save_settings()
            self._log_audit("SETTINGS_UPDATED", admin_user, 
                          f"Updated {section} settings: {list(updates.keys())}")
            return True
        return False

# ============================================
# SYSMON DATA PROCESSOR
# ============================================

class SysmonDataProcessor:
    """Process Sysmon CSV data"""
    
    def __init__(self):
        self.sysmon_data = None
        self.processed_data = None
    
    def load_sysmon_data(self, file_path):
        """Load and parse Sysmon CSV data"""
        try:
            self.sysmon_data = pd.read_csv(file_path)
            st.success(f"✅ Loaded {len(self.sysmon_data)} Sysmon events")
            return True
        except Exception as e:
            st.error(f"❌ Failed to load Sysmon data: {str(e)}")
            return False
    
    def parse_sysmon_message(self, message):
        """Parse Sysmon message field into structured data"""
        parsed = {}
        lines = message.split('\n')
        
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                parsed[key.strip()] = value.strip()
        
        return parsed
    
    def process_sysmon_data(self):
        """Process raw Sysmon data"""
        if self.sysmon_data is None or self.sysmon_data.empty:
            return None
        
        processed_records = []
        
        for _, row in self.sysmon_data.iterrows():
            try:
                parsed_message = self.parse_sysmon_message(row['Message'])
                
                # Extract event type from Message
                event_type = "Unknown"
                if "Network connection detected" in row['Message']:
                    event_type = "Network Connection"
                elif "Process terminated" in row['Message']:
                    event_type = "Process Termination"
                elif "Process created" in row['Message']:
                    event_type = "Process Creation"
                elif "Sysmon service state changed" in row['Message']:
                    event_type = "Service Change"
                
                # Calculate risk score based on event type and details
                risk_score = self._calculate_risk_score(event_type, parsed_message)
                
                record = {
                    "timestamp": row['TimeCreated'],
                    "event_id": row['Id'],
                    "level": row['LevelDisplayName'],
                    "event_type": event_type,
                    "parsed_data": parsed_message,
                    "risk_score": risk_score,
                    "severity": self._get_severity(risk_score),
                    "source_ip": parsed_message.get('SourceIp', 'Unknown'),
                    "destination_ip": parsed_message.get('DestinationIp', 'Unknown'),
                    "process_name": parsed_message.get('Image', 'Unknown').split('\\')[-1],
                    "user": parsed_message.get('User', 'Unknown'),
                    "protocol": parsed_message.get('Protocol', 'N/A'),
                    "port": parsed_message.get('DestinationPort', 'N/A')
                }
                
                processed_records.append(record)
            except Exception as e:
                st.warning(f"Failed to parse row: {str(e)}")
                continue
        
        self.processed_data = pd.DataFrame(processed_records)
        return self.processed_data
    
    def _calculate_risk_score(self, event_type, parsed_data):
        """Calculate risk score for an event"""
        base_score = 10
        
        # Event type modifiers
        if event_type == "Network Connection":
            base_score += 20
            # Check for suspicious destinations
            dest_ip = parsed_data.get('DestinationIp', '')
            if dest_ip:
                if self._is_suspicious_ip(dest_ip):
                    base_score += 30
                if parsed_data.get('DestinationPort') == '443':
                    base_score += 10  # HTTPS traffic
        
        elif event_type == "Process Termination":
            base_score += 5
        
        # User context modifiers
        user = parsed_data.get('User', '')
        if 'SYSTEM' in user or 'NETWORK SERVICE' in user:
            base_score += 15
        
        # Process name modifiers
        process = parsed_data.get('Image', '')
        suspicious_processes = ['powershell', 'cmd', 'wmic', 'regsvr32', 'rundll32']
        if any(sp in process.lower() for sp in suspicious_processes):
            base_score += 25
        
        return min(100, base_score)
    
    def _is_suspicious_ip(self, ip):
        """Check if IP is suspicious"""
        try:
            # Check for private IPs
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return False
            
            # Check for known suspicious IP ranges (example)
            suspicious_ranges = [
                "23.38.", "23.47.", "23.205.",  # Akamai
                "13.107.", "20.189.", "20.207.", # Microsoft
                "140.82.", "142.250."           # GitHub/Google
            ]
            
            return any(ip.startswith(prefix) for prefix in suspicious_ranges)
        except:
            return False
    
    def _get_severity(self, risk_score):
        """Convert risk score to severity level"""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        else:
            return "Low"
    
    def get_statistics(self):
        """Get statistics from processed data"""
        if self.processed_data is None or self.processed_data.empty:
            return None
        
        stats = {
            "total_events": len(self.processed_data),
            "event_types": self.processed_data['event_type'].value_counts().to_dict(),
            "severity_distribution": self.processed_data['severity'].value_counts().to_dict(),
            "top_source_ips": self.processed_data['source_ip'].value_counts().head(10).to_dict(),
            "top_dest_ips": self.processed_data['destination_ip'].value_counts().head(10).to_dict(),
            "top_processes": self.processed_data['process_name'].value_counts().head(10).to_dict(),
            "avg_risk_score": self.processed_data['risk_score'].mean(),
            "high_risk_events": len(self.processed_data[self.processed_data['risk_score'] >= 70]),
            "timeline": self.processed_data.groupby(
                pd.to_datetime(self.processed_data['timestamp']).dt.floor('H')
            ).size().to_dict()
        }
        
        return stats
    
    def get_top_threats(self, limit=10):
        """Get top threats by risk score"""
        if self.processed_data is None or self.processed_data.empty:
            return pd.DataFrame()
        
        return self.processed_data.sort_values('risk_score', ascending=False).head(limit)

# ============================================
# SOC TERMINAL
# ============================================

class SOC_Terminal:
    """Cyber SOC Terminal Emulator"""
    
    def __init__(self):
        self.commands = {
            "help": self._cmd_help,
            "clear": self._cmd_clear,
            "scan": self._cmd_scan,
            "investigate": self._cmd_investigate,
            "threats": self._cmd_threats,
            "whoami": self._cmd_whoami,
            "system": self._cmd_system,
            "netstat": self._cmd_netstat,
            "ps": self._cmd_process_list,
            "firewall": self._cmd_firewall,
            "log": self._cmd_log_analysis,
            "mitre": self._cmd_mitre_search,
            "ioc": self._cmd_ioc_check,
            "export": self._cmd_export_data
        }
        
        self.terminal_output = []
        self._initialize_terminal()
    
    def _initialize_terminal(self):
        """Initialize terminal with welcome message"""
        self.terminal_output = [
            "CYBER SOC TERMINAL v2.0",
            "Initializing security protocols...",
            "Loading threat intelligence feeds...",
            "Connecting to SIEM... [OK]",
            "Authenticating user... [OK]",
            "",
            "Welcome to Cyber SOC Command Interface",
            "Type 'help' for available commands",
            "----------------------------------------"
        ]
    
    def execute_command(self, command):
        """Execute terminal command"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return
        
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:] if len(cmd_parts) > 1 else []
        
        if cmd in self.commands:
            self.terminal_output.append(f"$ {command}")
            result = self.commands[cmd](args)
            if result:
                self.terminal_output.append(result)
        else:
            self.terminal_output.append(f"$ {command}")
            self.terminal_output.append(f"Command not found: {cmd}")
            self.terminal_output.append("Type 'help' for available commands")
        
        # Keep only last 50 lines
        if len(self.terminal_output) > 50:
            self.terminal_output = self.terminal_output[-50:]
    
    def _cmd_help(self, args):
        """Help command"""
        return """
Available Commands:
  help                   - Show this help message
  clear                  - Clear terminal screen
  scan <ip>              - Scan IP address for threats
  investigate <hash>     - Investigate file hash
  threats                - Show recent threats
  whoami                 - Show current user info
  system                 - Show system status
  netstat                - Show network connections
  ps                     - List running processes
  firewall               - Check firewall status
  log                    - Analyze security logs
  mitre <technique>      - Search MITRE ATT&CK
  ioc <type> <value>     - Check IOC
  export <data>          - Export data
        """
    
    def _cmd_clear(self, args):
        """Clear command"""
        self.terminal_output = ["Terminal cleared."]
        return None
    
    def _cmd_scan(self, args):
        """Scan IP address"""
        if not args:
            return "Usage: scan <ip_address>"
        
        ip = args[0]
        return f"""
Scanning {ip}...
[+] Port 22: SSH - Open
[+] Port 80: HTTP - Open (Apache/2.4.41)
[+] Port 443: HTTPS - Open (Nginx/1.18.0)
[+] Port 3389: RDP - Open
[!] Vulnerability detected: CVE-2023-12345
[!] Suspicious activity detected
Scan complete. Found 2 security issues.
        """
    
    def _cmd_threats(self, args):
        """Show recent threats"""
        return """
Recent Threats:
1. [CRITICAL] Data exfiltration detected - User: jsmith - Time: 10:45
2. [HIGH] Unauthorized access attempt - IP: 192.168.1.100 - Time: 10:30
3. [MEDIUM] Suspicious process execution - Process: powershell.exe - Time: 10:15
4. [LOW] Multiple failed logins - User: admin - Time: 09:45
        """
    
    def _cmd_whoami(self, args):
        """Show user info"""
        return """
User Information:
Username: soc_analyst
Role: SOC Analyst Level 2
Department: Security Operations Center
Clearance: Top Secret
Last Login: 2024-01-15 09:30:45
Session: Active (45 minutes)
        """
    
    def _cmd_system(self, args):
        """Show system status"""
        return """
System Status:
CPU Usage: 45%
Memory Usage: 68%
Disk Usage: 42%
Network: 1.2 Gbps incoming, 0.8 Gbps outgoing
Threats Detected: 12
Alerts Active: 3
Last Scan: 5 minutes ago
        """
    
    def _cmd_netstat(self, args):
        """Show network connections"""
        return """
Active Network Connections:
Proto  Local Address          Foreign Address        State
TCP    192.168.1.10:443       52.168.117.175:443    ESTABLISHED
TCP    192.168.1.10:80        23.38.59.250:80       ESTABLISHED
TCP    192.168.1.10:22        10.0.0.5:22           ESTABLISHED
UDP    192.168.1.10:53        192.168.1.1:53        LISTENING
        """
    
    def _cmd_process_list(self, args):
        """List running processes"""
        return """
Running Processes (Security Related):
PID    Name                     User              CPU%  Memory
2424   svchost.exe              SYSTEM            2.1%  45MB
53460  Code.exe                 DELL              15.2% 210MB
25820  chrome.exe               DELL              8.5%  185MB
9556   Dell.Customer.Connect... SYSTEM            1.2%  32MB
11592  svchost.exe              SYSTEM            1.8%  38MB
        """
    
    def _cmd_firewall(self, args):
        """Check firewall status"""
        return """
Firewall Status:
Status: Active
Rules: 245 active rules
Blocked Today: 128 attempts
Last Incident: 15 minutes ago
Threat Prevention: Enabled
Logging: Enabled
        """
    
    def _cmd_log_analysis(self, args):
        """Analyze security logs"""
        return """
Security Log Analysis:
Time Range: Last 24 hours
Total Events: 12,458
Critical Events: 8
Failed Logins: 42
Suspicious Activity: 15
Pattern Detected: Multiple RDP attempts from same IP
Recommendation: Block IP 192.168.1.200
        """
    
    def _cmd_mitre_search(self, args):
        """Search MITRE ATT&CK"""
        if not args:
            return "Usage: mitre <technique_id>"
        
        technique = args[0].upper()
        return f"""
MITRE ATT&CK Search: {technique}
Technique: Initial Access - T1190
Description: Exploit Public-Facing Application
Detection: Monitor for unusual outbound traffic
Prevention: Keep applications patched
Related Techniques: T1133, T1566, T1195
        """
    
    def _cmd_ioc_check(self, args):
        """Check IOC"""
        if len(args) < 2:
            return "Usage: ioc <type> <value>"
        
        ioc_type, value = args[0], args[1]
        return f"""
IOC Check:
Type: {ioc_type}
Value: {value}
Status: NOT FOUND in threat intelligence
Last Seen: N/A
Confidence: Low
        """
    
    def _cmd_export_data(self, args):
        """Export data"""
        if not args:
            return "Usage: export <threats|logs|network>"
        
        data_type = args[0]
        return f"""
Exporting {data_type} data...
Format: JSON
Size: 2.4 MB
Status: Export complete
Location: /exports/{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json
        """
    
    def _cmd_investigate(self, args):
        """Investigate file hash"""
        if not args:
            return "Usage: investigate <file_hash>"
        
        file_hash = args[0]
        return f"""
Investigation Report - Hash: {file_hash}
File Type: Executable (PE32)
Malware Family: Emotet
First Seen: 2024-01-10
Detection Rate: 45/60 AV engines
Behavior: Downloads additional payloads
Associated IPs: 192.168.1.100, 10.0.0.15
Recommendation: Quarantine and investigate
        """
    
    def get_output(self):
        """Get terminal output"""
        return "\n".join(self.terminal_output)

# ============================================
# ELK STACK MANAGER
# ============================================

class ELKStackManager:
    """ELK Stack Integration and Management"""
    
    def __init__(self):
        self.es = None
        self.kibana_available = False
        self._connect_to_elk()
    
    def _connect_to_elk(self):
        """Connect to ELK Stack"""
        try:
            self.es = Elasticsearch(
                [ENTERPRISE_CONFIG["elk_host"]],
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )
            
            if self.es.ping():
                st.session_state['elk_connected'] = True
                try:
                    response = requests.get(ENTERPRISE_CONFIG["kibana_url"], timeout=5)
                    if response.status_code == 200:
                        self.kibana_available = True
                        st.session_state['kibana_available'] = True
                except:
                    self.kibana_available = False
                    st.session_state['kibana_available'] = False
            else:
                st.session_state['elk_connected'] = False
                st.session_state['kibana_available'] = False
                
        except Exception as e:
            st.session_state['elk_connected'] = False
            st.session_state['kibana_available'] = False
    
    def get_elk_status(self):
        """Get ELK Stack status"""
        status = {
            "elasticsearch": "Connected" if st.session_state.get('elk_connected') else "Disconnected",
            "kibana": "Available" if st.session_state.get('kibana_available') else "Unavailable",
            "timestamp": datetime.now().isoformat()
        }
        
        if st.session_state.get('elk_connected'):
            try:
                health = self.es.cluster.health()
                status.update({
                    "cluster_name": health.get('cluster_name', 'Unknown'),
                    "status": health.get('status', 'Unknown'),
                    "node_count": health.get('number_of_nodes', 0),
                    "indices": self.get_indices_count()
                })
            except:
                pass
        
        return status
    
    def get_indices_count(self):
        """Get count of indices"""
        try:
            indices = self.es.indices.get_alias(index="*")
            return len(indices)
        except:
            return 0

# ============================================
# ENTERPRISE DASHBOARD
# ============================================

class EnterpriseSecurityDashboard:
    """Main Enterprise Dashboard"""
    
    def __init__(self):
        self.admin_manager = EnterpriseAdminManager()
        self.elk_manager = ELKStackManager()
        self.sysmon_processor = SysmonDataProcessor()
        self.soc_terminal = SOC_Terminal()
        
        # Initialize session state
        if 'authenticated' not in st.session_state:
            st.session_state.authenticated = False
        if 'current_user' not in st.session_state:
            st.session_state.current_user = None
        if 'elk_connected' not in st.session_state:
            st.session_state.elk_connected = False
        if 'kibana_available' not in st.session_state:
            st.session_state.kibana_available = False
        if 'sysmon_loaded' not in st.session_state:
            st.session_state.sysmon_loaded = False
        if 'terminal_command' not in st.session_state:
            st.session_state.terminal_command = ""
    
    def create_login_screen(self):
        """Create cyber login screen"""
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.markdown("""
            <div class="cyber-header glitch">
                <h1>🛡️ CYBER SECURITY OPS CENTER</h1>
                <p>Security Operations Command Interface</p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("login_form"):
                st.subheader("🔐 ACCESS CONTROL")
                
                username = st.text_input("Username", placeholder="Enter credentials")
                password = st.text_input("Password", type="password", placeholder="Authentication required")
                
                col_a, col_b = st.columns(2)
                with col_a:
                    login_button = st.form_submit_button("🔓 AUTHENTICATE", use_container_width=True)
                with col_b:
                    demo_button = st.form_submit_button("👁️ TEST MODE", use_container_width=True)
                
                if login_button:
                    if username and password:
                        result = self.admin_manager.authenticate_user(username, password)
                        if result["success"]:
                            st.session_state.authenticated = True
                            st.session_state.current_user = result["user"]
                            st.success("✅ Authentication successful!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Access denied")
                    else:
                        st.warning("⚠️ Credentials required")
                
                if demo_button:
                    st.session_state.authenticated = True
                    st.session_state.current_user = {
                        "id": "DEMO001",
                        "username": "demo_operator",
                        "email": "demo@cyberops.com",
                        "role": "SOC Analyst",
                        "permissions": ["view", "analyze", "alert"],
                        "department": "SOC"
                    }
                    st.info("👁️ Entering test mode...")
                    time.sleep(1)
                    st.rerun()
            
            st.markdown("---")
            st.info("**Test Credentials:**")
            st.code("Username: soc_analyst\nPassword: Cyber@123\n\nUsername: threat_hunter\nPassword: Hunter@123")
    
    def create_header(self):
        """Create dashboard header"""
        user = st.session_state.current_user
        
        st.markdown(f"""
        <div class="cyber-header">
            <h1>🛡️ {ENTERPRISE_CONFIG["company_name"]}</h1>
            <p>Real-time Threat Intelligence & Monitoring</p>
            <div style="margin-top: 1rem; display: flex; justify-content: center; gap: 15px;">
                <span style="background: rgba(0,255,65,0.2); padding: 8px 20px; border-radius: 25px; border: 1px solid #00ff41;">
                    👤 {user['username']} | {user['role']}
                </span>
                <span style="background: rgba(0,255,65,0.2); padding: 8px 20px; border-radius: 25px; border: 1px solid #00ff41;">
                    🏢 {user.get('department', 'Security')}
                </span>
                <span style="background: rgba(0,255,65,0.2); padding: 8px 20px; border-radius: 25px; border: 1px solid #00ff41;">
                    ⚡ SYSTEM: ONLINE
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    def create_sidebar(self):
        """Create cyber sidebar"""
        with st.sidebar:
            # User Info
            user = st.session_state.current_user
            st.markdown(f"### 👤 {user['username']}")
            st.caption(f"Clearance: {user['role']}")
            st.caption(f"Sector: {user.get('department', 'N/A')}")
            
            st.markdown("---")
            
            # Navigation
            st.markdown("### 🗺️ COMMAND NAVIGATION")
            
            # Main Tabs
            selected_tab = st.radio(
                "Select Interface",
                ["📊 DASHBOARD", "📡 SYSMON ANALYZER", "💻 SOC TERMINAL", "👥 USER CONTROL", 
                 "🔧 SYSTEM CONFIG", "📈 THREAT INTEL", "📋 COMPLIANCE", "🚨 INCIDENT RESPONSE"],
                label_visibility="collapsed"
            )
            
            st.session_state.selected_tab = selected_tab
            
            st.markdown("---")
            
            # System Status
            st.markdown("### 🔌 SYSTEM STATUS")
            
            # ELK Status
            elk_status = self.elk_manager.get_elk_status()
            col1, col2 = st.columns(2)
            with col1:
                status_color = "🟢" if elk_status["elasticsearch"] == "Connected" else "🔴"
                st.metric("Elasticsearch", status_color)
            with col2:
                kibana_color = "🟢" if elk_status["kibana"] == "Available" else "🔴"
                st.metric("Kibana", kibana_color)
            
            if st.session_state.get('elk_connected'):
                st.caption(f"Cluster: {elk_status.get('cluster_name', 'Unknown')}")
                st.caption(f"Indices: {elk_status.get('indices', 0)}")
            
            st.markdown("---")
            
            # Quick Actions
            st.markdown("### ⚡ QUICK ACTIONS")
            
            if st.button("🔄 REFRESH DATA", use_container_width=True):
                st.rerun()
            
            if st.button("🚨 ALERT CONSOLE", use_container_width=True):
                st.session_state.show_alert_console = True
            
            if st.button("📡 SCAN NETWORK", use_container_width=True):
                st.info("Initiating network scan...")
            
            st.markdown("---")
            
            # Logout
            if st.button("🚪 LOGOUT", use_container_width=True, type="secondary"):
                st.session_state.authenticated = False
                st.session_state.current_user = None
                st.success("Session terminated!")
                time.sleep(1)
                st.rerun()
            
            st.caption(f"🕒 {datetime.now().strftime('%H:%M:%S')}")
    
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        st.header("📊 REAL-TIME THREAT DASHBOARD")
        
        # Metrics Row - First row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.markdown("""
            <div class="cyber-card alert-critical">
                <h3>🚨 CRITICAL THREATS</h3>
                <h2>8</h2>
                <p>Immediate action required</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="cyber-card alert-high">
                <h3>⚠️ HIGH ALERTS</h3>
                <h2>15</h2>
                <p>Investigation pending</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown("""
            <div class="cyber-card">
                <h3>📈 TOTAL EVENTS</h3>
                <h2>12,458</h2>
                <p>Last 24 hours</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown("""
            <div class="cyber-card">
                <h3>🔍 ACTIVE SCANS</h3>
                <h2>8</h2>
                <p>Running now</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col5:
            st.markdown("""
            <div class="cyber-card">
                <h3>⚡ RESPONSE TIME</h3>
                <h2>2.1m</h2>
                <p>Average</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Charts and Data
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 THREAT DISTRIBUTION")
            
            # Sample threat data
            threat_data = pd.DataFrame({
                'Threat Type': ['Malware', 'Phishing', 'Insider Threat', 'DDoS', 'Data Exfiltration'],
                'Count': [28, 42, 15, 8, 12]
            })
            
            fig = px.bar(threat_data, x='Threat Type', y='Count', 
                        title="Threat Type Distribution", color='Count',
                        color_continuous_scale='viridis')
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📈 RISK TIMELINE")
            
            # Sample timeline data
            dates = pd.date_range(start='2024-01-01', periods=24, freq='H')
            timeline_data = pd.DataFrame({
                'Time': dates,
                'Risk Score': np.random.normal(60, 20, 24).clip(10, 95)
            })
            
            fig = px.area(timeline_data, x='Time', y='Risk Score', 
                         title="24-Hour Risk Timeline", 
                         line_shape='spline')
            st.plotly_chart(fig, use_container_width=True)
        
        # Recent Alerts
        st.subheader("🚨 RECENT ALERTS")
        
        alerts = [
            {"time": "10:45", "severity": "Critical", "type": "Data Exfiltration", "user": "jsmith", "status": "Investigating"},
            {"time": "10:30", "severity": "High", "type": "Unauthorized Access", "ip": "192.168.1.100", "status": "Pending"},
            {"time": "10:15", "severity": "Medium", "type": "Suspicious Process", "process": "powershell.exe", "status": "Analyzing"},
            {"time": "09:45", "severity": "Low", "type": "Failed Logins", "count": "15 attempts", "status": "Resolved"},
            {"time": "09:30", "severity": "High", "type": "Port Scan", "source": "203.0.113.25", "status": "Blocked"},
        ]
        
        for alert in alerts:
            severity_color = ENTERPRISE_CONFIG['alert_levels'].get(
                alert['severity'], {}
            ).get('color', '#00ff41')
            
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
                <strong>[{alert['time']}] {alert['type']}</strong><br>
                <small>Severity: {alert['severity']} | Status: {alert['status']}</small><br>
                {', '.join([f"{k}: {v}" for k, v in alert.items() if k not in ['time', 'severity', 'type', 'status']])}
            </div>
            """, unsafe_allow_html=True)
    
    def create_sysmon_analyzer_tab(self):
        """Create Sysmon analyzer tab"""
        st.header("📡 SYSMON LOG ANALYZER")
        
        # File upload section
        st.subheader("📁 UPLOAD SYSMON DATA")
        
        uploaded_file = st.file_uploader("Choose Sysmon CSV file", type=['csv'])
        
        if uploaded_file is not None:
            # Save uploaded file
            with open("uploaded_sysmon.csv", "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Load and process data
            if self.sysmon_processor.load_sysmon_data("uploaded_sysmon.csv"):
                processed_data = self.sysmon_processor.process_sysmon_data()
                
                if processed_data is not None:
                    st.session_state.sysmon_loaded = True
                    st.session_state.processed_data = processed_data
                    
                    # Show statistics
                    stats = self.sysmon_processor.get_statistics()
                    
                    if stats:
                        col1, col2, col3, col4 = st.columns(4)
                        
                        with col1:
                            st.metric("Total Events", stats["total_events"])
                        with col2:
                            st.metric("High Risk Events", stats["high_risk_events"])
                        with col3:
                            st.metric("Avg Risk Score", f"{stats['avg_risk_score']:.1f}")
                        with col4:
                            st.metric("File Status", "✅ LOADED")
                    
                    # Event type distribution
                    st.subheader("📊 EVENT ANALYSIS")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        event_types = pd.DataFrame(
                            list(stats["event_types"].items()),
                            columns=["Event Type", "Count"]
                        )
                        fig = px.pie(event_types, values='Count', names='Event Type', 
                                    title="Event Type Distribution", hole=0.3)
                        st.plotly_chart(fig, use_container_width=True)
                    
                    with col2:
                        severity_df = pd.DataFrame(
                            list(stats["severity_distribution"].items()),
                            columns=["Severity", "Count"]
                        )
                        fig = px.bar(severity_df, x='Severity', y='Count', 
                                    title="Severity Distribution", color='Severity',
                                    color_discrete_map={
                                        "Critical": "#DC2626",
                                        "High": "#EA580C",
                                        "Medium": "#F59E0B",
                                        "Low": "#10B981"
                                    })
                        st.plotly_chart(fig, use_container_width=True)
                    
                    # Top threats
                    st.subheader("🔍 TOP THREATS DETECTED")
                    
                    top_threats = self.sysmon_processor.get_top_threats(10)
                    
                    if not top_threats.empty:
                        for _, threat in top_threats.iterrows():
                            severity_color = ENTERPRISE_CONFIG['alert_levels'].get(
                                threat['severity'], {}
                            ).get('color', '#00ff41')
                            
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
                                <strong>{threat['event_type']} - Risk: {threat['risk_score']}</strong><br>
                                <small>Time: {threat['timestamp']} | Severity: {threat['severity']}</small><br>
                                Process: {threat['process_name']} | User: {threat['user']}<br>
                                Source: {threat['source_ip']} → Dest: {threat['destination_ip']}:{threat['port']}
                            </div>
                            """, unsafe_allow_html=True)
                    
                    # Raw data preview
                    with st.expander("📋 VIEW RAW DATA"):
                        st.dataframe(processed_data.head(50), use_container_width=True)
                        
                        # Export options
                        col1, col2 = st.columns(2)
                        with col1:
                            csv = processed_data.to_csv(index=False)
                            st.download_button(
                                label="📥 EXPORT AS CSV",
                                data=csv,
                                file_name=f"sysmon_analysis_{datetime.now().strftime('%Y%m%d')}.csv",
                                mime="text/csv",
                                use_container_width=True
                            )
        else:
            st.info("📁 Upload a Sysmon CSV file to begin analysis")
            
            # Show sample data structure
            with st.expander("📝 SAMPLE DATA FORMAT"):
                st.code("""
                "TimeCreated","Id","LevelDisplayName","Message"
                "24-08-2025 20:41:04","3","Information","Network connection detected:
                RuleName: -
                UtcTime: 2025-08-24 15:11:02.302
                ProcessGuid: {99ef7bdc-ed18-68aa-a153-000000001f00}
                ProcessId: 53460
                Image: C:\\Users\\DELL\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe
                User: DESKTOP-U5F5T3L\\DELL
                Protocol: tcp
                Initiated: true
                SourceIsIpv6: false
                SourceIp: 192.168.43.252
                SourceHostname: DESKTOP-U5F5T3L
                SourcePort: 49674
                SourcePortName: -
                DestinationIsIpv6: false
                DestinationIp: 52.168.117.175
                DestinationHostname: -
                DestinationPort: 443
                DestinationPortName: https"
                """)
    
    def create_soc_terminal_tab(self):
        """Create SOC terminal tab"""
        st.header("💻 SOC COMMAND TERMINAL")
        
        # Terminal output
        st.markdown("""
        <div class="terminal" id="terminal-output">
        """, unsafe_allow_html=True)
        
        # Display terminal output
        terminal_text = self.soc_terminal.get_output()
        st.text_area("", terminal_text, height=300, key="terminal_display", disabled=True)
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Command input
        col1, col2 = st.columns([4, 1])
        
        with col1:
            command = st.text_input("Enter command:", placeholder="Type command and press Enter...", 
                                   key="terminal_input")
        
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("EXECUTE", use_container_width=True):
                if command:
                    self.soc_terminal.execute_command(command)
                    st.session_state.terminal_command = command
                    st.rerun()
        
        # Quick commands
        st.subheader("⚡ QUICK COMMANDS")
        
        quick_cmds = st.columns(6)
        
        with quick_cmds[0]:
            if st.button("HELP", use_container_width=True):
                self.soc_terminal.execute_command("help")
                st.rerun()
        
        with quick_cmds[1]:
            if st.button("THREATS", use_container_width=True):
                self.soc_terminal.execute_command("threats")
                st.rerun()
        
        with quick_cmds[2]:
            if st.button("SYSTEM", use_container_width=True):
                self.soc_terminal.execute_command("system")
                st.rerun()
        
        with quick_cmds[3]:
            if st.button("NETSTAT", use_container_width=True):
                self.soc_terminal.execute_command("netstat")
                st.rerun()
        
        with quick_cmds[4]:
            if st.button("FIREWALL", use_container_width=True):
                self.soc_terminal.execute_command("firewall")
                st.rerun()
        
        with quick_cmds[5]:
            if st.button("CLEAR", use_container_width=True):
                self.soc_terminal.execute_command("clear")
                st.rerun()
        
        # Terminal features
        with st.expander("🔧 TERMINAL FEATURES"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("""
                **Available Commands:**
                - `scan <ip>` - Network scan
                - `investigate <hash>` - File analysis
                - `threats` - Show threats
                - `system` - System status
                - `netstat` - Network connections
                - `ps` - Process list
                """)
            
            with col2:
                st.markdown("""
                **Advanced Features:**
                - `firewall` - Firewall status
                - `log` - Log analysis
                - `mitre <id>` - MITRE search
                - `ioc <type> <value>` - IOC check
                - `export <data>` - Export data
                - `whoami` - User info
                """)
    
    def create_user_management_tab(self):
        """Create user management tab"""
        st.header("👥 USER ACCESS CONTROL")
        
        # Check permissions
        user = st.session_state.current_user
        if "admin" not in user.get("permissions", []):
            st.error("❌ ACCESS DENIED: Insufficient permissions")
            return
        
        # Tabs for user management
        tab1, tab2, tab3, tab4 = st.tabs(["➕ ADD USER", "👥 VIEW USERS", "✏️ EDIT USER", "📋 AUDIT LOG"])
        
        with tab1:
            st.subheader("➕ ADD NEW USER")
            
            with st.form("add_user_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    username = st.text_input("Username", placeholder="Enter username")
                    email = st.text_input("Email", placeholder="user@cyberops.com")
                    password = st.text_input("Password", type="password", placeholder="Enter password")
                    confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm password")
                
                with col2:
                    role = st.selectbox("Role", self.admin_manager.get_user_roles())
                    department = st.selectbox("Department", ENTERPRISE_CONFIG["departments"])
                    mfa_enabled = st.checkbox("Enable MFA", value=True)
                
                # Get permissions for role
                role_permissions = self.admin_manager.get_permissions_by_role(role)
                
                permissions = st.multiselect(
                    "Permissions",
                    options=["view", "analyze", "alert", "report", "investigate", "hunt", "respond", "engineer", "admin"],
                    default=role_permissions
                )
                
                col_a, col_b = st.columns(2)
                with col_a:
                    submit_button = st.form_submit_button("➕ ADD USER", use_container_width=True)
                with col_b:
                    cancel_button = st.form_submit_button("❌ CANCEL", use_container_width=True, type="secondary")
                
                if submit_button:
                    if not username or not email or not password:
                        st.error("❌ All fields required")
                    elif password != confirm_password:
                        st.error("❌ Passwords do not match")
                    else:
                        user_data = {
                            "username": username,
                            "email": email,
                            "password": password,
                            "role": role,
                            "department": department,
                            "permissions": permissions,
                            "mfa_enabled": mfa_enabled
                        }
                        
                        user_id = self.admin_manager.add_user(user_data, user['username'])
                        st.success(f"✅ User {username} added (ID: {user_id})")
                        st.rerun()
        
        with tab2:
            st.subheader("👥 CURRENT USERS")
            
            # Display users
            users_df = pd.DataFrame(self.admin_manager.users)
            
            if not users_df.empty:
                # Search and filter
                col1, col2, col3 = st.columns(3)
                with col1:
                    search_term = st.text_input("Search users", placeholder="Username, email...")
                with col2:
                    role_filter = st.selectbox("Filter by role", ["All"] + self.admin_manager.get_user_roles())
                with col3:
                    status_filter = st.selectbox("Filter by status", ["All", "active", "inactive", "deleted"])
                
                # Apply filters
                if search_term:
                    users_df = users_df[users_df.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)]
                if role_filter != "All":
                    users_df = users_df[users_df['role'] == role_filter]
                if status_filter != "All":
                    users_df = users_df[users_df['status'] == status_filter]
                
                # Display table
                display_cols = ['id', 'username', 'email', 'role', 'department', 'status', 'last_login']
                display_cols = [col for col in display_cols if col in users_df.columns]
                
                st.dataframe(
                    users_df[display_cols],
                    use_container_width=True,
                    hide_index=True
                )
                
                # Statistics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Users", len(users_df))
                with col2:
                    active_users = len(users_df[users_df['status'] == 'active'])
                    st.metric("Active Users", active_users)
                with col3:
                    analysts = len(users_df[users_df['role'].str.contains('Analyst|Hunter|Responder')])
                    st.metric("Security Staff", analysts)
                with col4:
                    recent_logins = len([u for u in users_df.to_dict('records') 
                                       if u.get('last_login')])
                    st.metric("Logged In", recent_logins)
            else:
                st.info("No users found")
        
        with tab3:
            st.subheader("✏️ EDIT USER")
            
            # Select user to edit
            active_users = [u for u in self.admin_manager.users if u['status'] == 'active']
            user_options = {f"{u['username']} ({u['role']})": u['id'] for u in active_users}
            
            if user_options:
                selected_user_label = st.selectbox("Select user to edit", list(user_options.keys()))
                selected_user_id = user_options[selected_user_label]
                
                # Find user data
                user_to_edit = next((u for u in self.admin_manager.users if u['id'] == selected_user_id), None)
                
                if user_to_edit:
                    with st.form("edit_user_form"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            new_role = st.selectbox("Role", self.admin_manager.get_user_roles(), 
                                                  index=self.admin_manager.get_user_roles().index(user_to_edit['role']) 
                                                  if user_to_edit['role'] in self.admin_manager.get_user_roles() else 0)
                            new_department = st.selectbox("Department", ENTERPRISE_CONFIG["departments"],
                                                        index=ENTERPRISE_CONFIG["departments"].index(user_to_edit['department']) 
                                                        if user_to_edit['department'] in ENTERPRISE_CONFIG["departments"] else 0)
                            new_status = st.selectbox("Status", ["active", "inactive"], 
                                                    index=0 if user_to_edit['status'] == "active" else 1)
                        
                        with col2:
                            new_mfa = st.checkbox("Enable MFA", value=user_to_edit.get('mfa_enabled', True))
                            new_session_timeout = st.number_input("Session Timeout (minutes)", 
                                                                min_value=5, max_value=480, 
                                                                value=user_to_edit.get('session_timeout', 30))
                        
                        new_permissions = st.multiselect(
                            "Permissions",
                            options=["view", "analyze", "alert", "report", "investigate", "hunt", "respond", "engineer", "admin"],
                            default=user_to_edit.get('permissions', ["view"])
                        )
                        
                        update_button = st.form_submit_button("💾 UPDATE USER", use_container_width=True)
                        
                        if update_button:
                            updates = {
                                "role": new_role,
                                "department": new_department,
                                "status": new_status,
                                "mfa_enabled": new_mfa,
                                "session_timeout": new_session_timeout,
                                "permissions": new_permissions
                            }
                            
                            if self.admin_manager.update_user(selected_user_id, updates, user['username']):
                                st.success(f"✅ User {user_to_edit['username']} updated")
                                st.rerun()
                            else:
                                st.error("❌ Update failed")
                else:
                    st.warning("User not found")
            else:
                st.info("No active users found")
        
        with tab4:
            st.subheader("📋 AUDIT LOG")
            
            audit_logs = self.admin_manager.get_audit_logs(limit=100)
            
            if audit_logs:
                # Convert to DataFrame
                logs_df = pd.DataFrame(audit_logs)
                
                # Display logs
                st.dataframe(
                    logs_df[['timestamp', 'action', 'user', 'details']],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No audit logs found")
    
    def create_system_config_tab(self):
        """Create system configuration tab"""
        st.header("🔧 SYSTEM CONFIGURATION")
        
        # System Settings
        st.subheader("⚙️ SYSTEM SETTINGS")
        
        with st.form("system_settings_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                auto_refresh = st.checkbox("Auto Refresh", value=True)
                refresh_interval = st.number_input("Refresh Interval (seconds)",
                                                  min_value=10, max_value=3600,
                                                  value=60)
                data_retention = st.number_input("Data Retention (days)",
                                                min_value=1, max_value=365,
                                                value=90)
            
            with col2:
                session_timeout = st.number_input("Session Timeout (minutes)",
                                                 min_value=5, max_value=480,
                                                 value=30)
                max_logins = st.number_input("Max Login Attempts",
                                            min_value=1, max_value=10,
                                            value=5)
                mfa_required = st.checkbox("MFA Required", value=True)
            
            submit_button = st.form_submit_button("💾 SAVE SETTINGS", use_container_width=True)
            
            if submit_button:
                updates = {
                    "auto_refresh": auto_refresh,
                    "refresh_interval": refresh_interval,
                    "data_retention_days": data_retention,
                    "session_timeout": session_timeout,
                    "max_login_attempts": max_logins,
                    "mfa_required": mfa_required
                }
                
                if self.admin_manager.update_settings("system", updates, 
                                                     st.session_state.current_user['username']):
                    st.success("✅ Settings updated")
                else:
                    st.error("❌ Update failed")
    
    def create_threat_intel_tab(self):
        """Create threat intelligence tab"""
        st.header("📈 THREAT INTELLIGENCE")
        
        # Threat Feed
        st.subheader("📡 THREAT FEEDS")
        
        feeds = [
            {"name": "MITRE ATT&CK", "status": "Active", "last_update": "5 min ago"},
            {"name": "CISA Alerts", "status": "Active", "last_update": "15 min ago"},
            {"name": "VirusTotal", "status": "Active", "last_update": "1 hour ago"},
            {"name": "AlienVault OTX", "status": "Active", "last_update": "30 min ago"},
            {"name": "ThreatConnect", "status": "Inactive", "last_update": "2 days ago"},
        ]
        
        for feed in feeds:
            col1, col2, col3 = st.columns([3, 1, 2])
            with col1:
                st.write(f"**{feed['name']}**")
            with col2:
                status_color = "🟢" if feed['status'] == "Active" else "🔴"
                st.write(status_color)
            with col3:
                st.write(f"Updated: {feed['last_update']}")
        
        # Threat Analysis
        st.subheader("🔍 THREAT ANALYSIS")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Top attack vectors
            attack_vectors = pd.DataFrame({
                'Vector': ['Phishing', 'Malware', 'Insider', 'DDoS', 'Credential Theft'],
                'Count': [42, 28, 15, 8, 22]
            })
            
            fig = px.pie(attack_vectors, values='Count', names='Vector', 
                        title="Top Attack Vectors", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Threat timeline
            timeline = pd.DataFrame({
                'Hour': list(range(24)),
                'Threats': np.random.poisson(5, 24)
            })
            
            fig = px.line(timeline, x='Hour', y='Threats', 
                         title="24-Hour Threat Timeline")
            st.plotly_chart(fig, use_container_width=True)
    
    def create_compliance_tab(self):
        """Create compliance tab"""
        st.header("📋 COMPLIANCE DASHBOARD")
        
        # Compliance Scores
        st.subheader("📊 COMPLIANCE SCORES")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("NIST CSF", "92%", "2% ↑")
        with col2:
            st.metric("ISO 27001", "88%", "1% ↑")
        with col3:
            st.metric("PCI DSS", "95%", "0%")
        with col4:
            st.metric("GDPR", "90%", "3% ↑")
        
        # Compliance Requirements
        st.subheader("📝 REQUIREMENTS STATUS")
        
        requirements = [
            {"framework": "NIST CSF", "requirement": "Identify", "status": "Compliant"},
            {"framework": "NIST CSF", "requirement": "Protect", "status": "Partial"},
            {"framework": "NIST CSF", "requirement": "Detect", "status": "Compliant"},
            {"framework": "NIST CSF", "requirement": "Respond", "status": "Non-Compliant"},
            {"framework": "NIST CSF", "requirement": "Recover", "status": "Compliant"},
            {"framework": "ISO 27001", "requirement": "Risk Assessment", "status": "Compliant"},
            {"framework": "ISO 27001", "requirement": "Access Control", "status": "Compliant"},
            {"framework": "PCI DSS", "requirement": "Network Security", "status": "Compliant"},
        ]
        
        for req in requirements:
            status_icon = "✅" if req['status'] == "Compliant" else "⚠️" if req['status'] == "Partial" else "❌"
            st.write(f"{status_icon} **{req['framework']}** - {req['requirement']}: {req['status']}")
    
    def create_incident_response_tab(self):
        """Create incident response tab"""
        st.header("🚨 INCIDENT RESPONSE")
        
        # Active Incidents
        st.subheader("🔴 ACTIVE INCIDENTS")
        
        incidents = [
            {"id": "INC-001", "severity": "Critical", "type": "Data Breach", "status": "Investigating", "time": "2 hours"},
            {"id": "INC-002", "severity": "High", "type": "Malware", "status": "Contained", "time": "5 hours"},
            {"id": "INC-003", "severity": "Medium", "type": "Phishing", "status": "Resolved", "time": "1 day"},
        ]
        
        for incident in incidents:
            severity_color = ENTERPRISE_CONFIG['alert_levels'].get(
                incident['severity'], {}
            ).get('color', '#00ff41')
            
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
                <strong>{incident['id']}: {incident['type']}</strong><br>
                <small>Severity: {incident['severity']} | Status: {incident['status']} | Active: {incident['time']}</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Response Actions
        st.subheader("⚡ RESPONSE ACTIONS")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚨 DECLARE INCIDENT", use_container_width=True):
                st.info("Incident declared. Notifying team...")
        
        with col2:
            if st.button("🛡️ CONTAIN THREAT", use_container_width=True):
                st.info("Containment procedures initiated...")
        
        with col3:
            if st.button("🔍 START INVESTIGATION", use_container_width=True):
                st.info("Investigation team dispatched...")
    
    def run(self):
        """Main application runner"""
        if not st.session_state.authenticated:
            self.create_login_screen()
        else:
            # Create main interface
            self.create_header()
            self.create_sidebar()
            
            # Show appropriate tab based on selection
            selected_tab = st.session_state.get('selected_tab', '📊 DASHBOARD')
            
            if selected_tab == "📊 DASHBOARD":
                self.create_dashboard_tab()
            elif selected_tab == "📡 SYSMON ANALYZER":
                self.create_sysmon_analyzer_tab()
            elif selected_tab == "💻 SOC TERMINAL":
                self.create_soc_terminal_tab()
            elif selected_tab == "👥 USER CONTROL":
                self.create_user_management_tab()
            elif selected_tab == "🔧 SYSTEM CONFIG":
                self.create_system_config_tab()
            elif selected_tab == "📈 THREAT INTEL":
                self.create_threat_intel_tab()
            elif selected_tab == "📋 COMPLIANCE":
                self.create_compliance_tab()
            elif selected_tab == "🚨 INCIDENT RESPONSE":
                self.create_incident_response_tab()

# ============================================
# MAIN APPLICATION
# ============================================

def main():
    """Main application entry point"""
    
    # Initialize dashboard
    dashboard = EnterpriseSecurityDashboard()
    
    # Run the dashboard
    dashboard.run()

if __name__ == "__main__":
    main()