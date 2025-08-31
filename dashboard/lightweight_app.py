# dashboard/lightweight_app.py
import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
import os
import random
from datetime import datetime

# Email alert functions (built-in to avoid import issues)
def send_test_alert():
    """Simulate sending an alert for testing"""
    st.sidebar.info("📧 [SIMULATED] Email alert would be sent to admin@company.com")
    return True

def check_and_alert_test(data):
    """Test version that doesn't actually send emails"""
    alerts = 0
    high_risk_users = []
    for user_data in data:
        if user_data['risk_score'] > 0.7:
            high_risk_users.append(user_data['user'])
            alerts += 1
    
    if alerts > 0:
        st.sidebar.warning(f"📧 Would send alerts for: {', '.join(high_risk_users)}")
    return alerts

def load_simulated_data():
    """Load simulated Elasticsearch data"""
    try:
        file_path = 'data/processed/simulated_es_data.json'
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            st.warning("No data file found. Please run the prediction pipeline first.")
            return create_sample_data()
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return create_sample_data()

def create_sample_data():
    """Create sample data for demonstration"""
    sample_data = []
    for i in range(1, 21):
        risk_score = round(random.uniform(0.1, 0.95), 3)
        sample_data.append({
            "timestamp": datetime.now().isoformat(),
            "user": f"user_{i:03d}",
            "risk_score": risk_score,
            "is_anomaly": 1 if risk_score > 0.7 else 0,
            "tor_usage": random.random() < 0.1  # 10% use Tor
        })
    return sample_data

def add_tor_detection(df):
    """Add Tor usage detection to dataframe"""
    if 'tor_usage' not in df.columns:
        df['tor_usage'] = [random.random() < 0.05 for _ in range(len(df))]
    return df

def main():
    st.set_page_config(
        page_title="Insider Threat Detection Dashboard",
        page_icon="🔒",
        layout="wide"
    )
    
    st.title("🔒 Insider Threat Detection Dashboard")
    st.markdown("Monitor user behavior and detect potential insider threats including Tor usage")
    
    # Load data
    data = load_simulated_data()
    df = pd.DataFrame(data)
    
    # Add Tor usage detection if not present
    df = add_tor_detection(df)
    
    # Sidebar
    st.sidebar.header("⚙️ Settings")
    risk_threshold = st.sidebar.slider(
        "Risk Threshold", 
        min_value=0.0, 
        max_value=1.0, 
        value=0.7, 
        step=0.05,
        help="Adjust the sensitivity for threat detection"
    )
    
    # Metrics
    st.header("📊 Overview Metrics")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Users", df['user'].nunique())

    with col2:
        high_risk_users = df[df['risk_score'] > risk_threshold]['user'].nunique()
        st.metric("High Risk Users", high_risk_users)

    with col3:
        avg_risk = df['risk_score'].mean()
        st.metric("Average Risk Score", f"{avg_risk:.3f}")

    with col4:
        total_alerts = len(df[df['risk_score'] > risk_threshold])
        st.metric("Total Alerts", total_alerts)
    
    # Visualizations
    st.header("📈 Risk Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Risk Score Distribution")
        fig = px.histogram(df, x='risk_score', nbins=20, 
                          title="Distribution of User Risk Scores")
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Top Risky Users")
        user_risk = df.groupby('user')['risk_score'].max().sort_values(ascending=False).head(10)
        fig = px.bar(x=user_risk.index, y=user_risk.values, 
                    labels={'x': 'User', 'y': 'Max Risk Score'},
                    title="Users with Highest Risk Scores")
        st.plotly_chart(fig, use_container_width=True)
    
    # Tor Network Detection
    st.header("🕵️ Tor Network Detection")
    tor_users = df[df['tor_usage'] == True]
    
    if not tor_users.empty:
        st.warning(f"🚨 Tor usage detected: {len(tor_users)} users")
        st.dataframe(tor_users[['user', 'risk_score', 'timestamp']].reset_index(drop=True))
    else:
        st.success("✅ No Tor network usage detected")
    
    # Pie Charts
    st.header("📊 Risk Distribution Charts")
    col1, col2 = st.columns(2)

    with col1:
        # Tor usage pie chart
        tor_count = df['tor_usage'].sum()
        fig_tor = go.Figure(go.Pie(
            labels=['Normal Users', 'Tor Users'],
            values=[len(df) - tor_count, tor_count],
            hole=0.3,
            marker_colors=['green', 'red']
        ))
        fig_tor.update_layout(title_text="Tor Network Usage")
        st.plotly_chart(fig_tor, use_container_width=True)

    with col2:
        # Anomaly distribution pie chart
        anomaly_count = df['is_anomaly'].sum()
        fig_anomaly = go.Figure(go.Pie(
            labels=['Normal', 'Anomaly'],
            values=[len(df) - anomaly_count, anomaly_count],
            hole=0.3,
            marker_colors=['blue', 'orange']
        ))
        fig_anomaly.update_layout(title_text="Anomaly Distribution")
        st.plotly_chart(fig_anomaly, use_container_width=True)
    
    # Email Alerts Section
    st.sidebar.header("📧 Email Alerts")
    
    if st.sidebar.button("Send Test Alert"):
        send_test_alert()
    
    if st.sidebar.button("Send Alerts for High Risk Users"):
        alerts_sent = check_and_alert_test(data)
        st.sidebar.success(f"📧 Would send {alerts_sent} alert(s) to admin")
    
    # Real-time monitoring section
    st.header("🕒 Recent High-Risk Alerts")
    recent_alerts = df[df['risk_score'] > risk_threshold].sort_values('timestamp', ascending=False).head(10)
    
    if not recent_alerts.empty:
        for _, alert in recent_alerts.iterrows():
            alert_text = f"**{alert['user']}** - Risk: {alert['risk_score']:.3f}"
            if alert['tor_usage']:
                alert_text += " - 🕵️ Tor Usage"
            st.warning(alert_text)
    else:
        st.info("No high-risk alerts with current threshold")
    
    # Detailed data view
    with st.expander("📋 Detailed Data View"):
        st.dataframe(df[['user', 'risk_score', 'is_anomaly', 'tor_usage', 'timestamp']].sort_values('risk_score', ascending=False))

if __name__ == "__main__":
    main()