# monitor_alerts.py
import time
import json
from datetime import datetime
from dashboard.email_alerts import check_and_alert_test

class AlertMonitor:
    def __init__(self, check_interval=300):  # 5 minutes
        self.check_interval = check_interval
        self.sent_alerts = set()
    
    def monitor(self):
        """Continuous monitoring loop"""
        print(f"🚨 Starting alert monitor (checking every {self.check_interval}s)")
        print("📧 Using simulated email alerts for testing")
        
        while True:
            try:
                # Load current data
                with open('data/processed/simulated_es_data.json', 'r') as f:
                    data = json.load(f)
                
                # Check for alerts
                alerts_sent = check_and_alert_test(data)
                
                if alerts_sent > 0:
                    print(f"📧 Simulated sending {alerts_sent} alert(s)")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(60)  # Wait 1 minute before retrying

if __name__ == "__main__":
    monitor = AlertMonitor(check_interval=60)  # Check every 60 seconds for demo
    monitor.monitor()