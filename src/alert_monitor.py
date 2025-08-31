# src/alert_monitor.py
import time
import json
from datetime import datetime
from email_alerts import EmailAlertSystem

class AlertMonitor:
    def __init__(self, check_interval=300):  # 5 minutes
        self.check_interval = check_interval
        self.alert_system = EmailAlertSystem()
        self.sent_alerts = set()
    
    def monitor(self):
        """Continuous monitoring loop"""
        print(f"🚨 Starting alert monitor (checking every {self.check_interval}s)")
        
        while True:
            try:
                # Load current data
                with open('data/processed/simulated_es_data.json', 'r') as f:
                    data = json.load(f)
                
                # Check for new alerts
                new_alerts = 0
                for user_data in data:
                    user_id = user_data['user']
                    if (user_data['risk_score'] > self.alert_system.config['alert_threshold'] and 
                        user_id not in self.sent_alerts):
                        
                        # Send alert
                        reasons = []
                        if user_data.get('tor_usage', False):
                            reasons.append("Tor usage detected")
                        if user_data['risk_score'] > 0.8:
                            reasons.append("Critical risk level")
                        
                        risk_reason = ", ".join(reasons) if reasons else "High risk behavior"
                        
                        if self.alert_system.send_alert(user_data, risk_reason):
                            self.sent_alerts.add(user_id)
                            new_alerts += 1
                            print(f"⚠️ New alert for {user_id} (risk: {user_data['risk_score']:.3f})")
                
                if new_alerts > 0:
                    print(f"📧 Sent {new_alerts} new alert(s)")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(60)  # Wait 1 minute before retrying

if __name__ == "__main__":
    monitor = AlertMonitor()
    monitor.monitor()