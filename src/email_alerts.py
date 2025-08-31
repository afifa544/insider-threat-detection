# src/real_alerts.py
import smtplib
import requests
import json
import os
from twilio.rest import Client
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class MultiChannelAlertSystem:
    def __init__(self):
        # Load configuration
        self.config = self.load_config()
        
        # Email config
        self.smtp_server = self.config.get("smtp_server", "smtp.gmail.com")
        self.smtp_port = self.config.get("smtp_port", 587)
        self.sender_email = self.config.get("sender_email", "")
        self.sender_password = self.config.get("sender_password", "")
        
        # Slack webhook
        self.slack_webhook = self.config.get("slack_webhook", "")
        
        # Twilio SMS
        self.twilio_sid = self.config.get("twilio_sid", "")
        self.twilio_token = self.config.get("twilio_token", "")
        self.twilio_number = self.config.get("twilio_number", "")
    
    def load_config(self):
        """Load alert configuration from file"""
        config_path = 'config/alert_config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Return default config if file doesn't exist
        return {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "taskeenafifa934@gmail.com",
            "sender_password": "your-app-password",
            "admin_email": "bushrafatima.vtu@gmail.com",
            "slack_webhook": "",
            "twilio_sid": "",
            "twilio_token": "",
            "twilio_number": "",
            "alert_threshold": 0.7
        }
    
    def send_email_alert(self, to_email, message):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = to_email
            msg['Subject'] = "🚨 Insider Threat Alert"
            
            body = f"""
            INSIDER THREAT DETECTION ALERT
            -------------------------------
            
            {message}
            
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            This is an automated alert from the Insider Threat Detection System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            
            print(f"📧 Email alert sent to {to_email}")
            return True
            
        except Exception as e:
            print(f"❌ Email failed: {e}")
            return False
    
    def send_slack_alert(self, message):
        """Send alert to Slack channel"""
        if not self.slack_webhook:
            print("⚠️ Slack webhook not configured")
            return False
            
        payload = {"text": message}
        try:
            response = requests.post(self.slack_webhook, json=payload)
            if response.status_code == 200:
                print("💬 Slack alert sent")
                return True
            else:
                print(f"❌ Slack failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Slack error: {e}")
            return False
    
    def send_sms_alert(self, to_number, message):
        """Send SMS alert via Twilio"""
        if not all([self.twilio_sid, self.twilio_token, self.twilio_number]):
            print("⚠️ Twilio not configured")
            return False
            
        try:
            client = Client(self.twilio_sid, self.twilio_token)
            message = client.messages.create(
                body=message,
                from_=self.twilio_number,
                to=to_number
            )
            print(f"📱 SMS alert sent to {to_number}")
            return True
        except Exception as e:
            print(f"❌ SMS failed: {e}")
            return False
    
    def send_multi_channel_alert(self, user_data, risk_score):
        """Send alerts through multiple channels"""
        message = f"🚨 Insider Threat Alert\nUser: {user_data['user']}\nRisk Score: {risk_score:.3f}\nTime: {datetime.now().strftime('%H:%M:%S')}"
        
        # Send to all channels
        results = {
            'email': self.send_email_alert(self.config.get("admin_email", "bushrafatima.vtu@gmail.com"), message),
            'slack': self.send_slack_alert(message),
            'sms': self.send_sms_alert("+1234567890", message)  # Replace with admin phone number
        }
        
        return results
    
    def send_test_alert(self):
        """Send test alert to all channels"""
        test_data = {
            'user': 'TEST_USER',
            'risk_score': 0.95
        }
        return self.send_multi_channel_alert(test_data, 0.95)

# Example usage
if __name__ == "__main__":
    alert_system = MultiChannelAlertSystem()
    
    print("Testing alert system...")
    results = alert_system.send_test_alert()
    
    print("\nTest Results:")
    for channel, success in results.items():
        status = "✅ Success" if success else "❌ Failed"
        print(f"{channel.upper()}: {status}")