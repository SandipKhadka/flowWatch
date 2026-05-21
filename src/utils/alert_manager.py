# src/utils/alert_manager.py
import smtplib
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict
import requests
import logging
from collections import deque

class AlertManager:
    """Advanced alert management with multiple notification channels"""
    
    def __init__(self, config_file="config/alert_config.json"):
        self.alert_history = deque(maxlen=1000)  # Store last 1000 alerts
        self.alert_throttle = {}  # Prevent alert flooding
        self.config = self.load_config(config_file)
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_file: str) -> Dict:
        """Load alert configuration"""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'sender_email': '',
                'sender_password': '',
                'recipient_emails': []
            },
            'webhook': {
                'enabled': False,
                'urls': [],
                'headers': {}
            },
            'slack': {
                'enabled': False,
                'webhook_url': ''
            },
            'thresholds': {
                'min_severity': 5,  # Minimum severity to send alert
                'cooldown_seconds': 60,  # Cooldown for same IP/attack
                'batch_size': 10  # Batch alerts before sending
            },
            'logging': {
                'file_enabled': True,
                'console_enabled': True,
                'log_file': 'logs/alerts.log'
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        except FileNotFoundError:
            # Create default config
            os.makedirs('config', exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
        
        return default_config
    
    def process_alert(self, alert: Dict) -> bool:
        """Process and route alert to appropriate channels"""
        from src.utils.attack_mapper import AttackMapper
        
        # Check if alert should be sent
        severity = AttackMapper.get_severity_score(alert['attack_type'])
        if severity < self.config['thresholds']['min_severity']:
            return False
        
        # Check throttling
        alert_key = f"{alert.get('source_ip')}_{alert['attack_type']}"
        if alert_key in self.alert_throttle:
            last_time = self.alert_throttle[alert_key]
            if (datetime.now() - last_time).seconds < self.config['thresholds']['cooldown_seconds']:
                return False
        
        # Update throttle
        self.alert_throttle[alert_key] = datetime.now()
        
        # Add to history
        self.alert_history.append(alert)
        
        # Log alert
        self.log_alert(alert)
        
        # Send notifications
        if self.config['email']['enabled']:
            self.send_email_alert(alert)
        
        if self.config['webhook']['enabled']:
            self.send_webhook_alert(alert)
        
        if self.config['slack']['enabled']:
            self.send_slack_alert(alert)
        
        return True
    
    def log_alert(self, alert: Dict):
        """Log alert to file and console"""
        log_message = f"[{alert['timestamp']}] {alert['attack_type'].upper()} - {alert.get('source_ip')} - Confidence: {alert['confidence']}"
        
        if self.config['logging']['console_enabled']:
            print(f"🚨 {log_message}")
        
        if self.config['logging']['file_enabled']:
            logging.basicConfig(
                filename=self.config['logging']['log_file'],
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            logging.info(log_message)
    
    def send_email_alert(self, alert: Dict):
        """Send email alert"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['sender_email']
            msg['To'] = ', '.join(self.config['email']['recipient_emails'])
            msg['Subject'] = f"SECURITY ALERT: {alert['attack_type'].upper()} Detected"
            
            body = f"""
            Security Alert from FlowWatch AI
            
            Attack Type: {alert['attack_type'].upper()}
            Source IP: {alert.get('source_ip', 'Unknown')}
            Timestamp: {alert['timestamp']}
            Confidence: {alert['confidence']*100:.1f}%
            
            Immediate action recommended.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['sender_email'], self.config['email']['sender_password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {alert['attack_type']}")
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def send_webhook_alert(self, alert: Dict):
        """Send webhook alert"""
        for url in self.config['webhook']['urls']:
            try:
                response = requests.post(
                    url,
                    json=alert,
                    headers=self.config['webhook']['headers'],
                    timeout=5
                )
                if response.status_code == 200:
                    self.logger.info(f"Webhook alert sent to {url}")
            except Exception as e:
                self.logger.error(f"Failed to send webhook alert: {e}")
    
    def send_slack_alert(self, alert: Dict):
        """Send Slack notification"""
        if not self.config['slack']['webhook_url']:
            return
        
        try:
            from src.utils.attack_mapper import AttackMapper
            severity = AttackMapper.get_severity_score(alert['attack_type'])
            
            color = "danger" if severity >= 7 else "warning" if severity >= 4 else "good"
            
            slack_message = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 {alert['attack_type'].upper()} Attack Detected",
                        "fields": [
                            {"title": "Source IP", "value": alert.get('source_ip'), "short": True},
                            {"title": "Severity", "value": f"{severity}/10", "short": True},
                            {"title": "Confidence", "value": f"{alert['confidence']*100:.1f}%", "short": True},
                            {"title": "Time", "value": alert['timestamp'], "short": False}
                        ],
                        "footer": "FlowWatch AI IDS",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.config['slack']['webhook_url'],
                json=slack_message,
                timeout=5
            )
            
            if response.status_code == 200:
                self.logger.info(f"Slack alert sent for {alert['attack_type']}")
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
    
    def get_alert_summary(self) -> Dict:
        """Get summary of recent alerts"""
        from collections import Counter
        
        if not self.alert_history:
            return {'total': 0, 'by_type': {}, 'by_source': {}}
        
        attack_types = Counter([a['attack_type'] for a in self.alert_history])
        sources = Counter([a.get('source_ip') for a in self.alert_history])
        
        return {
            'total': len(self.alert_history),
            'by_type': dict(attack_types),
            'by_source': dict(sources.most_common(10)),
            'latest_alert': self.alert_history[-1] if self.alert_history else None
        }
