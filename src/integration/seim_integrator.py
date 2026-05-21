# src/integration/siem_integrator.pyimport json
from datetime import datetime
import requests

class SIEMIntegrator:
    """Integrate with enterprise SIEM systems"""
    
    def __init__(self, config):
        self.config = config
        
    def forward_to_splunk(self, alert):
        """Forward alert to Splunk HEC"""
        splunk_data = {
            "time": datetime.now().timestamp(),
            "host": "securenet-ids",
            "source": "ids_detector",
            "sourcetype": "security",
            "event": {
                "attack_type": alert['attack_type'],
                "source_ip": alert['source_ip'],
                "confidence": alert['confidence'],
                "severity": AttackMapper.get_severity_score(alert['attack_type'])
            }
        }
        
        try:
            response = requests.post(
                "https://splunk-server:8088/services/collector",
                headers={"Authorization": f"Splunk {self.config['splunk_token']}"},
                json=splunk_data,
                verify=False
            )
            return response.status_code == 200
        except:
            return False
    
    def forward_to_elasticsearch(self, alert):
        """Forward alert to Elasticsearch"""
        es_data = {
            "@timestamp": datetime.now().isoformat(),
            "ids": "securenet-ai",
            "threat": alert
        }
        
        try:
            response = requests.post(
                f"{self.config['elastic_url']}/ids-alerts/_doc",
                json=es_data,
                auth=(self.config['elastic_user'], self.config['elastic_pass'])
            )
            return response.status_code == 201
        except:
            return False
    
    def export_to_json(self, alerts, filename=None):
        """Export alerts to JSON format for SIEM"""
        if not filename:
            filename = f"exports/siem_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            "export_time": datetime.now().isoformat(),
            "source": "SecureNet AI IDS",
            "version": "1.0",
            "alerts": alerts
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return filename
