# src/intelligence/threat_intel.py
import requests
from datetime import datetime, timedelta

class ThreatIntelligence:
    """External threat intelligence integration"""
    
    def __init__(self):
        self.threat_feeds = {
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'virustotal': 'https://www.virustotal.com/api/v3/ip_addresses/',
            'alienvault': 'https://otx.alienvault.com/api/v1/indicators/IPv4/'
        }
    
    def check_ip_reputation(self, ip):
        """Check IP reputation across multiple sources"""
        reputation = {
            'ip': ip,
            'abuse_score': 0,
            'total_reports': 0,
            'categories': [],
            'is_malicious': False
        }
        
        # AbuseIPDB check (free tier)
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                headers={'Key': 'YOUR_API_KEY'},
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                reputation['abuse_score'] = data['data']['abuseConfidenceScore']
                reputation['total_reports'] = data['data']['totalReports']
                reputation['is_malicious'] = reputation['abuse_score'] > 50
        except:
            pass
        
        return reputation
    
    def get_threat_bulletin(self):
        """Fetch latest threat intelligence bulletin"""
        # Simulated threat intelligence feed
        bulletins = [
            {
                'id': 'CVE-2024-1234',
                'title': 'Critical RCE in Network Services',
                'severity': 'Critical',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'description': 'New zero-day vulnerability being exploited in the wild'
            },
            {
                'id': 'T1498',
                'title': 'New DoS Attack Variant',
                'severity': 'High',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'description': 'Amplified DDoS attacks using new protocols'
            }
        ]
        return bulletins
