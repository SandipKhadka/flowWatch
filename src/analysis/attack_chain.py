# src/analysis/attack_chain.py
from datetime import datetime, timedelta

class AttackChainReconstruction:
    """Reconstruct multi-stage attack chains"""
    
    def reconstruct_chain(self, alerts, source_ip):
        """Reconstruct attack sequence for specific IP"""
        ip_alerts = [a for a in alerts if a.get('source_ip') == source_ip]
        
        if len(ip_alerts) < 2:
            return None
        
        # Sort by time
        ip_alerts.sort(key=lambda x: x['timestamp'])
        
        # Identify attack progression
        chain = {
            'source_ip': source_ip,
            'first_seen': ip_alerts[0]['timestamp'],
            'last_seen': ip_alerts[-1]['timestamp'],
            'total_attacks': len(ip_alerts),
            'progression': []
        }
        
        # Map attack progression
        for i, alert in enumerate(ip_alerts[:-1]):
            next_alert = ip_alerts[i + 1]
            time_diff = (datetime.fromisoformat(next_alert['timestamp']) - 
                        datetime.fromisoformat(alert['timestamp'])).seconds
            
            chain['progression'].append({
                'from': alert['attack_type'],
                'to': next_alert['attack_type'],
                'time_gap_seconds': time_diff,
                'confidence': alert['confidence']
            })
        
        # Determine attack pattern
        attack_types = [a['attack_type'] for a in ip_alerts]
        if 'probe' in attack_types and 'dos' in attack_types:
            chain['pattern'] = "Reconnaissance → DoS Attack"
            chain['severity'] = "Critical"
        elif 'probe' in attack_types and 'r2l' in attack_types:
            chain['pattern'] = "Reconnaissance → R2L Attack"
            chain['severity'] = "High"
        
        return chain
