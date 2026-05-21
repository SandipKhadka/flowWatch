# src/utils/attack_mapper.py
import pandas as pd
from typing import Dict, List, Tuple
from datetime import datetime

class AttackMapper:
    """Advanced attack classification and mapping system"""
    
    # Attack categories with severity scores (1-10)
    ATTACK_DATABASE = {
        'DoS': {
            'attacks': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'processtable', 'udpstorm', 'worm'],
            'severity': 8,
            'color': '#ef4444',
            'description': 'Denial of Service - Overwhelming target with traffic',
            'mitigation': ['Rate limiting', 'Traffic filtering', 'Load balancing']
        },
        'Probe': {
            'attacks': ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint', 'nmap_probe'],
            'severity': 6,
            'color': '#f59e0b',
            'description': 'Port scanning and network reconnaissance',
            'mitigation': ['Port knocking', 'Stealth mode', 'IDS rules']
        },
        'R2L': {
            'attacks': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'warezmaster', 'xlock', 'xsnoop'],
            'severity': 9,
            'color': '#dc2626',
            'description': 'Remote to Local - Unauthorized access attempts',
            'mitigation': ['Strong authentication', 'Password policies', 'Account lockout']
        },
        'U2R': {
            'attacks': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 'ps', 'sqlattack'],
            'severity': 10,
            'color': '#991b1b',
            'description': 'User to Root - Privilege escalation attempts',
            'mitigation': ['Patch management', 'Privilege separation', 'Kernel hardening']
        },
        'Normal': {
            'attacks': ['normal', 'benign'],
            'severity': 0,
            'color': '#10b981',
            'description': 'Normal network traffic',
            'mitigation': []
        }
    }
    
    # MITRE ATT&CK mapping
    MITRE_MAPPING = {
        'DoS': 'T1498',
        'Probe': 'T1040',
        'R2L': 'T1078',
        'U2R': 'T1068'
    }
    
    @classmethod
    def get_attack_info(cls, attack_label: str) -> Dict:
        """Get comprehensive attack information"""
        attack_label = str(attack_label).lower()
        
        for category, info in cls.ATTACK_DATABASE.items():
            if attack_label in info['attacks'] or attack_label == category.lower():
                return {
                    'category': category,
                    'severity': info['severity'],
                    'color': info['color'],
                    'description': info['description'],
                    'mitigation': info['mitigation'],
                    'mitre_id': cls.MITRE_MAPPING.get(category, 'Unknown'),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Unknown attack
        return {
            'category': 'Unknown',
            'severity': 5,
            'color': '#6b7280',
            'description': 'Unknown attack pattern',
            'mitigation': ['Investigate manually', 'Update signatures'],
            'mitre_id': 'Unknown'
        }
    
    @classmethod
    def get_severity_score(cls, attack_label: str) -> int:
        """Get severity score for attack"""
        info = cls.get_attack_info(attack_label)
        return info['severity']
    
    @classmethod
    def get_attack_color(cls, attack_label: str) -> str:
        """Get color code for attack visualization"""
        info = cls.get_attack_info(attack_label)
        return info['color']
    
    @classmethod
    def get_attack_statistics(cls, alerts: List[Dict]) -> Dict:
        """Generate attack statistics"""
        if not alerts:
            return {}
        
        df = pd.DataFrame(alerts)
        attack_counts = df['attack_type'].value_counts()
        
        statistics = {
            'total_attacks': len(alerts),
            'attack_distribution': attack_counts.to_dict(),
            'severity_breakdown': {},
            'top_attackers': df['source_ip'].value_counts().head(10).to_dict(),
            'hourly_pattern': df.groupby(df['timestamp'].str[:13]).size().to_dict(),
            'average_confidence': df['confidence'].mean(),
            'risk_score': cls.calculate_risk_score(alerts)
        }
        
        # Calculate severity breakdown
        for attack_type, count in attack_counts.items():
            severity = cls.get_severity_score(attack_type)
            if severity not in statistics['severity_breakdown']:
                statistics['severity_breakdown'][severity] = 0
            statistics['severity_breakdown'][severity] += count
        
        return statistics
    
    @classmethod
    def calculate_risk_score(cls, alerts: List[Dict]) -> float:
        """Calculate overall risk score"""
        if not alerts:
            return 0.0
        
        total_risk = 0
        for alert in alerts:
            severity = cls.get_severity_score(alert['attack_type'])
            confidence = alert.get('confidence', 0.8)
            total_risk += severity * confidence
        
        avg_risk = total_risk / len(alerts)
        return min(avg_risk, 10.0)  # Scale to 0-10
    
    @classmethod
    def get_recommendations(cls, alerts: List[Dict]) -> List[str]:
        """Get security recommendations based on attacks"""
        recommendations = set()
        
        for alert in alerts:
            info = cls.get_attack_info(alert['attack_type'])
            for mitigation in info['mitigation']:
                recommendations.add(mitigation)
        
        return list(recommendations)
