import pandas as pd
from typing import Dict, List, Tuple, Any, Union
from datetime import datetime

class AttackMapper:
    """Advanced attack classification and mapping system"""
    
    # Attack categories with severity scores (1-10)
    ATTACK_DATABASE = {
        'DoS': {
            'attacks': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'processtable', 'udpstorm', 'worm', 'dos', 'ddos'],
            'severity': 8,
            'color': '#ef4444',
            'description': 'Denial of Service - Overwhelming target with traffic',
            'mitigation': ['Rate limiting', 'Traffic filtering', 'Load balancing']
        },
        'Probe': {
            'attacks': ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint', 'nmap_probe', 'probe', 'port_scan'],
            'severity': 6,
            'color': '#f59e0b',
            'description': 'Port scanning and network reconnaissance',
            'mitigation': ['Port knocking', 'Stealth mode', 'IDS rules']
        },
        'R2L': {
            'attacks': ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'warezmaster', 'xlock', 'xsnoop', 'r2l', 'brute_force', 'ssh_brute', 'ftp_brute'],
            'severity': 9,
            'color': '#dc2626',
            'description': 'Remote to Local - Unauthorized access attempts',
            'mitigation': ['Strong authentication', 'Password policies', 'Account lockout']
        },
        'U2R': {
            'attacks': ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 'ps', 'sqlattack', 'u2r', 'infiltration'],
            'severity': 10,
            'color': '#991b1b',
            'description': 'User to Root - Privilege escalation attempts',
            'mitigation': ['Patch management', 'Privilege separation', 'Kernel hardening']
        },
        'WebAttack': {
            'attacks': ['web_attack', 'sqli', 'xss', 'sql_injection', 'cross_site_scripting'],
            'severity': 8,
            'color': '#f97316',
            'description': 'Web application attacks',
            'mitigation': ['WAF', 'Input validation', 'Parameterized queries']
        },
        'Botnet': {
            'attacks': ['botnet', 'c2', 'command_and_control', 'malware'],
            'severity': 9,
            'color': '#7c3aed',
            'description': 'Botnet communication and C2 traffic',
            'mitigation': ['DNS filtering', 'Traffic analysis', 'Blacklisting']
        },
        'Normal': {
            'attacks': ['normal', 'benign', 'legitimate'],
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
        'U2R': 'T1068',
        'WebAttack': 'T1190',
        'Botnet': 'T1071'
    }
    
    @classmethod
    def get_attack_info(cls, attack_label: str) -> Dict[str, Any]:
        """Get comprehensive attack information"""
        # Convert to string safely
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
    def get_severity_score(cls, attack_label: Union[str, Any]) -> int:
        """Get severity score for attack"""
        # Convert to string safely
        attack_label = str(attack_label)
        info = cls.get_attack_info(attack_label)
        return info['severity']
    
    @classmethod
    def get_attack_color(cls, attack_label: str) -> str:
        """Get color code for attack visualization"""
        info = cls.get_attack_info(attack_label)
        return info['color']
    
    @classmethod
    def get_attack_statistics(cls, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate attack statistics"""
        if not alerts:
            return {}
        
        df = pd.DataFrame(alerts)
        
        # Handle empty dataframe
        if df.empty:
            return {}
        
        attack_counts = df['attack_type'].value_counts()
        
        # Safely get hour from timestamp
        try:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.strftime('%Y-%m-%d %H')
            hourly_pattern = df.groupby('hour').size().to_dict()
        except:
            hourly_pattern = {}
        
        statistics = {
            'total_attacks': len(alerts),
            'attack_distribution': attack_counts.to_dict(),
            'severity_breakdown': {},
            'top_attackers': df['source_ip'].value_counts().head(10).to_dict(),
            'hourly_pattern': hourly_pattern,
            'average_confidence': float(df['confidence'].mean()) if not df.empty else 0.0,
            'risk_score': cls.calculate_risk_score(alerts)
        }
        
        # Calculate severity breakdown
        for attack_type, count in attack_counts.items():
            severity = cls.get_severity_score(str(attack_type))
            if severity not in statistics['severity_breakdown']:
                statistics['severity_breakdown'][severity] = 0
            statistics['severity_breakdown'][severity] += count
        
        return statistics
    
    @classmethod
    def calculate_risk_score(cls, alerts: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score"""
        if not alerts:
            return 0.0
        
        total_risk = 0.0
        for alert in alerts:
            severity = cls.get_severity_score(alert['attack_type'])
            confidence = alert.get('confidence', 0.8)
            total_risk += severity * confidence
        
        avg_risk = total_risk / len(alerts)
        return min(avg_risk, 10.0)  # Scale to 0-10
    
    @classmethod
    def get_recommendations(cls, alerts: List[Dict[str, Any]]) -> List[str]:
        """Get security recommendations based on attacks"""
        recommendations = set()
        
        for alert in alerts:
            info = cls.get_attack_info(str(alert['attack_type']))
            for mitigation in info['mitigation']:
                recommendations.add(mitigation)
        
        return list(recommendations)
    
    @classmethod
    def get_attack_summary(cls, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get simplified attack summary"""
        if not alerts:
            return {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'top_attack': 'None',
                'top_attacker': 'None'
            }
        
        total = len(alerts)
        critical = 0
        high = 0
        medium = 0
        low = 0
        
        for alert in alerts:
            severity = cls.get_severity_score(alert['attack_type'])
            if severity >= 8:
                critical += 1
            elif severity >= 5:
                high += 1
            elif severity >= 3:
                medium += 1
            else:
                low += 1
        
        # Get top attack type
        df = pd.DataFrame(alerts)
        top_attack = df['attack_type'].mode().iloc[0] if not df.empty else 'None'
        top_attacker = df['source_ip'].mode().iloc[0] if not df.empty else 'None'
        
        return {
            'total': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'top_attack': str(top_attack),
            'top_attacker': str(top_attacker)
        }
