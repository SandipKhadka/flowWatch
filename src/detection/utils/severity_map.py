"""Attack severity definitions and mapping"""

from typing import Tuple, NamedTuple


class SeverityInfo(NamedTuple):
    """Severity information for an attack type"""
    score: int
    level: str
    icon: str
    description: str = ""


class SeverityMap:
    """Map attack types to severity levels"""
    
    SEVERITY_LEVELS = {
        # CRITICAL (8-10)
        'infiltration': SeverityInfo(10, 'CRITICAL', '🔴', 'Unauthorized access attempt'),
        'u2r': SeverityInfo(10, 'CRITICAL', '🔴', 'User to root escalation'),
        'rootkit': SeverityInfo(10, 'CRITICAL', '🔴', 'Rootkit detected'),
        'ddos': SeverityInfo(9, 'CRITICAL', '🔴', 'DDoS attack detected'),
        'dos': SeverityInfo(8, 'CRITICAL', '🔴', 'DoS attack detected'),
        'r2l': SeverityInfo(8, 'CRITICAL', '🔴', 'Remote to local exploit'),
        
        # HIGH (5-7)
        'botnet': SeverityInfo(7, 'HIGH', '🟠', 'Botnet communication'),
        'brute_force': SeverityInfo(7, 'HIGH', '🟠', 'Brute force attack'),
        'web_attack': SeverityInfo(6, 'HIGH', '🟠', 'Web application attack'),
        'sqli': SeverityInfo(6, 'HIGH', '🟠', 'SQL injection'),
        'port_scan': SeverityInfo(5, 'HIGH', '🟠', 'Port scanning'),
        'nmap': SeverityInfo(5, 'HIGH', '🟠', 'Nmap scan detected'),
        
        # MEDIUM (3-4) - Filtered by default
        'probe': SeverityInfo(3, 'MEDIUM', '🟡', 'Network probe'),
        'ipsweep': SeverityInfo(3, 'MEDIUM', '🟡', 'IP sweep'),
        
        # NORMAL/LOW (0-2)
        'normal': SeverityInfo(0, 'NORMAL', '⚪', 'Normal traffic'),
        'benign': SeverityInfo(0, 'NORMAL', '⚪', 'Benign traffic'),
    }
    
    @classmethod
    def get_severity(cls, attack_type: str) -> SeverityInfo:
        """
        Get severity information for an attack type
        
        Args:
            attack_type: Type of attack
            
        Returns:
            SeverityInfo object
        """
        key = attack_type.lower()
        if key in cls.SEVERITY_LEVELS:
            return cls.SEVERITY_LEVELS[key]
        # Default to medium for unknown attacks
        return SeverityInfo(3, 'MEDIUM', '🟡', f'Unknown attack type: {attack_type}')
    
    @classmethod
    def is_high_severity(cls, attack_type: str, threshold: int = 5) -> bool:
        """Check if attack severity meets or exceeds threshold"""
        return cls.get_severity(attack_type).score >= threshold
