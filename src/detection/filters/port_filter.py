"""Port-based filtering utilities"""

from typing import Set, Optional


class PortFilter:
    """Filter traffic based on destination ports"""
    
    # Known benign ports/services
    BENIGN_PORTS = {
        80, 443,           # HTTP/HTTPS
        53,                # DNS
        67, 68,            # DHCP
        123,               # NTP
        5353,              # mDNS
        1900,              # SSDP/UPnP
        137, 138, 139,     # NetBIOS
        8443,              # HTTPS alt
        22,                # SSH (optional - adjust as needed)
        25,                # SMTP
        110,               # POP3
        143,               # IMAP
        993, 995,          # IMAPS/POP3S
    }
    
    # High-risk ports (for potential future enhancement)
    HIGH_RISK_PORTS = {
        21,    # FTP
        23,    # Telnet
        445,   # SMB
        3389,  # RDP
        5900,  # VNC
    }
    
    @classmethod
    def is_benign_port(cls, port: Optional[int]) -> bool:
        """Check if port is considered benign"""
        if port is None:
            return False
        return port in cls.BENIGN_PORTS
    
    @classmethod
    def is_high_risk_port(cls, port: Optional[int]) -> bool:
        """Check if port is considered high risk"""
        if port is None:
            return False
        return port in cls.HIGH_RISK_PORTS
    
    @classmethod
    def get_port_category(cls, port: Optional[int]) -> str:
        """Get category of a port"""
        if port is None:
            return "unknown"
        if port in cls.BENIGN_PORTS:
            return "benign"
        if port in cls.HIGH_RISK_PORTS:
            return "high_risk"
        return "normal"
