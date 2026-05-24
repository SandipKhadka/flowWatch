"""IP address filtering utilities"""

import ipaddress
import socket
import subprocess
from typing import Set


class IPFilter:
    """Handle IP address validation and filtering"""
    
    # Private IP ranges to filter out
    PRIVATE_RANGES = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '169.254.0.0/16',  # Link-local
        '127.0.0.0/8',     # Loopback
        '224.0.0.0/4',     # Multicast
        '240.0.0.0/4',     # Reserved
    ]
    
    @classmethod
    def is_private_or_local(cls, ip: str) -> bool:
        """
        Return True for loopback, link-local, private, multicast, 
        and reserved addresses.
        """
        if not ip:
            return True
            
        try:
            addr = ipaddress.ip_address(ip)
            return (
                addr.is_loopback or
                addr.is_link_local or
                addr.is_private or
                addr.is_multicast or
                addr.is_reserved or
                addr.is_unspecified
            )
        except ValueError:
            return True  # Invalid IP → treat as private/safe
    
    @classmethod
    def get_local_ips(cls) -> Set[str]:
        """Collect all IPs assigned to this machine (all interfaces)"""
        local = set()
        
        # Try using ip command (Linux)
        try:
            result = subprocess.run(
                ['ip', '-o', 'addr', 'show'],
                capture_output=True, 
                text=True, 
                timeout=3
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                for part in parts:
                    if '/' in part and cls._is_valid_ip(part.split('/')[0]):
                        try:
                            local.add(str(ipaddress.ip_interface(part).ip))
                        except Exception:
                            pass
        except Exception:
            pass
        
        # Always include hostname-resolved IP
        try:
            local.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
            
        return local
    
    @classmethod
    def _is_valid_ip(cls, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
