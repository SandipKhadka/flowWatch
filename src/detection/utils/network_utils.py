"""Network utility functions"""

import socket
import subprocess
import os


class NetworkUtils:
    """Network-related utility functions"""
    
    @staticmethod
    def is_connected(timeout: float = 1.5) -> bool:
        """
        Lightweight connectivity check.
        Tries non-blocking TCP connect to Google DNS.
        
        Args:
            timeout: Connection timeout in seconds
            
        Returns:
            True if internet connectivity is available
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(("8.8.8.8", 53))
            sock.close()
            return True
        except OSError:
            return False
    
    @staticmethod
    def get_available_interface() -> str:
        """
        Return the best non-loopback network interface.
        Prefers interfaces with default route.
        
        Returns:
            Interface name or 'lo' as fallback
        """
        # Priority 1: Default route interface
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, 
                text=True, 
                timeout=2
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if 'dev' in parts:
                    return parts[parts.index('dev') + 1]
        except Exception:
            pass
        
        # Priority 2: Any UP interface with IPv4 (non-loopback)
        try:
            result = subprocess.run(
                ['ip', '-o', 'addr', 'show', 'up'],
                capture_output=True, 
                text=True, 
                timeout=2
            )
            for line in result.stdout.splitlines():
                if 'inet ' in line and 'lo' not in line:
                    return line.split()[1]
        except Exception:
            pass
        
        # Priority 3: Common interface names
        common_interfaces = ['eth0', 'ens33', 'enp2s0', 'wlan0', 'wlo1', 'wlp2s0']
        for iface in common_interfaces:
            try:
                result = subprocess.run(
                    ['ip', 'link', 'show', iface],
                    capture_output=True, 
                    timeout=1
                )
                if result.returncode == 0:
                    return iface
            except Exception:
                pass
        
        return 'lo'  # Fallback to loopback
    
    @staticmethod
    def requires_root() -> bool:
        """Check if process has root privileges"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
