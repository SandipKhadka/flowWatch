"""Combined traffic filtering logic"""

from typing import Optional, Set
from .ip_filter import IPFilter
from .port_filter import PortFilter


class TrafficFilter:
    """Orchestrate all traffic filtering logic"""
    
    def __init__(self, local_ips: Optional[Set[str]] = None):
        """
        Initialize traffic filter
        
        Args:
            local_ips: Set of local IP addresses to filter out
        """
        self.local_ips = local_ips or set()
        self.ip_filter = IPFilter()
        self.port_filter = PortFilter()
    
    def should_process_packet(self, src_ip: str, dst_ip: str, dst_port: Optional[int] = None) -> tuple[bool, str]:
        """
        Determine if a packet should be processed by ML
        
        Returns:
            (should_process, reason)
        """
        # Filter private/local IPs
        if self.ip_filter.is_private_or_local(src_ip):
            return False, "private_source_ip"
        
        if self.ip_filter.is_private_or_local(dst_ip):
            return False, "private_dest_ip"
        
        # Filter own machine traffic
        if src_ip in self.local_ips or dst_ip in self.local_ips:
            return False, "local_traffic"
        
        # Filter benign ports
        if dst_port and self.port_filter.is_benign_port(dst_port):
            return False, f"benign_port_{dst_port}"
        
        return True, "ok"
    
    def update_local_ips(self, local_ips: Set[str]) -> None:
        """Update the set of local IP addresses"""
        self.local_ips = local_ips
