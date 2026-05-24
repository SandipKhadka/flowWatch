"""Live packet capture mode"""

from .base_mode import DetectionMode
from ..filters.ip_filter import IPFilter
import os


class LiveMode(DetectionMode):
    """Live packet capture with real network traffic"""
    
    def __init__(self, packet_handler, alert_handler, interface: str):
        """
        Initialize live mode
        
        Args:
            packet_handler: Packet handler instance
            alert_handler: Alert handler instance
            interface: Network interface to capture from
        """
        super().__init__(packet_handler, alert_handler)
        self.interface = interface
        self.packet_id = 0  # Move packet_id to instance variable
        
        # Network utilities
        from ..utils.network_utils import NetworkUtils
        self.network_utils = NetworkUtils()
        self.ip_filter = IPFilter()
    
    def run(self) -> None:
        """Run live packet capture"""
        import scapy.all as scapy
        
        # Update local IPs
        local_ips = self.ip_filter.get_local_ips()
        if self.packet_handler.traffic_filter:
            self.packet_handler.traffic_filter.update_local_ips(local_ips)
        
        print(f"🔴 Live capture on interface: {self.interface}")
        print(f"   Filtering: external IPs only, no private/loopback/own-IPs")
        print(f"   Packet handler active")
        print("=" * 55)
        
        # Reset packet counter
        self.packet_id = 0
        
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._handle_packet,  # Pass method directly
                store=False,
                filter="ip",  # IPv4 only
                stop_filter=lambda _: not self.is_running,
            )
        except PermissionError:
            print("❌ Permission denied. Run with: sudo streamlit run app.py")
            self.is_running = False
        except Exception as e:
            print(f"❌ Live capture error: {e}")
            self.is_running = False
    
    def _handle_packet(self, packet) -> None:
        """Handle captured packet"""
        self.packet_id += 1
        alert = self.packet_handler.process_packet(packet, self.packet_id)
        
        if alert:
            print(f"{alert['icon']} {alert['severity_level']:8} | "
                  f"{alert['attack_type'].upper():15} | "
                  f"{alert['source_ip']} → {alert['destination_ip']} | "
                  f"{alert['confidence']*100:.0f}%")
    
    def get_mode_name(self) -> str:
        return "live"
