"""
Real-time IDS - Refactored Production Version v3.0
More maintainable, scalable, and readable
"""

import warnings
import sys
import os

warnings.filterwarnings("ignore")

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.model_loader import ModelLoader
from detection.handlers import AlertHandler, PacketHandler
from detection.handlers.alert_handler import AlertConfig
from detection.filters import TrafficFilter, IPFilter
from detection.modes import DemoMode, LiveMode
from detection.utils import NetworkUtils


class RealTimeIDS:
    """
    Real-time Intrusion Detection System
    Handles both live capture and demo modes with robust filtering
    """
    
    def __init__(self, model_dir="src/models", alert_config: AlertConfig = None):
        """
        Initialize the IDS
        
        Args:
            model_dir: Directory containing ML models
            alert_config: Alert configuration (optional)
        """
        print("🔧 Initialising Real-Time IDS v3.0 (Refactored Edition)…")
        print("=" * 55)
        
        # Initialize components
        self.model_loader = ModelLoader(model_dir)
        self.alert_handler = AlertHandler(alert_config or AlertConfig())
        self.packet_handler = PacketHandler(self.model_loader, self.alert_handler)
        
        # Initialize filters
        self.ip_filter = IPFilter()
        local_ips = self.ip_filter.get_local_ips()
        self.traffic_filter = TrafficFilter(local_ips)
        self.packet_handler.set_traffic_filter(self.traffic_filter)
        
        # Detection mode
        self.current_mode = None
        self.network_utils = NetworkUtils()
        
        # Backward compatibility attributes
        self.mode = "demo"  # Default mode
        self.min_confidence = self.alert_handler.config.min_confidence
        self.min_severity = self.alert_handler.config.min_severity
        self.max_alerts_per_minute = self.alert_handler.config.max_alerts_per_minute
        
        # Alert queue for backward compatibility
        self.alert_queue = None  # Will be handled by get_alerts()
        self.packet_count = 0
        self.threat_count = 0
        self.alerts_history = []
        self.is_running = False
        self.thread = None
        
        # Display configuration
        self._display_configuration()
    
    def _display_configuration(self) -> None:
        """Display IDS configuration"""
        if self.model_loader.is_loaded:
            print("✅ ML models loaded successfully.")
            info = self.model_loader.get_model_info()
            print(f"   Attack classes : {info.get('attack_classes', 'N/A')}")
            print(f"   Feature count  : {info.get('feature_count', 'N/A')}")
        else:
            print("⚠️  Models not found – will run in Demo mode.")
        
        print(f"\n🔒 Alert Configuration:")
        print(f"   Min confidence : {self.alert_handler.config.min_confidence * 100:.0f}%")
        print(f"   Min severity   : {self.alert_handler.config.min_severity}+")
        print(f"   Rate limit     : ≤{self.alert_handler.config.max_alerts_per_minute} alerts/minute")
    
    # Backward compatibility properties
    @property
    def min_confidence(self):
        return self.alert_handler.config.min_confidence
    
    @min_confidence.setter
    def min_confidence(self, value):
        self.alert_handler.config.min_confidence = value
    
    @property
    def min_severity(self):
        return self.alert_handler.config.min_severity
    
    @min_severity.setter
    def min_severity(self, value):
        self.alert_handler.config.min_severity = value
    
    @property
    def max_alerts_per_minute(self):
        return self.alert_handler.config.max_alerts_per_minute
    
    @max_alerts_per_minute.setter
    def max_alerts_per_minute(self, value):
        self.alert_handler.config.max_alerts_per_minute = value
    
    def start_sniffing(self, interface: str = "auto") -> bool:
        """
        Start packet capture and detection
        
        Args:
            interface: Network interface ('auto', 'demo', or specific interface name)
            
        Returns:
            True if started successfully
        """
        self.is_running = True
        
        if interface == "auto":
            # Check connectivity first
            if not self.network_utils.is_connected():
                print("📡 No network connectivity – switching to Demo mode automatically.")
                return self._start_demo_mode()
            
            interface = self.network_utils.get_available_interface()
            print(f"🔍 Selected interface: {interface}")
        
        if interface == "demo":
            return self._start_demo_mode()
        
        return self._start_live_mode(interface)
    
    def _start_demo_mode(self) -> bool:
        """Start demo mode"""
        print("🎮 Starting Demo mode…")
        self.mode = "demo"
        self.current_mode = DemoMode(self.packet_handler, self.alert_handler)
        self.current_mode.start()
        
        # Update backward compatibility attributes
        self.packet_count = self.packet_handler.packet_count
        self.threat_count = self.packet_handler.threat_count
        self.alerts_history = self.alert_handler.alerts_history
        self.thread = self.current_mode.thread if self.current_mode else None
        
        return True
    
    def _start_live_mode(self, interface: str) -> bool:
        """Start live capture mode"""
        # Check root privileges
        if not self.network_utils.requires_root():
            print("❌ Live capture requires root privileges.")
            print("   Run: sudo streamlit run app.py")
            print("🎮 Falling back to Demo mode…")
            return self._start_demo_mode()
        
        print(f"🔴 Starting live capture on {interface}…")
        self.mode = "live"
        self.current_mode = LiveMode(self.packet_handler, self.alert_handler, interface)
        self.current_mode.start()
        
        # Update backward compatibility attributes
        self.packet_count = self.packet_handler.packet_count
        self.threat_count = self.packet_handler.threat_count
        self.alerts_history = self.alert_handler.alerts_history
        self.thread = self.current_mode.thread if self.current_mode else None
        
        return True
    
    def get_alerts(self) -> list:
        """Get all alerts from the alert handler"""
        # For backward compatibility, return the alerts history
        return self.alert_handler.alerts_history
    
    def get_stats(self) -> dict:
        """Get IDS statistics"""
        packet_stats = self.packet_handler.get_stats()
        alert_stats = self.alert_handler.get_stats()
        
        # Update backward compatibility counters
        self.packet_count = packet_stats['packets_processed']
        self.threat_count = packet_stats['threats_detected']
        
        return {
            **packet_stats,
            **alert_stats,
            'is_running': self.current_mode.is_running if self.current_mode else False,
            'mode': self.current_mode.get_mode_name() if self.current_mode else "stopped",
            'min_confidence': self.alert_handler.config.min_confidence,
            'min_severity': self.alert_handler.config.min_severity,
        }
    
    def stop(self) -> None:
        """Stop all detection activities"""
        self.is_running = False
        if self.current_mode:
            self.current_mode.stop()
        
        stats = self.get_stats()
        print(f"⛔ Stopped.  Packets: {stats['packets_processed']}  |  "
              f"Threats: {stats['threats_detected']}")
    
    def update_alert_config(self, **kwargs) -> None:
        """Update alert configuration dynamically"""
        self.alert_handler.update_config(**kwargs)
        
        # Update backward compatibility attributes
        self.min_confidence = self.alert_handler.config.min_confidence
        self.min_severity = self.alert_handler.config.min_severity
        self.max_alerts_per_minute = self.alert_handler.config.max_alerts_per_minute
        
        print("✅ Alert configuration updated")
        self._display_configuration()
    
    def reset_stats(self) -> None:
        """Reset all statistics"""
        self.packet_handler.reset_stats()
        self.alert_handler.alerts_history.clear()
        self.packet_count = 0
        self.threat_count = 0
        self.alerts_history = []
        print("📊 Statistics reset")


# For backward compatibility with existing code
def _is_private_or_local(ip: str) -> bool:
    """Legacy function for backward compatibility"""
    from detection.filters.ip_filter import IPFilter
    return IPFilter.is_private_or_local(ip)


def _get_local_ips() -> set:
    """Legacy function for backward compatibility"""
    from detection.filters.ip_filter import IPFilter
    return IPFilter.get_local_ips()


def _is_connected() -> bool:
    """Legacy function for backward compatibility"""
    from detection.utils.network_utils import NetworkUtils
    return NetworkUtils.is_connected()
