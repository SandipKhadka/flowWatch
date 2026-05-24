"""Packet processing and classification"""

from typing import Dict, Any, Optional, Tuple
from .feature_extractor import FeatureExtractor
from ..filters.traffic_filter import TrafficFilter
from ..utils.severity_map import SeverityMap


class PacketHandler:
    """Handle packet processing and ML classification"""
    
    def __init__(self, model_loader, alert_handler):
        """
        Initialize packet handler
        
        Args:
            model_loader: ML model loader instance
            alert_handler: Alert handler instance
        """
        self.model_loader = model_loader
        self.alert_handler = alert_handler
        self.feature_extractor = FeatureExtractor()
        self.traffic_filter = None  # Will be set later
        self.severity_map = SeverityMap()
        
        # Statistics
        self.packet_count = 0
        self.threat_count = 0
    
    def set_traffic_filter(self, traffic_filter: TrafficFilter) -> None:
        """Set the traffic filter instance"""
        self.traffic_filter = traffic_filter
    
    def process_packet(self, packet, packet_id: int) -> Optional[Dict[str, Any]]:
        """
        Process a single packet
        
        Args:
            packet: Scapy packet object
            packet_id: Sequential packet ID
            
        Returns:
            Alert dictionary if threat detected, None otherwise
        """
        self.packet_count += 1
        
        if not self.model_loader.is_loaded:
            return None
        
        try:
            # Extract packet information
            packet_info = self._extract_packet_info(packet)
            
            if not packet_info:
                return None
            
            # Apply traffic filtering
            if self.traffic_filter:
                should_process, reason = self.traffic_filter.should_process_packet(
                    packet_info['src_ip'],
                    packet_info['dst_ip'],
                    packet_info.get('dst_port')
                )
                
                if not should_process:
                    return None
            
            # Extract features
            features = self.feature_extractor.extract_features(
                packet, 
                packet_info['protocol']
            )
            
            # Run ML prediction
            prediction, confidence, _ = self.model_loader.predict(features)
            
            # Check if threat
            if prediction.lower() in ('normal', 'benign', 'unknown'):
                return None
            
            # Check severity
            severity_info = self.severity_map.get_severity(prediction)
            
            # Check if should alert
            should_alert, reasons = self.alert_handler.should_alert(
                confidence, 
                severity_info.score
            )
            
            if should_alert:
                self.threat_count += 1
                
                alert_data = {
                    'src_ip': packet_info['src_ip'],
                    'dst_ip': packet_info['dst_ip'],
                    'protocol': packet_info['protocol'],
                    'packet_size': packet_info['packet_size'],
                    'attack_type': prediction,
                    'confidence': confidence,
                    'severity': severity_info.score,
                    'severity_level': severity_info.level,
                    'icon': severity_info.icon,
                    'packet_id': packet_id,
                    'alert_reason': f"{confidence*100:.0f}% confidence, external IP",
                }
                
                return self.alert_handler.create_alert(alert_data)
        
        except Exception as e:
            # Silent fail for malformed packets
            pass
        
        return None
    
    def _extract_packet_info(self, packet) -> Optional[Dict[str, Any]]:
        """Extract basic information from packet"""
        try:
            import scapy.all as scapy
            
            if not packet.haslayer(scapy.IP):
                return None
            
            info = {
                'src_ip': packet[scapy.IP].src,
                'dst_ip': packet[scapy.IP].dst,
                'packet_size': len(packet),
                'dst_port': None,
                'protocol': 'Other'
            }
            
            # Determine protocol and extract port if applicable
            if packet.haslayer(scapy.TCP):
                info['protocol'] = 'TCP'
                info['dst_port'] = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                info['protocol'] = 'UDP'
                info['dst_port'] = packet[scapy.UDP].dport
            elif packet.haslayer(scapy.ICMP):
                info['protocol'] = 'ICMP'
            
            return info
            
        except Exception:
            return None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get packet handler statistics"""
        return {
            'packets_processed': self.packet_count,
            'threats_detected': self.threat_count,
            'threat_rate': (self.threat_count / max(self.packet_count, 1)) * 100,
        }
    
    def reset_stats(self) -> None:
        """Reset statistics counters"""
        self.packet_count = 0
        self.threat_count = 0
