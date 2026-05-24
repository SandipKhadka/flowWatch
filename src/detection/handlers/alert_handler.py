"""Alert management and rate limiting"""

import time
from typing import List, Dict, Any, Tuple
from collections import deque
from dataclasses import dataclass


@dataclass
class AlertConfig:
    """Configuration for alert handling"""
    min_confidence: float = 0.92
    min_severity: int = 5
    max_alerts_per_minute: int = 8
    rate_limit_window: int = 60  # seconds


class AlertHandler:
    """Handle alert creation, filtering, and rate limiting"""
    
    def __init__(self, config: AlertConfig = None):
        """
        Initialize alert handler
        
        Args:
            config: Alert configuration
        """
        self.config = config or AlertConfig()
        self._alert_timestamps: deque = deque(maxlen=1000)
        self.alerts_history: List[Dict[str, Any]] = []
    
    def should_alert(self, confidence: float, severity: int) -> Tuple[bool, List[str]]:
        """
        Determine if an alert should be raised
        
        Args:
            confidence: ML model confidence (0-1)
            severity: Severity score (0-10)
            
        Returns:
            (should_alert, reasons_for_not_alerting)
        """
        reasons = []
        
        # Check confidence threshold
        if confidence < self.config.min_confidence:
            reasons.append(
                f"confidence {confidence*100:.0f}% < {self.config.min_confidence*100:.0f}%"
            )
        
        # Check severity threshold
        if severity < self.config.min_severity:
            reasons.append(f"severity {severity} < {self.config.min_severity}")
        
        # Rate limiting
        now = time.time()
        # Remove old timestamps
        while self._alert_timestamps and now - self._alert_timestamps[0] > self.config.rate_limit_window:
            self._alert_timestamps.popleft()
        
        if len(self._alert_timestamps) >= self.config.max_alerts_per_minute:
            reasons.append(
                f"rate limit ({self.config.max_alerts_per_minute}/min)"
            )
        
        should_alert = len(reasons) == 0
        
        if should_alert:
            self._alert_timestamps.append(now)
        
        return should_alert, reasons
    
    def create_alert(self, packet_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an alert from packet data
        
        Args:
            packet_data: Dictionary containing packet information
            
        Returns:
            Formatted alert dictionary
        """
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet_data.get("src_ip", "unknown"),
            "destination_ip": packet_data.get("dst_ip", "unknown"),
            "protocol": packet_data.get("protocol", "unknown"),
            "packet_size": packet_data.get("packet_size", 0),
            "attack_type": packet_data.get("attack_type", "unknown"),
            "confidence": packet_data.get("confidence", 0.0),
            "severity": packet_data.get("severity", 0),
            "severity_level": packet_data.get("severity_level", "UNKNOWN"),
            "icon": packet_data.get("icon", "❓"),
            "status": "THREAT",
            "packet_id": packet_data.get("packet_id", 0),
            "alert_reason": packet_data.get("alert_reason", "ML detection"),
        }
        
        self.alerts_history.append(alert)
        return alert
    
    def get_stats(self) -> Dict[str, Any]:
        """Get alert handler statistics"""
        return {
            "total_alerts": len(self.alerts_history),
            "current_rate": len(self._alert_timestamps),
            "max_rate_allowed": self.config.max_alerts_per_minute,
            "min_confidence": self.config.min_confidence,
            "min_severity": self.config.min_severity,
        }
    
    def update_config(self, **kwargs):
        """Update alert configuration dynamically"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
