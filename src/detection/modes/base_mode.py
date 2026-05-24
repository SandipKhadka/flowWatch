"""Base class for detection modes"""

from abc import ABC, abstractmethod  # Fixed: Added ABC
from typing import Optional
import threading


class DetectionMode(ABC):
    """Abstract base class for detection modes"""
    
    def __init__(self, packet_handler, alert_handler):
        """
        Initialize detection mode
        
        Args:
            packet_handler: Packet handler instance
            alert_handler: Alert handler instance
        """
        self.packet_handler = packet_handler
        self.alert_handler = alert_handler
        self.is_running = False
        self.thread = None
    
    @abstractmethod
    def run(self) -> None:
        """Run the detection mode"""
        pass
    
    def start(self) -> bool:
        """Start the detection mode"""
        if self.is_running:
            return False
        
        self.is_running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        return True
    
    def stop(self) -> None:
        """Stop the detection mode"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3)
    
    @abstractmethod
    def get_mode_name(self) -> str:
        """Get the name of this detection mode"""
        pass
