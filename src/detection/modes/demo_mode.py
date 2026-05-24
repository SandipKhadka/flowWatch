"""Demo mode for simulation"""

import time
import random
from typing import List, Tuple
from .base_mode import DetectionMode


class DemoMode(DetectionMode):
    """Demo mode with realistic threat simulation"""
    
    def __init__(self, packet_handler, alert_handler):
        """Initialize demo mode"""
        super().__init__(packet_handler, alert_handler)
        
        # Traffic patterns
        self.normal_traffic = self._create_normal_traffic()
        self.attack_traffic = self._create_attack_traffic()
        self.attack_source_ips = self._get_attack_source_ips()
        
        # Simulation parameters
        self.packets_per_second = 5
        self.attack_rate = 0.02  # 2% attack rate
    
    def _create_normal_traffic(self) -> List[Tuple[str, float]]:
        """Create normal traffic patterns"""
        return [('normal', round(random.uniform(0.88, 0.99), 3)) for _ in range(98)]
    
    def _create_attack_traffic(self) -> List[Tuple[str, float]]:
        """Create attack traffic patterns with realistic confidences"""
        return [
            ('ddos', 0.97), ('ddos', 0.95),
            ('brute_force', 0.96), ('brute_force', 0.93),
            ('web_attack', 0.94), ('web_attack', 0.92),
            ('port_scan', 0.93), ('nmap', 0.91),
            ('botnet', 0.96), ('infiltration', 0.98),
        ]
    
    def _get_attack_source_ips(self) -> List[str]:
        """Get external IPs for simulated attacks"""
        return [
            '185.130.5.253', '45.155.205.233', '103.108.80.10',
            '91.108.4.15', '198.51.100.42', '203.0.113.99',
            '198.18.0.55', '5.188.206.14', '62.210.180.229',
            '195.54.162.230',
        ]
    
    def run(self) -> None:
        """Run demo mode simulation"""
        print("🎮 Demo Mode – realistic threat simulation")
        print(f"   Attack rate: {self.attack_rate * 100:.1f}%")
        print(f"   Thresholds: confidence > {self.alert_handler.config.min_confidence*100:.0f}%, severity {self.alert_handler.config.min_severity}+")
        print("=" * 55)
        
        # Create weighted traffic pool
        all_traffic = self.normal_traffic + self.attack_traffic
        normal_count = len(self.normal_traffic)
        attack_count = len(self.attack_traffic)
        
        weights = ([self.attack_rate / attack_count] * attack_count + 
                   [(1 - self.attack_rate) / normal_count] * normal_count)
        
        packet_id = 0
        
        while self.is_running:
            time.sleep(1.0 / self.packets_per_second)
            packet_id += 1
            
            # Generate traffic
            label, confidence = random.choices(all_traffic, weights=weights, k=1)[0]
            
            # Skip normal traffic (no alert)
            if label == 'normal':
                continue
            
            # Process attack
            self.packet_handler.packet_count += 1
            self._simulate_attack(label, confidence, packet_id)
            
            # Progress heartbeat
            if packet_id % 500 == 0:
                stats = self.packet_handler.get_stats()
                print(f"📊 {stats['packets_processed']} pkts | "
                      f"{stats['threats_detected']} threats | "
                      f"{stats['threat_rate']:.2f}% threat rate")
    
    def _simulate_attack(self, attack_type: str, confidence: float, packet_id: int) -> None:
        """Simulate an attack packet"""
        from ..utils.severity_map import SeverityMap
        
        severity_info = SeverityMap.get_severity(attack_type)
        should_alert, _ = self.alert_handler.should_alert(
            confidence, 
            severity_info.score
        )
        
        if should_alert:
            alert_data = {
                'src_ip': random.choice(self.attack_source_ips),
                'dst_ip': '192.168.1.100',  # Simulated local IP
                'protocol': random.choice(['TCP', 'UDP']),
                'packet_size': random.randint(64, 1500),
                'attack_type': attack_type,
                'confidence': confidence,
                'severity': severity_info.score,
                'severity_level': severity_info.level,
                'icon': severity_info.icon,
                'packet_id': packet_id,
                'alert_reason': f"High-confidence external threat ({confidence*100:.0f}%)",
            }
            
            alert = self.alert_handler.create_alert(alert_data)
            print(f"{severity_info.icon} {severity_info.level:8} | "
                  f"{attack_type.upper():15} | {alert['source_ip']} | "
                  f"{confidence*100:.0f}%")
    
    def get_mode_name(self) -> str:
        return "demo"
