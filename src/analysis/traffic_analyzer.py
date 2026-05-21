# src/analysis/traffic_analyzer.py
import pandas as pd
import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

class TrafficAnalyzer:
    """Advanced traffic pattern analysis"""
    
    def __init__(self):
        self.traffic_history = defaultdict(list)
        self.baseline = None
        
    def analyze_packet_bursts(self, packet_timestamps: List[datetime]) -> Dict:
        """Detect packet bursts (potential DoS)"""
        if len(packet_timestamps) < 10:
            return {'burst_detected': False}
        
        # Calculate inter-arrival times
        timestamps_sec = [ts.timestamp() for ts in packet_timestamps]
        inter_arrival = np.diff(timestamps_sec)
        
        # Detect bursts (sudden high frequency)
        mean_inter = np.mean(inter_arrival)
        std_inter = np.std(inter_arrival)
        
        bursts = []
        current_burst = []
        
        for i, interval in enumerate(inter_arrival):
            if interval < mean_inter - std_inter:
                current_burst.append(i)
            else:
                if len(current_burst) > 5:
                    bursts.append(current_burst)
                current_burst = []
        
        return {
            'burst_detected': len(bursts) > 0,
            'burst_count': len(bursts),
            'avg_frequency': 1/mean_inter if mean_inter > 0 else 0,
            'max_burst_size': max([len(b) for b in bursts]) if bursts else 0
        }
    
    def detect_port_scanning(self, connection_logs: List[Dict]) -> Dict:
        """Detect port scanning patterns"""
        source_scans = defaultdict(set)
        
        for log in connection_logs:
            if 'dst_port' in log and 'src_ip' in log:
                source_scans[log['src_ip']].add(log['dst_port'])
        
        # Detect scanners (tried many ports)
        scanners = {
            ip: ports for ip, ports in source_scans.items() 
            if len(ports) > 20
        }
        
        return {
            'scanners_detected': len(scanners),
            'scanner_details': scanners,
            'max_ports_scanned': max([len(p) for p in scanners.values()]) if scanners else 0
        }
    
    def calculate_traffic_entropy(self, ip_addresses: List[str]) -> float:
        """Calculate entropy of IP distribution"""
        from collections import Counter
        import math
        
        if not ip_addresses:
            return 0.0
        
        counter = Counter(ip_addresses)
        total = len(ip_addresses)
        
        entropy = 0
        for count in counter.values():
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def establish_baseline(self, normal_traffic: List[Dict]):
        """Establish normal traffic baseline"""
        self.baseline = {
            'packet_rate': np.mean([t['packet_rate'] for t in normal_traffic]),
            'packet_rate_std': np.std([t['packet_rate'] for t in normal_traffic]),
            'protocol_distribution': defaultdict(float),
            'avg_packet_size': np.mean([t['avg_packet_size'] for t in normal_traffic]),
            'connection_rate': np.mean([t['connection_rate'] for t in normal_traffic])
        }
        
        # Calculate protocol distribution
        for traffic in normal_traffic:
            for proto, ratio in traffic.get('protocols', {}).items():
                self.baseline['protocol_distribution'][proto] += ratio
        
        # Normalize
        total = sum(self.baseline['protocol_distribution'].values())
        if total > 0:
            for proto in self.baseline['protocol_distribution']:
                self.baseline['protocol_distribution'][proto] /= total
    
    def detect_anomalies(self, current_traffic: Dict) -> Dict:
        """Detect anomalies compared to baseline"""
        if not self.baseline:
            return {'anomaly_detected': False, 'reason': 'No baseline established'}
        
        anomalies = []
        
        # Check packet rate
        packet_rate = current_traffic.get('packet_rate', 0)
        if abs(packet_rate - self.baseline['packet_rate']) > 3 * self.baseline['packet_rate_std']:
            anomalies.append({
                'type': 'High Packet Rate',
                'current': packet_rate,
                'baseline': self.baseline['packet_rate'],
                'severity': 'High'
            })
        
        # Check protocol anomalies
        for proto, baseline_ratio in self.baseline['protocol_distribution'].items():
            current_ratio = current_traffic.get('protocols', {}).get(proto, 0)
            if abs(current_ratio - baseline_ratio) > 0.3:  # 30% deviation
                anomalies.append({
                    'type': f'Protocol Anomaly - {proto}',
                    'current': current_ratio,
                    'baseline': baseline_ratio,
                    'severity': 'Medium'
                })
        
        return {
            'anomaly_detected': len(anomalies) > 0,
            'anomalies': anomalies,
            'severity': max([a['severity'] for a in anomalies], default='Low')
        }
