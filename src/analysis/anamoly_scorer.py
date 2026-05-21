# src/analysis/anomaly_scorer.py
from scipy import stats
import numpy as np

class AnomalyScorer:
    """Multi-dimensional anomaly detection"""
    
    def __init__(self):
        self.baseline_stats = {}
    
    def calculate_anomaly_score(self, current_metrics, baseline):
        """Calculate comprehensive anomaly score"""
        scores = []
        
        # Packet rate anomaly
        if 'packet_rate' in current_metrics and 'packet_rate' in baseline:
            z_score = abs(current_metrics['packet_rate'] - baseline['packet_rate_mean']) / baseline['packet_rate_std']
            scores.append(min(z_score / 3, 1.0))  # Normalize to 0-1
        
        # Protocol distribution anomaly
        if 'protocols' in current_metrics and 'protocols' in baseline:
            for proto in baseline['protocols']:
                diff = abs(current_metrics['protocols'].get(proto, 0) - baseline['protocols'][proto])
                scores.append(min(diff / 0.3, 1.0))
        
        # IP entropy anomaly
        if 'ip_entropy' in current_metrics and 'ip_entropy_baseline' in baseline:
            entropy_diff = abs(current_metrics['ip_entropy'] - baseline['ip_entropy_baseline'])
            scores.append(min(entropy_diff / 2, 1.0))
        
        # Weighted average
        if scores:
            anomaly_score = np.mean(scores)
            return {
                'score': anomaly_score,
                'level': 'Critical' if anomaly_score > 0.8 else 'High' if anomaly_score > 0.6 else 'Medium' if anomaly_score > 0.3 else 'Low',
                'contributing_factors': len(scores)
            }
        
        return {'score': 0, 'level': 'Normal', 'contributing_factors': 0}
