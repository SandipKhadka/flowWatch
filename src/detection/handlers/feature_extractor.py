"""Feature extraction from packets"""

import numpy as np
from typing import Dict, Any, Optional


class FeatureExtractor:
    """Extract NSL-KDD compatible features from packets"""
    
    # Protocol mapping for NSL-KDD dataset
    PROTOCOL_MAP = {
        'TCP': 0,
        'UDP': 1,
        'ICMP': 2,
        'Other': 3
    }
    
    def __init__(self):
        """Initialize feature extractor"""
        self._feature_names = self._get_feature_names()
    
    def _get_feature_names(self) -> list:
        """Get list of feature names for NSL-KDD dataset"""
        return [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate'
        ]
    
    def extract_features(self, packet, protocol: str) -> np.ndarray:
        """
        Extract features from a packet
        
        Args:
            packet: Scapy packet object
            protocol: Protocol name (TCP/UDP/ICMP/Other)
            
        Returns:
            Feature vector as numpy array
        """
        features = self._get_default_features(protocol)
        
        # TCP-specific enrichment
        if protocol == 'TCP' and self._has_layer(packet, 'TCP'):
            features = self._enrich_tcp_features(features, packet)
        
        # Convert to numpy array in correct order
        feature_vector = np.array([features[name] for name in self._feature_names])
        return feature_vector
    
    def _get_default_features(self, protocol: str) -> Dict[str, float]:
        """Get default feature values"""
        return {
            'duration': 0.0,
            'protocol_type': self.PROTOCOL_MAP.get(protocol, 3),
            'service': 0,
            'flag': 0,
            'src_bytes': 0.0,
            'dst_bytes': 0.0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0,
        }
    
    def _enrich_tcp_features(self, features: Dict[str, float], packet) -> Dict[str, float]:
        """Add TCP-specific features"""
        try:
            tcp_layer = packet['TCP']
            features['flag'] = int(tcp_layer.flags)
            features['urgent'] = int(tcp_layer.urgptr > 0)
            
            # SYN flood detection indicator
            if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
                features['serror_rate'] = 1.0
        except Exception:
            pass
        
        return features
    
    def _has_layer(self, packet, layer_name: str) -> bool:
        """Check if packet has a specific layer"""
        try:
            return layer_name in packet
        except Exception:
            return False
    
    def get_feature_count(self) -> int:
        """Get number of features"""
        return len(self._feature_names)
