# src/intelligence/ioc_extractor.py
import re
from collections import defaultdict

class IoCExtractor:
    """Extract Indicators of Compromise from traffic"""
    
    def __init__(self):
        self.iocs = {
            'ip_addresses': [],
            'domains': [],
            'file_hashes': [],
            'urls': [],
            'email_addresses': []
        }
    
    def extract_from_packet(self, packet):
        """Extract IoCs from network packet"""
        iocs_found = defaultdict(list)
        
        # Extract IPs
        if hasattr(packet, 'src'):
            iocs_found['ip_addresses'].append(packet.src)
        if hasattr(packet, 'dst'):
            iocs_found['ip_addresses'].append(packet.dst)
        
        # Extract domains from DNS
        if hasattr(packet, 'qd') and hasattr(packet.qd, 'qname'):
            domain = packet.qd.qname.decode('utf-8').rstrip('.')
            iocs_found['domains'].append(domain)
        
        # Extract URLs from HTTP
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'Host'):
                iocs_found['domains'].append(packet.http.Host.decode())
            if hasattr(packet.http, 'uri'):
                iocs_found['urls'].append(packet.http.uri.decode())
        
        return dict(iocs_found)
    
    def generate_stix_report(self, iocs):
        """Generate STIX format report (industry standard)"""
        stix_report = {
            "type": "bundle",
            "id": f"bundle--{datetime.now().timestamp()}",
            "objects": []
        }
        
        for ioc_type, ioc_list in iocs.items():
            for ioc in ioc_list:
                stix_report["objects"].append({
                    "type": "indicator",
                    "id": f"indicator--{hash(ioc)}",
                    "pattern": f"[{ioc_type}:value = '{ioc}']",
                    "valid_from": datetime.now().isoformat()
                })
        
        return stix_report
