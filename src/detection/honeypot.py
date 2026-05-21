# src/detection/honeypot.py
import socket
import threading
from datetime import datetime

class SimpleHoneypot:
    """Decoy service to trap attackers"""
    
    def __init__(self, ports=[22, 23, 80, 443, 3389]):
        self.ports = ports
        self.attacks_logged = []
        self.is_running = False
    
    def start(self):
        """Start honeypot services"""
        self.is_running = True
        for port in self.ports:
            thread = threading.Thread(target=self.listen_port, args=(port,))
            thread.daemon = True
            thread.start()
        print(f"🍯 Honeypot active on ports: {self.ports}")
    
    def listen_port(self, port):
        """Listen on specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('0.0.0.0', port))
            server.listen(5)
            
            while self.is_running:
                client, addr = server.accept()
                self.log_attack(addr[0], port)
                client.close()
        except:
            pass
    
    def log_attack(self, ip, port):
        """Log honeypot interaction"""
        attack = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip,
            'target_port': port,
            'type': 'honeypot_trigger',
            'severity': 'Medium'
        }
        self.attacks_logged.append(attack)
        
        # Block IP automatically
        print(f"🍯 Honeypot triggered by {ip} on port {port}")
