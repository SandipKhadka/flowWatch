# src/response/firewall_manager.py
import subprocess
import platform

class FirewallManager:
    """Cross-platform firewall management"""
    
    def __init__(self):
        self.os_type = platform.system()
    
    def block_ip(self, ip, duration_minutes=60):
        """Block IP across multiple platforms"""
        if self.os_type == "Linux":
            # iptables
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            subprocess.run(cmd, shell=True)
            
            # Auto unblock after duration
            import threading
            threading.Timer(duration_minutes * 60, self.unblock_ip, args=[ip]).start()
            
        elif self.os_type == "Windows":
            # netsh
            cmd = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True)
        
        elif self.os_type == "Darwin":  # macOS
            cmd = f"sudo pfctl -t blocked -T add {ip}"
            subprocess.run(cmd, shell=True)
        
        return True
    
    def unblock_ip(self, ip):
        """Unblock IP address"""
        if self.os_type == "Linux":
            cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
        elif self.os_type == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="Block_{ip}"'
        elif self.os_type == "Darwin":
            cmd = f"sudo pfctl -t blocked -T delete {ip}"
        
        subprocess.run(cmd, shell=True)
        return True
    
    def get_firewall_rules(self):
        """List current firewall rules"""
        if self.os_type == "Linux":
            result = subprocess.run("sudo iptables -L INPUT -n", shell=True, capture_output=True, text=True)
            return result.stdout
        return "Firewall rules not available"
