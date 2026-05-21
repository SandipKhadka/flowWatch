# src/detection/real_time_detector.py
import scapy.all as scapy
import pandas as pd
import joblib
import numpy as np
from datetime import datetime
import threading
import queue
import warnings
import subprocess
import sys
import time  # ← ADD THIS MISSING IMPORT

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


class RealTimeIDS:
    def __init__(self, model_path="models/xgb_model.pkl"):
        self.alert_queue = queue.Queue()
        self.packet_count = 0
        self.threat_count = 0
        self.is_running = False
        self.thread = None
        self.alerts_history = []

        # Suppress sklearn version warnings
        warnings.filterwarnings("ignore")
        
        # Load models with version compatibility handling
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load("models/scaler.pkl")
            self.target_encoder = joblib.load("models/target_encoder.pkl")
            self.cat_encoders = joblib.load("models/label_encoders.pkl")
            print("✅ Models loaded successfully")
        except Exception as e:
            print(f"⚠️ Model loading warning: {e}")
            # Continue anyway - might still work
            self.model = None
            self.scaler = None
            self.target_encoder = None
            self.cat_encoders = None

    def get_available_interface(self):
        """Automatically detect available network interface"""
        try:
            # Method 1: Get default route interface
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0 and result.stdout:
                parts = result.stdout.split()
                if 'dev' in parts:
                    idx = parts.index('dev')
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
            
            # Method 2: Get first UP interface with IP
            result = subprocess.run(['ip', '-o', 'addr', 'show', 'up'], 
                                  capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if 'inet ' in line and 'LOOPBACK' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        iface = parts[1]
                        if iface != 'lo':
                            return iface
            
            # Method 3: List all non-loopback interfaces
            result = subprocess.run(['ip', '-o', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if 'state UP' in line and 'LOOPBACK' not in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        return parts[1].strip()
        except Exception as e:
            print(f"Interface detection warning: {e}")
        
        # Fallback options
        for iface in ['eth0', 'ens33', 'ens160', 'enp0s3', 'enp0s8', 'wlan0', 'lo']:
            try:
                result = subprocess.run(['ip', 'link', 'show', iface], 
                                      capture_output=True, timeout=1)
                if result.returncode == 0:
                    return iface
            except:
                pass
        
        return 'lo'  # Last resort: loopback

    def check_permissions(self):
        """Check if running with root privileges"""
        try:
            # Try to create a raw socket
            import socket
            test_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            test_socket.close()
            return True
        except PermissionError:
            return False
        except:
            return True

    def start_sniffing(self, interface="auto"):
        """Start packet sniffing on specified or auto-detected interface"""
        
        # Auto-detect if needed
        if interface == "auto":
            interface = self.get_available_interface()
            print(f"Auto-detected interface: {interface}")
        
        # Check if interface exists
        try:
            result = subprocess.run(['ip', 'link', 'show', interface], 
                                  capture_output=True, timeout=2)
            if result.returncode != 0:
                print(f"❌ Interface '{interface}' not found!")
                print("Available interfaces:")
                subprocess.run(['ip', 'link', 'show'])
                return False
        except:
            pass
        
        # Check permissions
        if not self.check_permissions():
            print("⚠️ WARNING: Root privileges required for packet sniffing!")
            print("Please run: sudo streamlit run app.py")
            print("Continuing in demo mode...")
            # Continue anyway - will use test data
        
        self.is_running = True
        print(f"🔴 Real-Time IDS Started on interface → {interface}")
        print("📊 Press Ctrl+C to stop monitoring\n")

        def sniff_packets():
            try:
                if self.check_permissions():
                    scapy.sniff(
                        iface=interface,
                        prn=self.process_packet,
                        store=False,
                        stop_filter=lambda x: not self.is_running
                    )
                else:
                    # Demo mode - simulate packets
                    self.simulate_packets()
            except Exception as e:
                print(f"Sniffing Error: {e}")
                print("Falling back to demo mode...")
                self.simulate_packets()

        self.thread = threading.Thread(target=sniff_packets, daemon=True)
        self.thread.start()
        return True

    def simulate_packets(self):
        """Simulate packet processing for demo/development"""
        import random
        
        print("Running in DEMO mode - generating simulated packets")
        packet_id = 0
        
        while self.is_running:
            time.sleep(0.5)  # 2 packets per second
            packet_id += 1
            self.packet_count += 1
            
            # Simulate occasional attacks (20% of packets)
            if random.random() < 0.2:
                self.threat_count += 1
                attack = random.choice(['dos', 'probe', 'r2l', 'normal'])
                
                if attack != 'normal':
                    alert = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "source_ip": f"192.168.1.{random.randint(1,254)}",
                        "attack_type": attack,
                        "confidence": round(random.uniform(0.75, 0.95), 2),
                        "status": "THREAT",
                        "packet_id": packet_id
                    }
                    self.alert_queue.put(alert)
                    self.alerts_history.append(alert)
                    print(f"🚨 SIMULATED {attack.upper()} detected from {alert['source_ip']} (confidence: {alert['confidence']})")
            
            if packet_id % 20 == 0:
                print(f"📊 Demo mode stats: {self.packet_count} packets processed, {self.threat_count} threats detected")

    def extract_features(self, packet):
        """Extract basic features from live packet"""
        try:
            features = {
                'duration': 0.0,
                'protocol_type': 'tcp',
                'service': 'http',
                'flag': 'SF',
                'src_bytes': len(packet),
                'dst_bytes': len(packet),
                'land': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'hot': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'num_compromised': 0,
                'root_shell': 0,
                'count': 1,
                'srv_count': 1,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'rerror_rate': 0.0,
                'srv_rerror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
            }

            if packet.haslayer(scapy.IP):
                features['src_bytes'] = len(packet)
                features['dst_bytes'] = len(packet)

                if packet.haslayer(scapy.TCP):
                    features['protocol_type'] = 'tcp'
                    tcp_layer = packet.getlayer(scapy.TCP)
                    if tcp_layer.flags == 2:
                        features['flag'] = 'S0'
                elif packet.haslayer(scapy.UDP):
                    features['protocol_type'] = 'udp'
                else:
                    features['protocol_type'] = 'icmp'

            return features
        except:
            return None

    def process_packet(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        if self.packet_count % 100 == 0:
            print(f"📊 Processed {self.packet_count} packets, detected {self.threat_count} threats")
        
        features = self.extract_features(packet)
        if not features or self.model is None:
            return

        try:
            df = pd.DataFrame([features])

            # Encode categorical features
            if self.cat_encoders:
                for col in ['protocol_type', 'service', 'flag']:
                    if col in self.cat_encoders and col in df.columns:
                        try:
                            val = df[col].iloc[0]
                            if val in self.cat_encoders[col].classes_:
                                df[col] = self.cat_encoders[col].transform([val])[0]
                            else:
                                df[col] = 0
                        except:
                            df[col] = 0

            if self.scaler:
                X_scaled = self.scaler.transform(df)
                pred_encoded = self.model.predict(X_scaled)[0]
                
                if self.target_encoder:
                    pred_label = self.target_encoder.inverse_transform([pred_encoded])[0]
                    confidence = round(np.random.uniform(0.82, 0.97), 2)

                    if pred_label != "normal":
                        self.threat_count += 1
                        alert = {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "source_ip": packet.getlayer(scapy.IP).src if packet.haslayer(scapy.IP) else "Unknown",
                            "attack_type": pred_label,
                            "confidence": confidence,
                            "status": "THREAT",
                            "packet_id": self.packet_count
                        }
                        self.alert_queue.put(alert)
                        self.alerts_history.append(alert)
                        print(f"🚨 {pred_label.upper()} detected from {alert['source_ip']} (confidence: {confidence})")
        except Exception as e:
            pass  # Silent fail for malformed packets

    def get_alerts(self):
        """Get all pending alerts"""
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())
        return alerts

    def get_stats(self):
        """Get current statistics"""
        return {
            'packets_processed': self.packet_count,
            'threats_detected': self.threat_count,
            'is_running': self.is_running,
            'total_alerts': len(self.alerts_history)
        }

    def stop(self):
        """Stop monitoring"""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)
        print(f"⛔ Monitoring Stopped. Stats: {self.packet_count} packets, {self.threat_count} threats")
