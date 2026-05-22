# src/detection/real_time_detector.py - ROBUST PRODUCTION VERSION v2.0
import numpy as np
from datetime import datetime
import threading
import queue
import warnings
import time
import sys
import os
import random
import subprocess
import socket
import ipaddress

warnings.filterwarnings("ignore")

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.model_loader import ModelLoader

# ─────────────────────────────────────────────────────────
# IP UTILITIES
# ─────────────────────────────────────────────────────────
def _is_private_or_local(ip: str) -> bool:
    """Return True for loopback, link-local, private, multicast, and reserved addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_loopback          # 127.x.x.x / ::1
            or addr.is_link_local     # 169.254.x.x / fe80::
            or addr.is_private        # 10.x / 172.16-31.x / 192.168.x
            or addr.is_multicast      # 224.x – 239.x
            or addr.is_reserved       # 0.x, 240.x, etc.
            or addr.is_unspecified    # 0.0.0.0 / ::
        )
    except ValueError:
        return True  # Unknown → treat as private/safe → skip


def _get_local_ips() -> set:
    """Collect all IPs assigned to this machine (all interfaces)."""
    local = set()
    try:
        result = subprocess.run(
            ['ip', '-o', 'addr', 'show'],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            for p in parts:
                if '/' in p:
                    try:
                        local.add(str(ipaddress.ip_interface(p).ip))
                    except Exception:
                        pass
    except Exception:
        pass
    # Always include the hostname-resolved IP
    try:
        local.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    return local


def _is_connected() -> bool:
    """
    Lightweight connectivity check.
    Tries a non-blocking TCP connect to 8.8.8.8:53 (Google DNS).
    Returns False if machine has no route to the internet.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect(("8.8.8.8", 53))
        s.close()
        return True
    except OSError:
        return False


# ─────────────────────────────────────────────────────────
# KNOWN BENIGN PORTS / SERVICES (very high FP rate)
# ─────────────────────────────────────────────────────────
BENIGN_DPORT = {
    80, 443,           # HTTP / HTTPS
    53,                # DNS
    67, 68,            # DHCP
    123,               # NTP
    5353,              # mDNS
    1900,              # SSDP / UPnP discovery
    137, 138, 139,     # NetBIOS
    443, 8443,         # HTTPS alt
}

# ─────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────
class RealTimeIDS:
    def __init__(self, model_dir="src/models"):
        self.alert_queue = queue.Queue()
        self.packet_count = 0
        self.threat_count = 0
        self.is_running = False
        self.thread = None
        self.alerts_history = []
        self.mode = "demo"

        # ── ALERT THRESHOLDS ──────────────────────────────
        # Raised from 0.88 → 0.92 to drastically cut FPs
        self.min_confidence   = 0.92
        # Only HIGH/CRITICAL (unchanged)
        self.min_severity     = 5
        # Tighter rate-limiting
        self.max_alerts_per_minute = 8

        # For rate-limiting
        self._alert_ts: list = []

        # Cache of this machine's own IPs (used to skip self-traffic)
        self._local_ips: set = _get_local_ips()

        print("🔧 Initialising Real-Time IDS v2.0 (Robust Edition)…")
        print("=" * 55)

        self.model_loader = ModelLoader(model_dir)

        if self.model_loader.is_loaded:
            print("✅ ML models loaded successfully.")
            info = self.model_loader.get_model_info()
            print(f"   Attack classes : {info.get('attack_classes', 'N/A')}")
            print(f"   Feature count  : {info.get('feature_count', 'N/A')}")
        else:
            print("⚠️  Models not found – will run in Demo mode.")

        print(f"\n🔒 Alert Thresholds:")
        print(f"   Min confidence : {self.min_confidence * 100:.0f}%")
        print(f"   Min severity   : {self.min_severity}+ (HIGH/CRITICAL only)")
        print(f"   Rate limit     : ≤{self.max_alerts_per_minute} alerts / minute")

    # ──────────────────────────────────────────────────────
    # INTERFACE DETECTION
    # ──────────────────────────────────────────────────────
    def get_available_interface(self) -> str:
        """
        Return the best non-loopback network interface.
        Prefers interfaces that actually carry a default route.
        Falls back to 'lo' only when nothing else is found.
        """
        # Priority 1: interface used by the default route
        try:
            res = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=2
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if 'dev' in parts:
                    iface = parts[parts.index('dev') + 1]
                    print(f"🔍 Default-route interface: {iface}")
                    return iface
        except Exception:
            pass

        # Priority 2: any UP interface with an IPv4 address (not loopback)
        try:
            res = subprocess.run(
                ['ip', '-o', 'addr', 'show', 'up'],
                capture_output=True, text=True, timeout=2
            )
            for line in res.stdout.splitlines():
                if 'inet ' in line and 'lo' not in line:
                    iface = line.split()[1]
                    print(f"🔍 Auto-detected interface: {iface}")
                    return iface
        except Exception:
            pass

        # Priority 3: common names
        for iface in ['eth0', 'ens33', 'enp2s0', 'wlan0', 'wlo1', 'wlp2s0']:
            try:
                res = subprocess.run(
                    ['ip', 'link', 'show', iface],
                    capture_output=True, timeout=1
                )
                if res.returncode == 0:
                    print(f"🔍 Found interface: {iface}")
                    return iface
            except Exception:
                pass

        print("⚠️  No usable network interface found – using loopback (demo only).")
        return 'lo'

    # ──────────────────────────────────────────────────────
    # SEVERITY MAP
    # ──────────────────────────────────────────────────────
    def get_severity_level(self, attack_type: str) -> tuple:
        severity_map = {
            # CRITICAL 8-10
            'infiltration': (10, 'CRITICAL', '🔴'),
            'u2r':          (10, 'CRITICAL', '🔴'),
            'rootkit':      (10, 'CRITICAL', '🔴'),
            'ddos':         (9,  'CRITICAL', '🔴'),
            'dos':          (8,  'CRITICAL', '🔴'),
            'r2l':          (8,  'CRITICAL', '🔴'),
            # HIGH 5-7
            'botnet':       (7,  'HIGH', '🟠'),
            'brute_force':  (7,  'HIGH', '🟠'),
            'web_attack':   (6,  'HIGH', '🟠'),
            'sqli':         (6,  'HIGH', '🟠'),
            'port_scan':    (5,  'HIGH', '🟠'),
            'nmap':         (5,  'HIGH', '🟠'),
            # MEDIUM – suppressed by default
            'probe':        (3,  'MEDIUM', '🟡'),
            'ipsweep':      (3,  'MEDIUM', '🟡'),
            # NORMAL
            'normal':       (0,  'NORMAL', '⚪'),
            'benign':       (0,  'NORMAL', '⚪'),
        }
        key = attack_type.lower()
        if key in severity_map:
            s, lv, ic = severity_map[key]
            return s, lv, ic
        # Unknown attack → MEDIUM (won't breach min_severity=5)
        return 3, 'MEDIUM', '🟡'

    # ──────────────────────────────────────────────────────
    # ALERT GATE
    # ──────────────────────────────────────────────────────
    def should_alert(self, confidence: float, severity: int) -> tuple[bool, list]:
        """Multi-factor gate before raising an alert."""
        reasons = []

        if confidence < self.min_confidence:
            reasons.append(
                f"confidence {confidence * 100:.0f}% < {self.min_confidence * 100:.0f}%"
            )

        if severity < self.min_severity:
            reasons.append(f"severity {severity} < {self.min_severity}")

        # Sliding-window rate limiter
        now = time.time()
        self._alert_ts = [t for t in self._alert_ts if now - t < 60]
        if len(self._alert_ts) >= self.max_alerts_per_minute:
            reasons.append(f"rate limit ({self.max_alerts_per_minute}/min)")

        ok = len(reasons) == 0
        if ok:
            self._alert_ts.append(now)
        return ok, reasons

    # ──────────────────────────────────────────────────────
    # DEMO MODE  (realistic, low FP)
    # ──────────────────────────────────────────────────────
    def _demo_mode(self):
        """
        Realistic demo:  ~98 % normal traffic,  ~2 % genuine threats.
        Only threats that pass the confidence + severity gate are shown.
        """
        print("🎮 Demo Mode – realistic threat simulation (2 % attack rate)")
        print(f"   Threshold: >{self.min_confidence * 100:.0f}% confidence, severity {self.min_severity}+")
        print("=" * 55)

        # ── traffic pool ─────────────────────────────────
        # Each entry: (label, confidence)
        normal_pool = [
            ('normal', round(random.uniform(0.88, 0.99), 3))
            for _ in range(98)          # 98 normal samples
        ]

        # Real attacks with realistic confidence distribution
        attack_pool = [
            ('ddos',        0.97), ('ddos',        0.95),
            ('brute_force', 0.96), ('brute_force', 0.93),
            ('web_attack',  0.94), ('web_attack',  0.92),
            ('port_scan',   0.93), ('nmap',        0.91),
            ('botnet',      0.96), ('infiltration', 0.98),
        ]

        # Pre-build weighted list: 98 % normal, 2 % attack
        all_traffic = normal_pool + attack_pool
        weights = [0.98 / len(normal_pool)] * len(normal_pool) + \
                  [0.02 / len(attack_pool)] * len(attack_pool)

        # External-only source IPs for simulated attacks
        attack_src_ips = [
            '185.130.5.253',  '45.155.205.233', '103.108.80.10',
            '91.108.4.15',    '198.51.100.42',  '203.0.113.99',
            '198.18.0.55',    '5.188.206.14',   '62.210.180.229',
            '195.54.162.230',
        ]

        packet_id = 0

        while self.is_running:
            time.sleep(0.2)     # 5 packets / second
            packet_id += 1
            self.packet_count += 1

            label, conf = random.choices(all_traffic, weights=weights, k=1)[0]

            if label == 'normal':
                continue            # Normal traffic → no alert, no noise

            # ── It's an attack candidate ──────────────────
            sev, lv, icon = self.get_severity_level(label)
            ok, reasons = self.should_alert(conf, sev)

            if ok:
                self.threat_count += 1
                alert = {
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip":      random.choice(attack_src_ips),
                    "attack_type":    label,
                    "confidence":     conf,
                    "severity":       sev,
                    "severity_level": lv,
                    "icon":           icon,
                    "status":         "THREAT",
                    "packet_id":      packet_id,
                    "alert_reason":   f"High-confidence external threat ({conf * 100:.0f}%)",
                }
                self.alert_queue.put(alert)
                self.alerts_history.append(alert)
                print(f"{icon} {lv:8} | {label.upper():15} | {alert['source_ip']} | {conf * 100:.0f}%")

            # Progress heartbeat every 500 packets
            if packet_id % 500 == 0:
                rate = (self.threat_count / max(self.packet_count, 1)) * 100
                print(f"📊 {self.packet_count} pkts | {self.threat_count} threats | {rate:.2f}% threat rate")

    # ──────────────────────────────────────────────────────
    # LIVE CAPTURE
    # ──────────────────────────────────────────────────────
    def _live_capture(self, interface: str):
        """
        Live packet capture with robust pre-filtering to eliminate:
         • Loopback / private / link-local traffic
         • Own machine's IPs (self-generated traffic)
         • Common benign service ports (DNS, DHCP, NTP, mDNS …)
         • Traffic captured while the machine is offline
        """
        import scapy.all as scapy

        # Connectivity guard
        if not _is_connected():
            print("⚠️  No internet connectivity detected.")
            print("   Live capture would only see local/loopback traffic → Demo mode.")
            self._demo_mode()
            return

        print(f"🔴 Live capture on interface: {interface}")
        print(f"   Filtering: external IPs only, no private/loopback/own-IPs")
        print(f"   Skipping benign ports: {sorted(BENIGN_DPORT)}")
        print("=" * 55)

        # Refresh own IPs right before capture starts
        self._local_ips = _get_local_ips()

        try:
            scapy.sniff(
                iface=interface,
                prn=self._process_live_packet,
                store=False,
                filter="ip",            # Only IPv4 (drops ARP, IPv6 noise, loopback at kernel level)
                stop_filter=lambda _: not self.is_running,
            )
        except PermissionError:
            print("❌ Permission denied. Run with: sudo streamlit run app.py")
            print("🎮 Falling back to Demo mode…")
            self._demo_mode()
        except OSError as e:
            print(f"❌ Interface error ({interface}): {e}")
            print("🎮 Falling back to Demo mode…")
            self._demo_mode()
        except Exception as e:
            print(f"❌ Live capture error: {e}")
            print("🎮 Falling back to Demo mode…")
            self._demo_mode()

    def _process_live_packet(self, packet):
        """
        Per-packet handler.  Heavy pre-filtering runs before the ML model
        to keep FP rate as low as possible.
        """
        import scapy.all as scapy

        self.packet_count += 1

        if not self.model_loader.is_loaded:
            return

        try:
            if not packet.haslayer(scapy.IP):
                return

            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            # ── 1. Skip all loopback / private / multicast addresses ──
            if _is_private_or_local(src_ip) or _is_private_or_local(dst_ip):
                return

            # ── 2. Skip the machine's own traffic ─────────────────────
            if src_ip in self._local_ips or dst_ip in self._local_ips:
                return

            # ── 3. Skip known-benign destination ports ─────────────────
            dst_port = None
            if packet.haslayer(scapy.TCP):
                dst_port = packet[scapy.TCP].dport
                protocol = "TCP"
            elif packet.haslayer(scapy.UDP):
                dst_port = packet[scapy.UDP].dport
                protocol = "UDP"
            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"
            else:
                protocol = "Other"

            if dst_port in BENIGN_DPORT:
                return

            # ── 4. ML classification ───────────────────────────────────
            features = self._extract_features(packet, protocol)
            prediction, confidence, _ = self.model_loader.predict(features)

            if prediction in ('normal', 'benign', 'unknown'):
                return

            sev, lv, icon = self.get_severity_level(prediction)
            ok, _ = self.should_alert(confidence, sev)

            if ok:
                self.threat_count += 1
                alert = {
                    "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_ip":      src_ip,
                    "destination_ip": dst_ip,
                    "protocol":       protocol,
                    "packet_size":    len(packet),
                    "attack_type":    prediction,
                    "confidence":     confidence,
                    "severity":       sev,
                    "severity_level": lv,
                    "icon":           icon,
                    "status":         "THREAT",
                    "packet_id":      self.packet_count,
                    "alert_reason":   f"{confidence * 100:.0f}% confidence, external IP",
                }
                self.alert_queue.put(alert)
                self.alerts_history.append(alert)
                print(
                    f"{icon} {lv:8} | {prediction.upper():15} | "
                    f"{src_ip} → {dst_ip} | {confidence * 100:.0f}%"
                )

        except Exception:
            pass    # Silent fail for malformed packets

    # ──────────────────────────────────────────────────────
    # FEATURE EXTRACTION
    # ──────────────────────────────────────────────────────
    def _extract_features(self, packet, protocol: str) -> np.ndarray:
        """Extract NSL-KDD-compatible features from a live packet."""
        import scapy.all as scapy

        proto_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'Other': 3}

        features = {
            'duration':                   0.0,
            'protocol_type':              proto_map.get(protocol, 3),
            'service':                    0,
            'flag':                       0,
            'src_bytes':                  len(packet),
            'dst_bytes':                  len(packet),
            'land':                       0,
            'wrong_fragment':             0,
            'urgent':                     0,
            'hot':                        0,
            'num_failed_logins':          0,
            'logged_in':                  0,
            'num_compromised':            0,
            'root_shell':                 0,
            'su_attempted':               0,
            'num_root':                   0,
            'num_file_creations':         0,
            'num_shells':                 0,
            'num_access_files':           0,
            'num_outbound_cmds':          0,
            'is_host_login':              0,
            'is_guest_login':             0,
            'count':                      1,
            'srv_count':                  1,
            'serror_rate':                0.0,
            'srv_serror_rate':            0.0,
            'rerror_rate':                0.0,
            'srv_rerror_rate':            0.0,
            'same_srv_rate':              1.0,
            'diff_srv_rate':              0.0,
            'srv_diff_host_rate':         0.0,
            'dst_host_count':             1,
            'dst_host_srv_count':         1,
            'dst_host_same_srv_rate':     1.0,
            'dst_host_diff_srv_rate':     0.0,
            'dst_host_same_src_port_rate':0.0,
            'dst_host_srv_diff_host_rate':0.0,
            'dst_host_serror_rate':       0.0,
            'dst_host_srv_serror_rate':   0.0,
            'dst_host_rerror_rate':       0.0,
            'dst_host_srv_rerror_rate':   0.0,
        }

        # TCP-specific enrichment
        if protocol == 'TCP' and packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            features['flag'] = int(tcp.flags)
            features['urgent'] = int(tcp.urgptr > 0)
            # SYN-only with no ACK → potential scan / SYN flood
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                features['serror_rate'] = 1.0

        return self.model_loader.extract_features_for_prediction(features)

    # ──────────────────────────────────────────────────────
    # PUBLIC API
    # ──────────────────────────────────────────────────────
    def start_sniffing(self, interface: str = "auto") -> bool:
        self.is_running = True

        if interface == "auto":
            # If offline → demo mode immediately (no pointless capture attempt)
            if not _is_connected():
                print("📡 No network connectivity – switching to Demo mode automatically.")
                return self.start_sniffing("demo")
            interface = self.get_available_interface()
            print(f"🔍 Selected interface: {interface}")

        if interface == "demo":
            print("🎮 Starting Demo mode…")
            self.mode = "demo"
            self.thread = threading.Thread(target=self._demo_mode, daemon=True)
            self.thread.start()
            return True

        # Live capture requires root
        if os.geteuid() != 0:
            print("❌ Live capture requires root privileges.")
            print("   Run: sudo streamlit run app.py")
            print("🎮 Falling back to Demo mode…")
            return self.start_sniffing("demo")

        print(f"🔴 Starting live capture on {interface}…")
        self.mode = "live"
        self.thread = threading.Thread(
            target=self._live_capture, args=(interface,), daemon=True
        )
        self.thread.start()
        return True

    def get_alerts(self) -> list:
        alerts = []
        while not self.alert_queue.empty():
            alerts.append(self.alert_queue.get())
        return alerts

    def get_stats(self) -> dict:
        return {
            'packets_processed': self.packet_count,
            'threats_detected':  self.threat_count,
            'is_running':        self.is_running,
            'total_alerts':      len(self.alerts_history),
            'mode':              self.mode,
            'min_confidence':    self.min_confidence,
            'min_severity':      self.min_severity,
        }

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=3)
        print(
            f"⛔ Stopped.  Packets: {self.packet_count}  |  "
            f"Threats: {self.threat_count}"
        )
