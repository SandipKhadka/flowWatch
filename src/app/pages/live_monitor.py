"""
Live Monitor Page Component
"""

import streamlit as st
from ..session_state import session
from ..components import MetricCard, AlertCard, CardStyle
from ...utils.attack_mapper import AttackMapper


class LiveMonitorPage:
    """Live monitoring page with real-time threat display"""
    
    def __init__(self):
        self.attack_mapper = AttackMapper()
    
    def render(self):
        """Render the live monitoring page"""
        st.markdown("## 🎯 Real-Time Threat Monitor")
        st.caption(f"⚠️ Showing ONLY threats with >{session.get('min_confidence_filter', 0.85)*100:.0f}% confidence")
        
        if session.is_running() and session.get('detector'):
            self._render_active_monitoring()
        else:
            self._render_inactive_state()
    
    def _render_active_monitoring(self):
        """Render active monitoring state"""
        detector = session.get('detector')
        
        # Get and update alerts
        new_alerts = detector.get_alerts()
        for alert in new_alerts:
            session.add_alert(alert)
        
        # Get statistics
        stats = detector.get_stats()
        
        # Render metric cards
        self._render_metric_cards(stats)
        
        st.markdown("---")
        
        # Render alert feed
        self._render_alert_feed()
    
    def _render_metric_cards(self, stats: dict):
        """Render metric cards"""
        col1, col2, col3, col4 = st.columns(4)
        
        alerts = session.get('alerts', [])
        risk = self.attack_mapper.calculate_risk_score(alerts) if alerts else 0
        unique_ips = len(set([a['source_ip'] for a in alerts])) if alerts else 0
        
        metrics = [
            ("📦 Total Packets", f"{stats.get('packets_processed', 0):,}", None),
            ("⚠️ Real Threats", f"{stats.get('threats_detected', 0):,}", None),
            ("🎯 Risk Score", f"{risk:.1f}/10", None),
            ("🌐 Attackers", f"{unique_ips:,}", None)
        ]
        
        for col, (title, value, delta) in zip([col1, col2, col3, col4], metrics):
            with col:
                style = CardStyle.DANGER if "Threats" in title or "Risk" in title else CardStyle.PRIMARY
                MetricCard.render(title, value, delta, style=style)
    
    def _render_alert_feed(self):
        """Render the alert feed"""
        st.markdown("### 🚨 Real Threat Alert Feed")
        st.caption("🔴 CRITICAL (Severity 8-10) | 🟠 HIGH (Severity 5-7)")
        
        alerts = session.get('alerts', [])
        min_confidence = session.get('min_confidence_filter', 0.85)
        
        # Filter alerts
        filtered_alerts = [
            a for a in alerts 
            if a.get('confidence', 0) >= min_confidence
        ][-30:]  # Last 30 alerts
        
        if filtered_alerts:
            col1, col2 = st.columns(2)
            alerts_list = list(reversed(filtered_alerts))
            mid = len(alerts_list) // 2
            
            for col, alerts_subset in [(col1, alerts_list[:mid]), (col2, alerts_list[mid:])]:
                with col:
                    for alert in alerts_subset:
                        AlertCard.render(alert)
        else:
            st.info("💡 No threats meeting confidence/severity thresholds. System monitoring...")
    
    def _render_inactive_state(self):
        """Render inactive state with welcome message"""
        st.info("👈 **Click START in the sidebar to begin monitoring**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🚀 Modern IDS Features
            
            | Feature | Description |
            |---------|-------------|
            | **Binary Classifier** | Normal vs Attack detection |
            | **Multiclass Classifier** | Identifies 10 attack types |
            | **Confidence Threshold** | Only >88% confidence alerts |
            | **Severity Filtering** | Only HIGH (5+) and CRITICAL (8+) |
            """)
        
        with col2:
            st.markdown("""
            ### 🎯 Attack Types Detected
            
            - DDoS & DoS Attacks
            - Port Scanning & Reconnaissance
            - Brute Force Attacks
            - Web Attacks (SQLi, XSS)
            - Infiltration & Botnet
            - R2L & U2R Attacks
            """)
