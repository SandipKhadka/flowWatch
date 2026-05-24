"""
Sidebar component with all controls
"""

import streamlit as st
import time
from ..session_state import session
from ..config import config, AppMode
from ...detection.real_time_detector import RealTimeIDS


class SidebarRenderer:
    """Render and manage sidebar content"""
    
    @classmethod
    def render(cls):
        """Render the complete sidebar"""
        with st.sidebar:
            st.markdown("## 🎮 Control Panel")
            
            cls._render_system_status()
            st.markdown("---")
            
            cls._render_mode_selector()
            st.markdown("---")
            
            cls._render_control_buttons()
            st.markdown("---")
            
            cls._render_model_info()
            st.markdown("---")
            
            cls._render_alert_settings()
            st.markdown("---")
            
            cls._render_live_stats()
            st.markdown("---")
            
            cls._render_database_stats()
    
    @classmethod
    def _render_system_status(cls):
        """Render system status indicator"""
        if session.is_running():
            st.success("🟢 **SYSTEM ACTIVE**")
            st.caption("Modern IDS Model Running | Real Threats Only")
        else:
            st.warning("⚪ **SYSTEM STANDBY**")
            st.caption("Click Start to begin monitoring")
    
    @classmethod
    def _render_mode_selector(cls):
        """Render mode selection radio buttons"""
        mode = st.radio(
            "**Detection Mode**",
            [m.value for m in AppMode],
            index=0,
            help="Demo Mode: Simulated realistic threats\nLive Capture: Real network traffic (requires sudo)",
            key="mode_selector"
        )
        return mode
    
    @classmethod
    def _render_control_buttons(cls):
        """Render start/stop buttons"""
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🚀 **START**", use_container_width=True):
                cls._start_detection()
        
        with col2:
            if st.button("⛔ **STOP**", use_container_width=True):
                cls._stop_detection()
    
    @classmethod
    def _start_detection(cls):
        """Start the detection system"""
        try:
            mode = st.session_state.get('mode_selector', AppMode.DEMO.value)
            detector = RealTimeIDS()
            
            if mode == AppMode.DEMO.value:
                detector.start_sniffing("demo")
            else:
                detector.start_sniffing("auto")
            
            session.set('detector', detector)
            session.set('running', True)
            
            # Get model info
            if hasattr(detector, 'model_loader'):
                session.set('model_info', detector.model_loader.get_model_info())
            
            st.success("✅ System Started Successfully!")
            time.sleep(0.5)
            st.rerun()
        except Exception as e:
            st.error(f"❌ Error starting system: {str(e)}")
    
    @classmethod
    def _stop_detection(cls):
        """Stop the detection system"""
        detector = session.get('detector')
        if detector:
            detector.stop()
        session.set('running', False)
        st.warning("⛔ System Stopped")
        time.sleep(0.5)
        st.rerun()
    
    @classmethod
    def _render_model_info(cls):
        """Render model information card"""
        st.markdown("### 🤖 Modern IDS Model")
        
        model_info = session.get('model_info')
        if model_info:
            st.markdown(f"""
            <div style="background: rgba(31, 41, 55, 0.7); padding: 1rem; border-radius: 0.5rem; font-size: 0.8rem;">
                <strong>✅ Model Status:</strong> Active<br>
                <strong>🎯 Attack Classes:</strong> {model_info.get('attack_classes', '10')}<br>
                <strong>📊 Features:</strong> {model_info.get('feature_count', '45')}<br>
                <strong>🏆 Accuracy:</strong> 99%+<br>
                <strong>🔒 Threshold:</strong> {config.detection.min_confidence*100:.0f}% / Severity {config.detection.min_severity}+
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("💡 Start the system to see model information")
    
    @classmethod
    def _render_alert_settings(cls):
        """Render alert filtering settings"""
        st.markdown("### 🎯 Alert Filters")
        
        detector = session.get('detector')
        if detector and session.is_running():
            current_conf = getattr(detector, 'min_confidence', config.detection.min_confidence)
            current_sev = getattr(detector, 'min_severity', config.detection.min_severity)
            st.caption(f"📊 Current: {current_conf*100:.0f}% confidence, Severity {current_sev}+")
        
        min_conf = st.slider(
            "Min Confidence",
            0.70, 0.98, session.get('min_confidence_filter', 0.85), 0.01,
            help="Filter alerts by minimum confidence score",
            key="min_confidence_slider"
        )
        session.set('min_confidence_filter', min_conf)
    
    @classmethod
    def _render_live_stats(cls):
        """Render live statistics"""
        if session.is_running():
            detector = session.get('detector')
            if detector:
                stats = detector.get_stats()
                
                st.markdown("### 📊 Live Statistics")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("📦 Packets", f"{stats.get('packets_processed', 0):,}")
                with col2:
                    st.metric("⚠️ Threats", f"{stats.get('threats_detected', 0):,}")
                
                if stats.get('packets_processed', 0) > 0:
                    rate = (stats.get('threats_detected', 0) / stats.get('packets_processed', 1)) * 100
                    st.metric("🎯 Threat Rate", f"{rate:.2f}%")
                
                # Threat level progress bar
                threat_level = min(stats.get('threats_detected', 0) / 100, 1.0)
                st.progress(threat_level, text=f"📈 Threat Level: {int(threat_level*100)}%")
                
                # Auto refresh toggle
                st.markdown("---")
                auto_refresh = st.checkbox(
                    "🔄 Auto Refresh",
                    value=session.get('auto_refresh', True),
                    help="Automatically refresh the dashboard"
                )
                session.set('auto_refresh', auto_refresh)
    
    @classmethod
    def _render_database_stats(cls):
        """Render database statistics"""
        st.markdown("### 🗄️ Database")
        
        import sqlite3
        try:
            conn = sqlite3.connect(config.database.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(DISTINCT date(timestamp)) FROM alerts")
            total_days = cursor.fetchone()[0]
            conn.close()
            
            st.metric("📝 Total Records", f"{total_alerts:,}")
            st.metric("📅 Days of History", total_days if total_days else 0)
        except Exception:
            pass
        
        st.caption(f"💾 Memory: {len(session.get('alerts', [])):,} alerts")
