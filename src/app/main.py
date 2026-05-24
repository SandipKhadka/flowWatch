"""
FlowWatch AI - Main Application Entry Point
"""

import streamlit as st
import time

from .config import config
from .session_state import session
from .components import SidebarRenderer
from .pages import LiveMonitorPage, AnalyticsPage, ThreatIntelPage, ReportsPage


class FlowWatchApp:
    """Main application class"""
    
    def __init__(self):
        """Initialize the application"""
        self._setup_page_config()
        
        # Initialize pages
        self.live_monitor = LiveMonitorPage()
        self.analytics = AnalyticsPage()
        self.threat_intel = ThreatIntelPage()
        self.reports = ReportsPage()
    
    def _setup_page_config(self):
        """Configure Streamlit page settings"""
        st.set_page_config(
            page_title="FlowWatch AI - Modern Intrusion Detection System",
            page_icon="🛡️",
            layout=config.ui.page_layout,
            initial_sidebar_state=config.ui.sidebar_initial_state
        )
    
    def _render_header(self):
        """Render the application header"""
        st.markdown("""
        <style>
        .app-header {
            background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            padding: 2rem;
            border-radius: 1rem;
            color: white;
            margin-bottom: 2rem;
            text-align: center;
            animation: fadeInDown 0.8s ease-out;
        }
        .app-header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .model-badge {
            background: rgba(16, 185, 129, 0.2);
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.75rem;
            display: inline-block;
            margin: 0.2rem;
        }
        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        </style>
        
        <div class="app-header">
            <h1>🛡️ FlowWatch AI</h1>
            <p>Modern Hybrid Intrusion Detection System | 99%+ Accuracy | Real Threat Detection Only</p>
            <div style="margin-top: 1rem;">
                <span class="model-badge">🎯 XGBoost Ensemble</span>
                <span class="model-badge">🔬 Binary + Multiclass</span>
                <span class="model-badge">⚡ >88% Confidence Threshold</span>
                <span class="model-badge">⚠️ Severity 5+ Only</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    def _handle_auto_refresh(self):
        """Handle auto-refresh functionality"""
        if session.is_running() and session.get('auto_refresh', True):
            time.sleep(config.ui.auto_refresh_interval)
            st.rerun()
    
    def _render_footer(self):
        """Render application footer"""
        st.markdown("---")
        st.markdown("""
        <div style="text-align: center; color: gray; padding: 1rem;">
            <p>🛡️ FlowWatch AI - Modern Hybrid Intrusion Detection System</p>
            <p>Powered by XGBoost Ensemble | Binary + Multiclass | 99%+ Accuracy | Real Threats Only</p>
            <p style="font-size: 0.8rem;">Final Year Project 2026 | Department of Information Technology</p>
        </div>
        """, unsafe_allow_html=True)
    
    def run(self):
        """Main application entry point"""
        # Render sidebar
        SidebarRenderer.render()
        
        # Render header
        self._render_header()
        
        # Create tabs
        tab1, tab2, tab3, tab4 = st.tabs(["🎯 Live Monitor", "📈 Analytics", "🗺️ Threat Intelligence", "📄 Reports"])
        
        with tab1:
            self.live_monitor.render()
        
        with tab2:
            self.analytics.render()
        
        with tab3:
            self.threat_intel.render()
        
        with tab4:
            self.reports.render()
        
        # Handle auto-refresh
        self._handle_auto_refresh()
        
        # Footer
        self._render_footer()


def main():
    """Application entry point"""
    app = FlowWatchApp()
    app.run()


if __name__ == "__main__":
    main()
