# src/integration/feature_integrator.py
"""Integration hub for all advanced features"""

import streamlit as st
from datetime import datetime
import pandas as pd
import plotly.graph_objects as go
from src.visualization.animated_timeline import AnimatedThreatTimeline
from src.visualization.wordcloud_viz import AttackWordCloud
from src.intelligence.mitre_mapper import MitreAttackMapper
from src.intelligence.threat_intel import ThreatIntelligence
from src.analysis.benchmark import PerformanceBenchmark
from src.reports.auto_reporter import AutoReportGenerator

class FeatureIntegrator:
    """Central integration for all advanced features"""
    
    def __init__(self, ids_instance=None):
        self.ids = ids_instance
        self.performance_benchmark = PerformanceBenchmark()
        self.threat_intel = ThreatIntelligence()
        self.api_server = None
        
    def display_visualization_tab(self, alerts):
        """Display all visualization features in one tab"""
        st.markdown("### 🎨 Advanced Visualizations")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Animated Threat Timeline")
            timeline_viz = AnimatedThreatTimeline()
            fig = timeline_viz.create_animated_timeline(alerts)
            if fig:
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Not enough data for timeline")
        
        with col2:
            st.markdown("#### Attack Word Cloud")
            wordcloud_viz = AttackWordCloud()
            wordcloud_viz.create_attack_wordcloud(alerts)
    
    def display_intelligence_tab(self, alerts):
        """Display threat intelligence features"""
        st.markdown("### 🧠 Threat Intelligence")
        
        # MITRE ATT&CK Matrix
        st.markdown("#### MITRE ATT&CK Framework Mapping")
        mitre_fig = MitreAttackMapper.generate_attack_matrix(alerts)
        if mitre_fig:
            st.plotly_chart(mitre_fig, use_container_width=True)
        
        # Threat Intel Bulletin
        st.markdown("#### Latest Threat Intelligence")
        bulletins = self.threat_intel.get_threat_bulletin()
        for bulletin in bulletins:
            with st.expander(f"🔴 {bulletin['title']} - {bulletin['severity']}"):
                st.write(f"**Description:** {bulletin['description']}")
                st.write(f"**CVE ID:** {bulletin['id']}")
                st.write(f"**Date:** {bulletin['date']}")
    
    def display_performance_tab(self):
        """Display performance benchmarks"""
        st.markdown("### ⚡ System Performance")
        
        fig, report = self.performance_benchmark.get_performance_report()
        if fig:
            st.plotly_chart(fig, use_container_width=True)
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Avg Latency", f"{report['avg_latency_ms']:.2f} ms")
        with col2:
            st.metric("CPU Usage", f"{report['cpu_usage']}%")
        with col3:
            st.metric("Memory Usage", f"{report['memory_usage']}%")
    
    def start_api_server(self, port=5000):
        """Start REST API server"""
        if self.ids:
            self.api_server = IDSAPI(self.ids)
            self.api_server.start(port)
            st.success(f"✅ API Server started on port {port}")
            st.info(f"API Endpoints: http://localhost:{port}/api/status")
    
    def generate_report(self, alerts, stats):
        """Generate comprehensive report"""
        report_gen = AutoReportGenerator()
        report_file = report_gen.generate_html_report(alerts, stats)
        return report_file
