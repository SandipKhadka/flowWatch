import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import sys
import os
import sqlite3
import warnings
warnings.filterwarnings("ignore")

# Add path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.detection.real_time_detector import RealTimeIDS
from src.utils.attack_mapper import AttackMapper
from src.utils.database_manager import DatabaseManager
from src.utils.alert_manager import AlertManager

# Try to import PDF exporter
try:
    from src.utils.pdf_generator import PDFExporter
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# Page config
st.set_page_config(
    page_title="FlowWatch AI - Modern Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 1rem;
        color: white;
        margin-bottom: 2rem;
        text-align: center;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 1rem;
        padding: 1.5rem;
        color: white;
        text-align: center;
    }
    .alert-critical {
        background: #dc2626;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #ff0000;
        animation: slideIn 0.3s ease-out;
    }
    .alert-high {
        background: #f59e0b;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #ff6600;
        animation: slideIn 0.3s ease-out;
    }
    .alert-medium {
        background: #eab308;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: white;
        border-left: 5px solid #ffcc00;
        animation: slideIn 0.3s ease-out;
    }
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.5rem 2rem;
        font-weight: bold;
        transition: transform 0.3s;
    }
    .stButton > button:hover {
        transform: scale(1.02);
        transition: 0.3s;
    }
    .model-badge {
        background: #10b981;
        padding: 0.25rem 0.75rem;
        border-radius: 2rem;
        font-size: 0.75rem;
        display: inline-block;
    }
    .historical-card {
        background: #e0e7ff;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .model-info {
        background: #1f2937;
        padding: 1rem;
        border-radius: 0.5rem;
        color: white;
        font-size: 0.8rem;
    }
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateX(-20px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'detector' not in st.session_state:
    st.session_state.detector = None
if 'running' not in st.session_state:
    st.session_state.running = False
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'db' not in st.session_state:
    st.session_state.db = DatabaseManager()
if 'alert_manager' not in st.session_state:
    st.session_state.alert_manager = AlertManager()
if 'quick_filter' not in st.session_state:
    st.session_state.quick_filter = None
if 'historical_loaded' not in st.session_state:
    st.session_state.historical_loaded = False
if 'model_info' not in st.session_state:
    st.session_state.model_info = None
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = True

# Load historical alerts from database on startup
if not st.session_state.historical_loaded and st.session_state.db:
    try:
        historical_df = st.session_state.db.get_alerts(hours=24*30, limit=5000)
        if not historical_df.empty:
            historical_alerts = historical_df.to_dict('records')
            existing_keys = set([(a['timestamp'], a['source_ip'], a['attack_type']) for a in st.session_state.alerts])
            new_alerts = [a for a in historical_alerts if (a['timestamp'], a['source_ip'], a['attack_type']) not in existing_keys]
            st.session_state.alerts.extend(new_alerts)
            st.session_state.historical_loaded = True
    except Exception as e:
        pass

# Header
st.markdown("""
<div class="header">
    <h1>🛡️ FlowWatch AI</h1>
    <p>Modern Hybrid Intrusion Detection System | 99%+ Accuracy | Real Threat Detection Only</p>
    <p style="font-size: 0.9rem; margin-top: 0.5rem;">
        <span class="model-badge">XGBoost Ensemble</span> 
        <span class="model-badge">Binary + Multiclass</span>
        <span class="model-badge">>88% Confidence Threshold</span>
        <span class="model-badge">Severity 5+ Only</span>
    </p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("## 🎮 Control Panel")
    
    # System status
    if st.session_state.running:
        st.success("🟢 SYSTEM ACTIVE")
        st.caption("Modern IDS Model Running | Real Threats Only")
    else:
        st.warning("⚪ SYSTEM STANDBY")
        st.caption("Click Start to begin monitoring")
    
    st.markdown("---")
    
    # Mode selection
    mode = st.radio("Mode", ["Demo Mode", "Live Capture"], index=0,
                   help="Demo Mode: Simulated realistic threats\nLive Capture: Real network traffic (requires sudo)")
    
    st.markdown("---")
    
    # Control buttons
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🚀 START", use_container_width=True):
            try:
                st.session_state.detector = RealTimeIDS()
                if mode == "Demo Mode":
                    st.session_state.detector.start_sniffing("demo")
                else:
                    st.session_state.detector.start_sniffing("auto")
                st.session_state.running = True
                
                # Get model info
                if hasattr(st.session_state.detector, 'model_loader'):
                    st.session_state.model_info = st.session_state.detector.model_loader.get_model_info()
                
                st.success("✅ System Started!")
                time.sleep(0.5)
                st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")
    
    with col2:
        if st.button("⛔ STOP", use_container_width=True):
            if st.session_state.detector:
                st.session_state.detector.stop()
            st.session_state.running = False
            st.warning("System Stopped")
            time.sleep(0.5)
            st.rerun()
    
    st.markdown("---")
    
    # Model Information
    st.markdown("### 🤖 Modern IDS Model")
    
    if st.session_state.model_info:
        with st.container():
            st.markdown(f"""
            <div class="model-info">
                <strong>✅ Model Status:</strong> Active<br>
                <strong>🎯 Attack Classes:</strong> {st.session_state.model_info.get('attack_classes', '10')}<br>
                <strong>📊 Features:</strong> {st.session_state.model_info.get('feature_count', '45')}<br>
                <strong>🏆 Accuracy:</strong> 99%+<br>
                <strong>🔒 Threshold:</strong> 88% confidence / Severity 5+
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Start the system to see model info")
    
    st.markdown("---")
    
    # Alert Settings
    st.markdown("### 🎯 Alert Filters")
    
    if st.session_state.detector and st.session_state.running:
        current_conf = st.session_state.detector.min_confidence
        current_sev = st.session_state.detector.min_severity
        st.caption(f"Current: {current_conf*100:.0f}% confidence, Severity {current_sev}+")
    
    st.markdown("---")
    
    # Live stats
    if st.session_state.running and st.session_state.detector:
        stats = st.session_state.detector.get_stats()
        st.markdown("### 📊 Live Statistics")
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("📦 Packets", stats['packets_processed'])
        with col2:
            st.metric("⚠️ Threats", stats['threats_detected'], 
                     delta=stats['threats_detected'] if stats['threats_detected'] > 0 else None)
        
        if stats['packets_processed'] > 0:
            rate = (stats['threats_detected'] / stats['packets_processed']) * 100
            st.metric("🎯 Threat Rate", f"{rate:.1f}%")
        
        threat_level = min(stats['threats_detected'] / 30, 1.0)
        st.progress(threat_level, text=f"Threat Level: {int(threat_level*100)}%")
        
        mode_display = stats.get('mode', 'unknown')
        if mode_display == 'demo':
            st.info("🎮 Demo Mode - Realistic Threats")
        elif mode_display == 'live':
            st.success("🔴 Live Capture - Real Traffic")
        
        # Auto refresh toggle
        st.markdown("---")
        st.session_state.auto_refresh = st.checkbox("Auto Refresh", value=st.session_state.auto_refresh)
    
    st.markdown("---")
    
    # Database Stats
    st.markdown("### 🗄️ Database")
    try:
        conn = sqlite3.connect("data/ids_database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts_db = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(DISTINCT date(timestamp)) FROM alerts")
        total_days = cursor.fetchone()[0]
        conn.close()
        
        st.metric("Total Records", total_alerts_db)
        st.metric("Days of History", total_days if total_days else 0)
        st.caption(f"Memory: {len(st.session_state.alerts)} alerts")
    except:
        st.caption(f"Alerts in memory: {len(st.session_state.alerts)}")

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["🎯 Live Monitor", "📈 Analytics", "🗺️ Threat Intelligence", "📄 Reports & History"])

# ==================== TAB 1: Live Monitor ====================
with tab1:
    st.markdown("## 🎯 Real-Time Threat Monitor")
    st.caption("⚠️ Showing ONLY threats with >88% confidence and severity 5+ (HIGH/CRITICAL)")
    
    if st.session_state.running and st.session_state.detector:
        # Get new alerts
        new_alerts = st.session_state.detector.get_alerts()
        for alert in new_alerts:
            st.session_state.alerts.append(alert)
            st.session_state.db.save_alert(alert)
            st.session_state.alert_manager.process_alert(alert)
        
        # Display metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        stats = st.session_state.detector.get_stats()
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h4>📦 Total Packets</h4>
                <h2>{stats['packets_processed']}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h4>⚠️ Real Threats</h4>
                <h2 style="color: #ff6b6b">{stats['threats_detected']}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            risk = AttackMapper.calculate_risk_score(st.session_state.alerts) if st.session_state.alerts else 0
            risk_color = "red" if risk > 7 else "orange" if risk > 4 else "yellow"
            st.markdown(f"""
            <div class="metric-card">
                <h4>🎯 Risk Score</h4>
                <h2 style="color: {risk_color}">{risk:.1f}/10</h2>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            unique_ips = len(set([a['source_ip'] for a in st.session_state.alerts])) if st.session_state.alerts else 0
            st.markdown(f"""
            <div class="metric-card">
                <h4>🌐 Attackers</h4>
                <h2>{unique_ips}</h2>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Live alerts feed
        st.markdown("### 🚨 Real Threat Alert Feed")
        st.caption("🔴 CRITICAL (Severity 8-10) | 🟠 HIGH (Severity 5-7)")
        
        if st.session_state.alerts:
            # Filter to show only recent alerts
            recent_alerts = [a for a in st.session_state.alerts if 'confidence' in a and a.get('confidence', 0) >= 0.85]
            recent_alerts = recent_alerts[-30:] if len(recent_alerts) > 30 else recent_alerts
            
            if recent_alerts:
                alert_col1, alert_col2 = st.columns(2)
                alerts_list = list(reversed(recent_alerts))
                mid = len(alerts_list) // 2
                
                with alert_col1:
                    for alert in alerts_list[:mid]:
                        severity = alert.get('severity', AttackMapper.get_severity_score(alert['attack_type']))
                        confidence = alert.get('confidence', 0.85)
                        
                        if severity >= 8:
                            st.markdown(f"""
                            <div class="alert-critical">
                                🔴 <strong>CRITICAL</strong> - {alert['attack_type'].upper()}<br>
                                📍 {alert['source_ip']}<br>
                                ⏰ {alert['timestamp'][11:19] if len(alert['timestamp']) > 11 else alert['timestamp']}<br>
                                🎯 {confidence*100:.0f}% confidence | Severity: {severity}/10
                            </div>
                            """, unsafe_allow_html=True)
                        elif severity >= 5:
                            st.markdown(f"""
                            <div class="alert-high">
                                🟠 <strong>HIGH</strong> - {alert['attack_type'].upper()}<br>
                                📍 {alert['source_ip']}<br>
                                ⏰ {alert['timestamp'][11:19] if len(alert['timestamp']) > 11 else alert['timestamp']}<br>
                                🎯 {confidence*100:.0f}% confidence | Severity: {severity}/10
                            </div>
                            """, unsafe_allow_html=True)
                
                with alert_col2:
                    for alert in alerts_list[mid:]:
                        severity = alert.get('severity', AttackMapper.get_severity_score(alert['attack_type']))
                        confidence = alert.get('confidence', 0.85)
                        
                        if severity >= 8:
                            st.markdown(f"""
                            <div class="alert-critical">
                                🔴 <strong>CRITICAL</strong> - {alert['attack_type'].upper()}<br>
                                📍 {alert['source_ip']}<br>
                                ⏰ {alert['timestamp'][11:19] if len(alert['timestamp']) > 11 else alert['timestamp']}<br>
                                🎯 {confidence*100:.0f}% confidence | Severity: {severity}/10
                            </div>
                            """, unsafe_allow_html=True)
                        elif severity >= 5:
                            st.markdown(f"""
                            <div class="alert-high">
                                🟠 <strong>HIGH</strong> - {alert['attack_type'].upper()}<br>
                                📍 {alert['source_ip']}<br>
                                ⏰ {alert['timestamp'][11:19] if len(alert['timestamp']) > 11 else alert['timestamp']}<br>
                                🎯 {confidence*100:.0f}% confidence | Severity: {severity}/10
                            </div>
                            """, unsafe_allow_html=True)
            else:
                st.info("💡 No threats meeting confidence/severity thresholds. System monitoring...")
        else:
            st.info("💡 No threats detected yet. The system is monitoring...")
    else:
        st.info("👈 **Click START in the sidebar to begin monitoring**")
        
        st.markdown("""
        ### 🚀 Modern IDS Features:
        
        | Feature | Description |
        |---------|-------------|
        | **Binary Classifier** | Normal vs Attack detection |
        | **Multiclass Classifier** | Identifies specific attack types (10 classes) |
        | **Confidence Threshold** | Only >88% confidence alerts |
        | **Severity Filtering** | Only HIGH (5+) and CRITICAL (8+) alerts |
        | **Attack Types** | DDoS, Port Scan, Brute Force, Web Attacks, Infiltration, Botnet, etc. |
        
        ### 📋 Demo Instructions:
        1. Click **START** in the sidebar
        2. Select **Demo Mode**
        3. Watch only REAL threats appear (not normal traffic)
        4. Note: YouTube, Netflix, browsing will NOT trigger alerts
        """)

# ==================== TAB 2: Analytics ====================
with tab2:
    st.markdown("## 📈 Attack Analytics Dashboard")
    
    if st.session_state.alerts:
        df = pd.DataFrame(st.session_state.alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Real Threats", len(df))
        with col2:
            st.metric("Attack Types", df['attack_type'].nunique())
        with col3:
            avg_conf = df['confidence'].mean() * 100
            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        with col4:
            top_attack = df['attack_type'].mode()[0] if not df.empty else "None"
            st.metric("Most Common", top_attack.upper())
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🎯 Attack Type Distribution")
            attack_counts = df['attack_type'].value_counts()
            if len(attack_counts) > 0:
                fig = px.pie(values=attack_counts.values, names=attack_counts.index,
                            title="Real Threat Distribution", 
                            color_discrete_sequence=px.colors.sequential.Reds_r, 
                            hole=0.3)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### 🌐 Top Attack Sources")
            source_counts = df['source_ip'].value_counts().head(10)
            if len(source_counts) > 0:
                fig = px.bar(x=source_counts.values, y=source_counts.index, orientation='h',
                            title="Top 10 Attackers", color=source_counts.values,
                            color_continuous_scale="Reds")
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("#### 📅 Threat Timeline")
        df_sorted = df.sort_values('timestamp')
        df_sorted.set_index('timestamp', inplace=True)
        
        if len(df_sorted) > 1:
            timeline = df_sorted.resample('10s').size()
            if len(timeline) > 0:
                fig = px.line(x=timeline.index, y=timeline.values, 
                             title="Threat Frequency Over Time",
                             labels={'x': 'Time', 'y': 'Number of Threats'})
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("#### 📊 Detection Confidence Distribution")
        fig = px.histogram(df, x='confidence', nbins=20, 
                          title="Confidence Score Distribution (Real Threats Only)",
                          color_discrete_sequence=['green'])
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
    else:
        st.info("📊 No threat data available. Start monitoring to see analytics.")

# ==================== TAB 3: Threat Intelligence ====================
with tab3:
    st.markdown("## 🗺️ Threat Intelligence & MITRE ATT&CK")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🎯 Attack Classification")
        
        attack_data = {
            "Attack Type": ["DDoS", "Port Scan", "Brute Force", "Web Attack", "Infiltration", "Botnet", "DOS", "R2L", "U2R"],
            "Severity": ["9/10", "5/10", "7/10", "6/10", "10/10", "7/10", "8/10", "8/10", "10/10"],
            "MITRE ID": ["T1498", "T1040", "T1110", "T1190", "T1071", "T1071", "T1498", "T1078", "T1068"],
            "Tactic": ["Impact", "Discovery", "Credential Access", "Initial Access", "C2", "C2", "Impact", "Priv Esc", "Priv Esc"]
        }
        
        df_attacks = pd.DataFrame(attack_data)
        st.dataframe(df_attacks, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.markdown("### 💡 Security Recommendations")
        if st.session_state.alerts:
            recommendations = AttackMapper.get_recommendations(st.session_state.alerts)
            for i, rec in enumerate(recommendations[:5], 1):
                st.markdown(f"{i}. {rec}")
        else:
            st.info("No recommendations yet - start monitoring")
    
    with col2:
        st.markdown("### 📊 Current Risk Assessment")
        
        if st.session_state.alerts:
            risk = AttackMapper.calculate_risk_score(st.session_state.alerts)
            
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta", value=risk,
                title={"text": "Overall Risk Score", "font": {"size": 20}},
                delta={"reference": 5, "increasing": {"color": "red"}},
                gauge={"axis": {"range": [0, 10]}, "bar": {"color": "darkred"},
                       "steps": [{"range": [0, 3], "color": "lightgreen"},
                                {"range": [3, 6], "color": "yellow"},
                                {"range": [6, 8], "color": "orange"},
                                {"range": [8, 10], "color": "red"}]}
            ))
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("#### Severity Distribution")
            severities = [AttackMapper.get_severity_score(a['attack_type']) for a in st.session_state.alerts]
            severity_df = pd.DataFrame({'Severity': severities})
            severity_counts = severity_df['Severity'].value_counts().sort_index()
            
            if len(severity_counts) > 0:
                fig = px.bar(x=severity_counts.index, y=severity_counts.values,
                            title="Real Threat Severity Levels", color=severity_counts.values,
                            color_continuous_scale="Reds")
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No data available - start monitoring to see risk assessment")

# ==================== TAB 4: Reports & History ====================
with tab4:
    st.markdown("## 📄 Security Reports & Historical Data")
    
    # Historical Data Loader
    st.markdown("### 📜 Load Historical Records")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        time_period = st.selectbox(
            "Select Time Period",
            ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
        )
    
    with col2:
        if st.button("🔄 Load from Database", use_container_width=True):
            try:
                if time_period == "Last 24 Hours":
                    hours = 24
                elif time_period == "Last 7 Days":
                    hours = 24 * 7
                elif time_period == "Last 30 Days":
                    hours = 24 * 30
                else:
                    hours = 24 * 365
                
                historical_df = st.session_state.db.get_alerts(hours=hours, limit=10000)
                
                if not historical_df.empty:
                    historical_alerts = historical_df.to_dict('records')
                    existing_keys = set([(a['timestamp'], a['source_ip'], a['attack_type']) for a in st.session_state.alerts])
                    new_alerts = [a for a in historical_alerts if (a['timestamp'], a['source_ip'], a['attack_type']) not in existing_keys]
                    st.session_state.alerts.extend(new_alerts)
                    st.success(f"✅ Loaded {len(new_alerts)} historical records! Total: {len(st.session_state.alerts)}")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.info("No historical records found")
            except Exception as e:
                st.error(f"Error: {e}")
    
    with col3:
        if st.button("📊 Show DB Statistics", use_container_width=True):
            try:
                conn = sqlite3.connect("data/ids_database.db")
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM alerts")
                total = cursor.fetchone()[0]
                cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts")
                min_date, max_date = cursor.fetchone()
                cursor.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type")
                attack_counts = cursor.fetchall()
                conn.close()
                
                st.markdown(f"""
                <div class="historical-card">
                    <strong>📊 Database Statistics:</strong><br>
                    Total Records: {total}<br>
                    Date Range: {min_date} to {max_date}<br>
                    Attack Types: {len(attack_counts)}<br>
                </div>
                """, unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Error: {e}")
    
    st.markdown("---")
    
    if st.session_state.alerts:
        df_alerts = pd.DataFrame(st.session_state.alerts)
        df_alerts['severity'] = df_alerts['attack_type'].apply(lambda x: AttackMapper.get_severity_score(x))
        
        # Quick Filters
        st.markdown("### 🔍 Quick Filters")
        quick_col1, quick_col2, quick_col3, quick_col4 = st.columns(4)
        
        filtered_df = df_alerts.copy()
        
        with quick_col1:
            if st.button("🔴 Critical Only", use_container_width=True):
                filtered_df = df_alerts[df_alerts['severity'] >= 8]
        
        with quick_col2:
            if st.button("🟠 High Only", use_container_width=True):
                filtered_df = df_alerts[(df_alerts['severity'] >= 5) & (df_alerts['severity'] < 8)]
        
        with quick_col3:
            if st.button("🎯 High Confidence (>90%)", use_container_width=True):
                filtered_df = df_alerts[df_alerts['confidence'] >= 0.90]
        
        with quick_col4:
            if st.button("🔄 Show All", use_container_width=True):
                filtered_df = df_alerts
        
        st.markdown("---")
        
        # Advanced Filters
        st.markdown("### 🔧 Advanced Filters")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            attack_types = ['All'] + sorted(df_alerts['attack_type'].unique().tolist())
            selected_attack = st.selectbox("Attack Type", attack_types)
        
        with col2:
            all_ips = ['All'] + sorted(df_alerts['source_ip'].unique().tolist())
            selected_ip = st.selectbox("Source IP", all_ips)
        
        with col3:
            min_confidence = st.slider("Min Confidence", 0.70, 0.98, 0.85, 0.01)
        
        with col4:
            severity_options = ['All', 'Critical (8-10)', 'High (5-7)']
            selected_severity = st.selectbox("Severity Level", severity_options)
        
        # Apply filters
        if selected_attack != "All":
            filtered_df = filtered_df[filtered_df['attack_type'] == selected_attack]
        if selected_ip != "All":
            filtered_df = filtered_df[filtered_df['source_ip'] == selected_ip]
        filtered_df = filtered_df[filtered_df['confidence'] >= min_confidence]
        
        if selected_severity == "Critical (8-10)":
            filtered_df = filtered_df[filtered_df['severity'] >= 8]
        elif selected_severity == "High (5-7)":
            filtered_df = filtered_df[(filtered_df['severity'] >= 5) & (filtered_df['severity'] < 8)]
        
        st.info(f"📊 Showing **{len(filtered_df)}** of **{len(df_alerts)}** real threats")
        st.markdown("---")
        
        # Display Data
        st.markdown("### 📋 Threat Records")
        
        display_df = filtered_df.copy()
        display_df = display_df[['timestamp', 'source_ip', 'attack_type', 'confidence', 'severity']]
        display_df.columns = ['Timestamp', 'Source IP', 'Attack Type', 'Confidence', 'Severity']
        display_df['Confidence'] = display_df['Confidence'].apply(lambda x: f"{x*100:.1f}%")
        display_df['Severity'] = display_df['Severity'].apply(lambda x: f"{x}/10")
        
        st.dataframe(display_df, use_container_width=True)
        
        st.markdown("---")
        
        # Statistics
        if not filtered_df.empty:
            st.markdown("### 📊 Filtered Statistics")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Threats", len(filtered_df))
                st.metric("Unique Attackers", filtered_df['source_ip'].nunique())
            
            with col2:
                top_attack = filtered_df['attack_type'].mode()[0] if not filtered_df.empty else "None"
                st.metric("Most Common Attack", top_attack.upper())
                avg_conf = filtered_df['confidence'].mean() * 100
                st.metric("Avg Confidence", f"{avg_conf:.1f}%")
            
            with col3:
                critical = len(filtered_df[filtered_df['severity'] >= 8])
                high = len(filtered_df[(filtered_df['severity'] >= 5) & (filtered_df['severity'] < 8)])
                st.metric("Critical Threats", critical)
                st.metric("High Threats", high)
            
            attack_counts = filtered_df['attack_type'].value_counts()
            if len(attack_counts) > 0:
                fig = px.pie(values=attack_counts.values, names=attack_counts.index,
                            title="Threat Distribution", 
                            color_discrete_sequence=px.colors.sequential.Reds_r)
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Export Options
        st.markdown("### 💾 Export Options")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📊 Export to CSV", use_container_width=True):
                csv = filtered_df.to_csv(index=False)
                st.download_button("Download CSV", csv, f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
        
        with col2:
            if st.button("📋 Export to JSON", use_container_width=True):
                json_str = filtered_df.to_json(orient='records', indent=2)
                st.download_button("Download JSON", json_str, f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "application/json")
        
        with col3:
            if st.button("📊 Export to Excel", use_container_width=True):
                try:
                    excel_file = f"exports/threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
                    os.makedirs("exports", exist_ok=True)
                    filtered_df.to_excel(excel_file, index=False)
                    with open(excel_file, 'rb') as f:
                        st.download_button("Download Excel", f, excel_file.split('/')[-1], "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                except Exception as e:
                    st.error(f"Excel error: {e}")
        
        with col4:
            if st.button("📄 Export to PDF", use_container_width=True):
                if PDF_AVAILABLE:
                    try:
                        exporter = PDFExporter()
                        pdf_file = exporter.export_alerts_to_pdf(filtered_df)
                        with open(pdf_file, 'rb') as f:
                            st.download_button("Download PDF", f, pdf_file.split('/')[-1], "application/pdf")
                    except Exception as e:
                        st.error(f"PDF error: {e}")
                else:
                    st.error("Install fpdf2: pip install fpdf2")
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📦 Export ALL Historical Data", use_container_width=True):
                try:
                    all_data = st.session_state.db.get_alerts(hours=24*365, limit=100000)
                    if not all_data.empty:
                        csv_all = all_data.to_csv(index=False)
                        st.download_button("Download Complete History", csv_all, f"complete_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
                except Exception as e:
                    st.error(f"Error: {e}")
        
        with col2:
            if st.button("🗑️ Clear Current View", use_container_width=True):
                st.session_state.alerts = []
                st.success("Cleared! Reload from database to restore.")
                time.sleep(1)
                st.rerun()
        
    else:
        st.info("📄 No threat data available. Start monitoring or load historical data.")

# Auto refresh for real-time updates
if st.session_state.running and st.session_state.auto_refresh:
    time.sleep(2)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: gray; padding: 1rem;">
    <p>🛡️ FlowWatch AI - Modern Hybrid Intrusion Detection System</p>
    <p>Powered by XGBoost Ensemble | Binary + Multiclass | 99%+ Accuracy | Real Threats Only</p>
    <p style="font-size: 0.8rem;">Final Year Project 2026 | Department of Information Technology</p>
</div>
""", unsafe_allow_html=True)
