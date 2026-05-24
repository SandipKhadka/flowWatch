"""
Reports Page - Generate and export security reports with database integration
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import io
from ..session_state import session
from ..components import MetricCard, CardStyle, InfoCard
from ...utils.attack_mapper import AttackMapper
from ...utils.database_manager import DatabaseManager
from ...utils.pdf_generator import PDFExporter
import sqlite3


class ReportsPage:
    """Reports page for generating security reports from database"""
    
    def __init__(self):
        self.attack_mapper = AttackMapper()
        self.db = DatabaseManager()
        self.pdf_exporter = PDFExporter()
    
    def render(self):
        """Render the reports page"""
        st.markdown("## 📄 Security Reports & Export")
        st.caption("Generate comprehensive security reports from database records")
        
        # Load data from database
        self._load_data_from_db()
        
        alerts = session.get('alerts', [])
        
        # Convert to DataFrame with proper datetime handling
        if alerts:
            df = pd.DataFrame(alerts)
            if 'timestamp' in df.columns:
                # Convert to datetime, handling both string and datetime
                df['timestamp'] = pd.to_datetime(df['timestamp'])
        else:
            df = pd.DataFrame()
        
        # Report generation section
        self._render_report_generator(df)
        
        st.markdown("---")
        
        if not df.empty:
            # Data export section
            self._render_data_export(df)
            
            st.markdown("---")
            
            # Executive summary
            self._render_executive_summary(df)
            
            st.markdown("---")
            
            # Historical data management
            self._render_historical_data()
        else:
            self._render_empty_state()
    
    def _load_data_from_db(self):
        """Load data from database into session state"""
        try:
            if not session.get('historical_loaded', False):
                with st.spinner("Loading data from database..."):
                    historical_df = self.db.get_alerts(hours=720, limit=10000)
                    
                    if not historical_df.empty:
                        historical_alerts = historical_df.to_dict('records')
                        
                        existing_keys = {
                            (a['timestamp'], a['source_ip'], a['attack_type']) 
                            for a in session.get('alerts', [])
                        }
                        
                        new_alerts = [
                            a for a in historical_alerts 
                            if (a['timestamp'], a['source_ip'], a['attack_type']) not in existing_keys
                        ]
                        
                        if new_alerts:
                            current_alerts = session.get('alerts', [])
                            session.set('alerts', current_alerts + new_alerts)
                            session.set('historical_loaded', True)
                            st.success(f"✅ Loaded {len(new_alerts)} historical records")
        except Exception as e:
            st.error(f"Error loading from database: {e}")
    
    def _render_report_generator(self, df: pd.DataFrame):
        """Render report generation controls"""
        st.markdown("### 📊 Generate Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_type = st.selectbox(
                "Report Type",
                ["Executive Summary", "Detailed Analysis", "Threat Intelligence", "Compliance Report"],
                key="report_type"
            )
        
        with col2:
            time_range = st.selectbox(
                "Time Range",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
                key="time_range"
            )
        
        if st.button("📄 Generate Report", use_container_width=True):
            if not df.empty:
                self._generate_report(df, report_type, time_range)
            else:
                st.warning("No data available. Load historical data or start monitoring.")
    
    def _generate_report(self, df: pd.DataFrame, report_type: str, time_range: str):
        """Generate and display report"""
        st.markdown("### 📋 Report Preview")
        
        # Filter data
        df_filtered = df.copy()
        
        if time_range == "Last 24 Hours":
            cutoff = datetime.now() - timedelta(hours=24)
            df_filtered = df_filtered[df_filtered['timestamp'] >= cutoff]
        elif time_range == "Last 7 Days":
            cutoff = datetime.now() - timedelta(days=7)
            df_filtered = df_filtered[df_filtered['timestamp'] >= cutoff]
        elif time_range == "Last 30 Days":
            cutoff = datetime.now() - timedelta(days=30)
            df_filtered = df_filtered[df_filtered['timestamp'] >= cutoff]
        
        if df_filtered.empty:
            st.warning("No data available for selected time range")
            return
        
        # Display summary
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Threats", len(df_filtered))
        with col2:
            st.metric("Unique Attackers", df_filtered['source_ip'].nunique())
        with col3:
            avg_conf = df_filtered['confidence'].mean() * 100
            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        
        # Top threats
        st.markdown("#### Top Threats")
        top_threats = df_filtered['attack_type'].value_counts().head(5)
        for threat, count in top_threats.items():
            st.progress(count / len(df_filtered), text=f"{threat.upper()}: {count} attacks")
    
    def _render_data_export(self, df: pd.DataFrame):
        """Render data export options"""
        st.markdown("### 💾 Export Data")
        
        if df.empty:
            st.info("No data to export")
            return
        
        col1, col2, col3, col4 = st.columns(4)
        
        # CSV Export
        with col1:
            if st.button("📊 Export CSV", use_container_width=True):
                df_export = df.copy()
                if 'timestamp' in df_export.columns:
                    df_export['timestamp'] = df_export['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                
                csv_buffer = io.StringIO()
                df_export.to_csv(csv_buffer, index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv_buffer.getvalue(),
                    file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key="csv_download"
                )
        
        # JSON Export
        with col2:
            if st.button("📋 Export JSON", use_container_width=True):
                df_export = df.copy()
                if 'timestamp' in df_export.columns:
                    df_export['timestamp'] = df_export['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                
                json_data = df_export.to_json(orient='records', indent=2)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    key="json_download"
                )
        
        # Excel Export
        with col3:
            if st.button("📊 Export Excel", use_container_width=True):
                try:
                    df_export = df.copy()
                    if 'timestamp' in df_export.columns:
                        df_export['timestamp'] = df_export['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    excel_buffer = io.BytesIO()
                    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                        df_export.to_excel(writer, index=False, sheet_name='Threats')
                        
                        # Summary sheet
                        summary_data = {
                            'Metric': ['Total Threats', 'Unique Attackers', 'Attack Types', 'Date Range'],
                            'Value': [
                                len(df_export),
                                df_export['source_ip'].nunique(),
                                df_export['attack_type'].nunique(),
                                f"{df['timestamp'].min()} to {df['timestamp'].max()}"
                            ]
                        }
                        pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
                    
                    st.download_button(
                        label="Download Excel",
                        data=excel_buffer.getvalue(),
                        file_name=f"threats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        key="excel_download"
                    )
                except Exception as e:
                    st.error(f"Excel export failed: {e}")
        
        # PDF Export
        with col4:
            if st.button("📄 Export PDF", use_container_width=True):
                with st.spinner("Generating PDF report..."):
                    try:
                        # Convert to string timestamps for PDF
                        df_pdf = df.copy()
                        if 'timestamp' in df_pdf.columns:
                            df_pdf['timestamp'] = df_pdf['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Generate PDF
                        filename = self.pdf_exporter.export_alerts_to_pdf(df_pdf)
                        
                        # Read and download
                        with open(filename, 'rb') as f:
                            pdf_data = f.read()
                        
                        st.download_button(
                            label="Download PDF",
                            data=pdf_data,
                            file_name=os.path.basename(filename),
                            mime="application/pdf",
                            key="pdf_download"
                        )
                        st.success("✅ PDF generated successfully!")
                    except Exception as e:
                        st.error(f"PDF export failed: {e}")
    
    def _render_executive_summary(self, df: pd.DataFrame):
        """Render executive summary statistics"""
        st.markdown("### 📈 Database Statistics")
        
        try:
            conn = sqlite3.connect("data/ids_database.db")
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_records = cursor.fetchone()[0]
            
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM alerts")
            min_date, max_date = cursor.fetchone()
            
            cursor.execute("SELECT attack_type, COUNT(*) FROM alerts GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 5")
            top_attacks = cursor.fetchall()
            
            conn.close()
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total Records in DB", f"{total_records:,}")
                if min_date and max_date:
                    st.caption(f"📅 {str(min_date)[:10]} to {str(max_date)[:10]}")
            
            with col2:
                st.markdown("#### Top Attack Types")
                for attack, count in top_attacks[:3]:
                    st.markdown(f"• {attack.upper()}: {count:,}")
            
            with col3:
                st.markdown("#### Current Session")
                st.metric("Records in Memory", f"{len(df):,}")
                
        except Exception as e:
            st.error(f"Error getting database stats: {e}")
    
    def _render_historical_data(self):
        """Render historical data loader"""
        st.markdown("### 📜 Historical Data Management")
        
        col1, col2 = st.columns(2)
        
        with col1:
            days = st.number_input("Load last N days", min_value=1, max_value=365, value=30)
            if st.button("🔄 Load from Database", use_container_width=True):
                with st.spinner(f"Loading last {days} days..."):
                    try:
                        hours = days * 24
                        historical_df = self.db.get_alerts(hours=hours, limit=50000)
                        
                        if not historical_df.empty:
                            historical_alerts = historical_df.to_dict('records')
                            session.set('alerts', historical_alerts)
                            session.set('historical_loaded', True)
                            st.success(f"✅ Loaded {len(historical_alerts)} records")
                            st.rerun()
                        else:
                            st.info("No historical records found")
                    except Exception as e:
                        st.error(f"Error: {e}")
        
        with col2:
            if st.button("🗑️ Clear Session Data", use_container_width=True):
                session.set('alerts', [])
                session.set('historical_loaded', False)
                st.success("Session data cleared")
                st.rerun()
    
    def _render_empty_state(self):
        """Render empty state"""
        st.info("📄 No data available. Load historical data or start monitoring.")
        
        st.markdown("""
        ### 📊 How to get data:
        
        1. **Load Historical Data** - Use the button above to load from database
        2. **Start Monitoring** - Click START in sidebar and select Demo Mode
        3. **Export Reports** - CSV, JSON, Excel, and PDF formats available
        
        ### 📈 Available Reports:
        
        - **Executive Summary** - High-level security overview
        - **Detailed Analysis** - In-depth threat investigation  
        - **Threat Intelligence** - MITRE ATT&CK mapping
        - **Compliance Report** - Security controls assessment
        """)


import os
