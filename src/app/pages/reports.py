"""
Reports Page - Working Exports Using PDFExporter
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import io
import os
from ..session_state import session
from ...utils.attack_mapper import AttackMapper
from ...utils.database_manager import DatabaseManager
from ...utils.pdf_generator import PDFExporter


class ReportsPage:
    """Reports page with working export functionality"""
    
    def __init__(self):
        self.attack_mapper = AttackMapper()
        self.db = DatabaseManager()
        self.pdf_exporter = PDFExporter()
    
    def render(self):
        """Render the reports page"""
        
        # Load data
        self._load_data_from_db()
        alerts = session.get('alerts', [])
        
        if alerts:
            df = pd.DataFrame(alerts)
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
        else:
            df = pd.DataFrame()
        
        # Header
        st.markdown("## 📄 Reports & Export Center")
        st.caption("Export your security data in multiple formats")
        
        # Show data status
        if not df.empty:
            st.success(f"✅ **{len(df):,} records** ready to export")
        else:
            st.warning("⚠️ No data available. Start monitoring or load historical data.")
            self._render_loading_options()
            return
        
        st.markdown("---")
        
        # Create tabs for different export methods
        tab1, tab2, tab3 = st.tabs(["📊 Quick Export", "📄 Smart Report", "📈 Analytics"])
        
        with tab1:
            self._render_export_tab(df)
        
        with tab2:
            self._render_report_tab(df)
        
        with tab3:
            self._render_analytics_tab(df)
    
    def _render_export_tab(self, df: pd.DataFrame):
        """Render export tab with working downloads"""
        st.markdown("### Export Your Data")
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            date_filter = st.selectbox(
                "Time Range",
                ["All Time", "Last 24 Hours", "Last 7 Days", "Last 30 Days"],
                key="export_date_filter"
            )
        
        with col2:
            attack_types = ['All'] + sorted(df['attack_type'].unique().tolist())
            attack_filter = st.selectbox("Attack Type", attack_types, key="export_attack_filter")
        
        with col3:
            min_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.0, 0.05, key="export_confidence")
        
        # Apply filters
        filtered_df = df.copy()
        
        if date_filter == "Last 24 Hours":
            cutoff = datetime.now() - timedelta(hours=24)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        elif date_filter == "Last 7 Days":
            cutoff = datetime.now() - timedelta(days=7)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        elif date_filter == "Last 30 Days":
            cutoff = datetime.now() - timedelta(days=30)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        
        if attack_filter != 'All':
            filtered_df = filtered_df[filtered_df['attack_type'] == attack_filter]
        
        filtered_df = filtered_df[filtered_df['confidence'] >= min_confidence]
        
        # Show record count
        st.info(f"📊 **{len(filtered_df)} records** will be exported")
        
        # Preview
        with st.expander("🔍 Preview Data"):
            preview_df = filtered_df.head(10).copy()
            if 'timestamp' in preview_df.columns:
                preview_df['timestamp'] = preview_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            if 'confidence' in preview_df.columns:
                preview_df['confidence'] = preview_df['confidence'].apply(lambda x: f"{x*100:.1f}%")
            st.dataframe(preview_df, use_container_width=True)
        
        st.markdown("---")
        st.markdown("### Choose Export Format")
        
        # Export buttons in a grid
        col1, col2, col3, col4 = st.columns(4)
        
        # CSV Export
        with col1:
            if st.button("📊 **CSV**\nExcel Compatible", use_container_width=True):
                self._export_csv(filtered_df)
        
        # JSON Export
        with col2:
            if st.button("📋 **JSON**\nAPI Ready", use_container_width=True):
                self._export_json(filtered_df)
        
        # Excel Export
        with col3:
            if st.button("📈 **Excel**\nMulti-sheet", use_container_width=True):
                self._export_excel(filtered_df)
        
        # PDF Export
        with col4:
            if st.button("📄 **PDF**\nProfessional", use_container_width=True):
                self._export_pdf(filtered_df)
    
    def _render_report_tab(self, df: pd.DataFrame):
        """Render report generation tab"""
        st.markdown("### Generate Security Report")
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_type = st.selectbox(
                "Report Type",
                ["Executive Summary", "Detailed Analysis", "Threat Intelligence"],
                key="report_type"
            )
        
        with col2:
            date_range = st.selectbox(
                "Time Period",
                ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
                key="report_date"
            )
        
        # Apply date filter
        filtered_df = df.copy()
        if date_range == "Last 24 Hours":
            cutoff = datetime.now() - timedelta(hours=24)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        elif date_range == "Last 7 Days":
            cutoff = datetime.now() - timedelta(days=7)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        elif date_range == "Last 30 Days":
            cutoff = datetime.now() - timedelta(days=30)
            filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff]
        
        if filtered_df.empty:
            st.warning("No data for selected period")
            return
        
        # Show report preview
        st.markdown("### Report Preview")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Threats", len(filtered_df))
        with col2:
            st.metric("Unique Attackers", filtered_df['source_ip'].nunique())
        with col3:
            avg_conf = filtered_df['confidence'].mean() * 100
            st.metric("Avg Confidence", f"{avg_conf:.1f}%")
        
        # Top threats
        st.markdown("#### Top Threats")
        top_threats = filtered_df['attack_type'].value_counts().head(5)
        for threat, count in top_threats.items():
            st.progress(count / len(filtered_df), text=f"{threat.upper()}: {count} attacks")
        
        # Export report
        st.markdown("---")
        if st.button("📄 Download Report", use_container_width=True):
            self._export_csv(filtered_df, f"{report_type.lower().replace(' ', '_')}")
    
    def _render_analytics_tab(self, df: pd.DataFrame):
        """Render analytics tab with visualizations"""
        st.markdown("### Security Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack distribution pie chart
            attack_counts = df['attack_type'].value_counts().head(8)
            if not attack_counts.empty:
                fig = px.pie(
                    values=attack_counts.values,
                    names=attack_counts.index,
                    title="Attack Distribution",
                    hole=0.3
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Timeline chart
            df_sorted = df.sort_values('timestamp')
            df_sorted.set_index('timestamp', inplace=True)
            daily_counts = df_sorted.resample('D').size().reset_index()
            daily_counts.columns = ['Date', 'Count']
            
            if not daily_counts.empty:
                fig = px.line(
                    daily_counts,
                    x='Date',
                    y='Count',
                    title="Attack Timeline",
                    markers=True
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        # Top attackers
        st.markdown("#### Top Attackers")
        top_attackers = df['source_ip'].value_counts().head(10)
        if not top_attackers.empty:
            fig = px.bar(
                x=top_attackers.values,
                y=top_attackers.index,
                orientation='h',
                title="Top 10 Attackers",
                color=top_attackers.values,
                color_continuous_scale='Reds'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        # Export analytics data
        if st.button("📊 Export Analytics Data", use_container_width=True):
            self._export_csv(df, "analytics_data")
    
    def _export_csv(self, df: pd.DataFrame, prefix: str = "export"):
        """Export to CSV with working download"""
        try:
            # Prepare data
            export_df = df.copy()
            if 'timestamp' in export_df.columns:
                export_df['timestamp'] = export_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            if 'confidence' in export_df.columns:
                export_df['confidence'] = export_df['confidence'].apply(lambda x: f"{x:.3f}")
            
            # Create CSV
            csv_buffer = io.StringIO()
            export_df.to_csv(csv_buffer, index=False)
            
            # Generate filename
            filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            # Show download button
            st.download_button(
                label="✅ Click to Download CSV",
                data=csv_buffer.getvalue(),
                file_name=filename,
                mime="text/csv",
                key=f"csv_download_{datetime.now().timestamp()}"
            )
            st.success(f"✅ CSV ready! {len(df)} records exported")
            
        except Exception as e:
            st.error(f"CSV export failed: {str(e)}")
    
    def _export_json(self, df: pd.DataFrame, prefix: str = "export"):
        """Export to JSON with working download"""
        try:
            # Prepare data
            export_df = df.copy()
            if 'timestamp' in export_df.columns:
                export_df['timestamp'] = export_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            
            # Convert to JSON
            json_data = export_df.to_json(orient='records', indent=2)
            
            # Generate filename
            filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Show download button
            st.download_button(
                label="✅ Click to Download JSON",
                data=json_data,
                file_name=filename,
                mime="application/json",
                key=f"json_download_{datetime.now().timestamp()}"
            )
            st.success(f"✅ JSON ready! {len(df)} records exported")
            
        except Exception as e:
            st.error(f"JSON export failed: {str(e)}")
    
    def _export_excel(self, df: pd.DataFrame, prefix: str = "export"):
        """Export to Excel with working download"""
        try:
            # Prepare data
            export_df = df.copy()
            if 'timestamp' in export_df.columns:
                export_df['timestamp'] = export_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
            if 'confidence' in export_df.columns:
                export_df['confidence'] = export_df['confidence'].apply(lambda x: f"{x:.3f}")
            
            # Create Excel file
            excel_buffer = io.BytesIO()
            with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                export_df.to_excel(writer, index=False, sheet_name='Threats')
                
                # Add summary sheet
                summary_data = {
                    'Metric': ['Total Records', 'Unique Attackers', 'Attack Types', 'Generated'],
                    'Value': [
                        len(export_df),
                        export_df['source_ip'].nunique(),
                        export_df['attack_type'].nunique(),
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    ]
                }
                pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            excel_buffer.seek(0)
            
            # Generate filename
            filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            
            # Show download button
            st.download_button(
                label="✅ Click to Download Excel",
                data=excel_buffer.getvalue(),
                file_name=filename,
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"excel_download_{datetime.now().timestamp()}"
            )
            st.success(f"✅ Excel ready! {len(df)} records exported")
            
        except Exception as e:
            st.error(f"Excel export failed: {str(e)}")
            st.info("Try installing openpyxl: pip install openpyxl")
    
    def _export_pdf(self, df: pd.DataFrame, prefix: str = "export"):
        """Export to PDF using your PDFExporter"""
        try:
            with st.spinner("Generating PDF report..."):
                # Prepare data for PDF (convert timestamps to string)
                pdf_df = df.copy()
                if 'timestamp' in pdf_df.columns:
                    pdf_df['timestamp'] = pdf_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                if 'confidence' in pdf_df.columns:
                    pdf_df['confidence'] = pdf_df['confidence'].apply(lambda x: float(x))
                
                # Generate PDF using your exporter
                filename = self.pdf_exporter.export_alerts_to_pdf(pdf_df)
                
                # Read the generated PDF file
                with open(filename, 'rb') as f:
                    pdf_data = f.read()
                
                # Generate download filename
                download_filename = f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
                
                # Show download button
                st.download_button(
                    label="✅ Click to Download PDF",
                    data=pdf_data,
                    file_name=download_filename,
                    mime="application/pdf",
                    key=f"pdf_download_{datetime.now().timestamp()}"
                )
                st.success(f"✅ PDF ready! {len(df)} records exported")
                
        except Exception as e:
            st.error(f"PDF export failed: {str(e)}")
            st.info("Make sure fpdf is installed: pip install fpdf")
    
    def _render_loading_options(self):
        """Show options to load data"""
        st.markdown("### How to get data:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 Load Historical Data", use_container_width=True):
                with st.spinner("Loading data from database..."):
                    historical_df = self.db.get_alerts(hours=720, limit=5000)
                    if not historical_df.empty:
                        session.set('alerts', historical_df.to_dict('records'))
                        session.set('historical_loaded', True)
                        st.success(f"✅ Loaded {len(historical_df)} records!")
                        st.rerun()
                    else:
                        st.info("No historical data found")
        
        with col2:
            st.markdown("""
            **Or start monitoring:**
            1. Click START in sidebar
            2. Select Demo Mode
            3. Wait for threats to be detected
            4. Return here to export
            """)
    
    def _load_data_from_db(self):
        """Load data from database"""
        try:
            if not session.get('historical_loaded', False):
                historical_df = self.db.get_alerts(hours=720, limit=5000)
                if not historical_df.empty:
                    current_alerts = session.get('alerts', [])
                    historical_alerts = historical_df.to_dict('records')
                    
                    existing_keys = {
                        (a['timestamp'], a['source_ip'], a['attack_type']) 
                        for a in current_alerts
                    }
                    
                    new_alerts = [
                        a for a in historical_alerts 
                        if (a['timestamp'], a['source_ip'], a['attack_type']) not in existing_keys
                    ]
                    
                    if new_alerts:
                        session.set('alerts', current_alerts + new_alerts)
                        session.set('historical_loaded', True)
        except Exception:
            pass
