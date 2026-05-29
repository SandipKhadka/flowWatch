"""
Analytics Page - Comprehensive attack analytics and visualizations
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from ..session_state import session
from ..components import MetricCard, CardStyle
from ...utils.attack_mapper import AttackMapper


class AnalyticsPage:
    """Analytics page with detailed statistics and visualizations"""
    
    def __init__(self):
        self.attack_mapper = AttackMapper()
    
    def render(self):
        """Render the analytics page"""
        st.markdown("## 📈 Attack Analytics Dashboard")
        st.caption("Comprehensive analysis of detected threats and attack patterns")
        
        alerts = session.get('alerts', [])
        
        if not alerts:
            self._render_empty_state()
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Time range selector
        df = self._render_time_range_selector(df)
        
        if df.empty:
            st.warning("No data available for selected time range")
            return
        
        # Key metrics
        self._render_key_metrics(df)
        
        st.markdown("---")
        
        # Charts Row 1
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_attack_distribution(df)
        
        with col2:
            self._render_severity_distribution(df)
        
        # Charts Row 2
        col1, col2 = st.columns(2)
        
        with col1:
            self._render_top_attackers(df)
        
        with col2:
            self._render_top_targets(df)
        
        st.markdown("---")
        
        # Time series analysis
        self._render_time_series_analysis(df)
        
        st.markdown("---")
        
        # Advanced analytics
        self._render_advanced_analytics(df)
        
        st.markdown("---")
        
        # Attack patterns
        self._render_attack_patterns(df)
    
    def _render_empty_state(self):
        """Render empty state message"""
        st.info("📊 No threat data available. Start monitoring to see analytics.")
        st.markdown("""
        ### 📈 What you'll see here:
        
        - **Attack Distribution** - Types of attacks detected
        - **Severity Levels** - Critical vs High threats
        - **Top Attackers** - Most frequent source IPs
        - **Time Series** - Attack patterns over time
        - **Risk Trends** - Security risk evolution
        - **Attack Patterns** - Behavioral analysis
        """)
    
    def _render_time_range_selector(self, df: pd.DataFrame):
        """Render time range selector"""
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            time_ranges = {
                "Last 24 Hours": 24,
                "Last 7 Days": 168,
                "Last 30 Days": 720,
                "All Time": None
            }
            selected_range = st.selectbox(
                "📅 Time Range",
                list(time_ranges.keys()),
                key="analytics_time_range"
            )
            
            if time_ranges[selected_range]:
                cutoff = datetime.now() - timedelta(hours=time_ranges[selected_range])
                df = df[df['timestamp'] >= cutoff]
        
        with col2:
            st.metric("📊 Total Threats", f"{len(df):,}")
        
        with col3:
            unique_attackers = df['source_ip'].nunique()
            st.metric("🌐 Unique Attackers", f"{unique_attackers:,}")
        
        return df
    
    def _render_key_metrics(self, df: pd.DataFrame):
        """Render key metrics cards"""
        col1, col2, col3, col4 = st.columns(4)
        
        # Calculate metrics
        avg_confidence = df['confidence'].mean() * 100
        risk_score = self.attack_mapper.calculate_risk_score(df.to_dict('records'))
        critical_count = len(df[df['severity'] >= 8]) if 'severity' in df.columns else 0
        high_count = len(df[(df['severity'] >= 5) & (df['severity'] < 8)]) if 'severity' in df.columns else 0
        
        metrics = [
            ("⭐ Avg Confidence", f"{avg_confidence:.1f}%", None, CardStyle.SUCCESS),
            ("🎯 Risk Score", f"{risk_score:.1f}/10", None, CardStyle.DANGER if risk_score > 7 else CardStyle.WARNING),
            ("🔴 Critical", f"{critical_count:,}", None, CardStyle.DANGER),
            ("🟠 High", f"{high_count:,}", None, CardStyle.WARNING)
        ]
        
        for col, (title, value, delta, style) in zip([col1, col2, col3, col4], metrics):
            with col:
                MetricCard.render(title, value, delta, style)
    
    def _render_attack_distribution(self, df: pd.DataFrame):
        """Render attack type distribution"""
        st.markdown("#### 🎯 Attack Type Distribution")
        
        attack_counts = df['attack_type'].value_counts()
        
        if len(attack_counts) > 0:
            fig = px.pie(
                values=attack_counts.values,
                names=attack_counts.index,
                title="Threats by Type",
                color_discrete_sequence=px.colors.sequential.Reds_r,
                hole=0.3
            )
            fig.update_layout(height=400, showlegend=True)
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
            
            # Show detailed table
            with st.expander("📋 View Detailed Breakdown"):
                breakdown_df = pd.DataFrame({
                    'Attack Type': attack_counts.index,
                    'Count': attack_counts.values,
                    'Percentage': (attack_counts.values / len(df) * 100).round(1)
                })
                st.dataframe(breakdown_df, use_container_width=True, hide_index=True)
    
    def _render_severity_distribution(self, df: pd.DataFrame):
        """Render severity distribution"""
        st.markdown("#### ⚠️ Severity Distribution")
        
        if 'severity' in df.columns:
            severity_counts = df['severity'].value_counts().sort_index()
            
            fig = go.Figure(data=[
                go.Bar(
                    x=severity_counts.index.astype(str),
                    y=severity_counts.values,
                    marker_color=['#10b981', '#f59e0b', '#f97316', '#ef4444'],
                    text=severity_counts.values,
                    textposition='auto'
                )
            ])
            fig.update_layout(
                title="Threat Severity Levels",
                xaxis_title="Severity Score",
                yaxis_title="Number of Threats",
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Severity statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Average Severity", f"{df['severity'].mean():.1f}/10")
            with col2:
                st.metric("Median Severity", f"{df['severity'].median():.1f}/10")
            with col3:
                st.metric("Max Severity", f"{df['severity'].max():.1f}/10")
    
    def _render_top_attackers(self, df: pd.DataFrame):
        """Render top attackers chart"""
        st.markdown("#### 🌐 Top Attack Sources")
        
        source_counts = df['source_ip'].value_counts().head(10)
        
        if len(source_counts) > 0:
            fig = px.bar(
                x=source_counts.values,
                y=source_counts.index,
                orientation='h',
                title="Top 10 Attackers",
                color=source_counts.values,
                color_continuous_scale='Reds',
                labels={'x': 'Number of Attacks', 'y': 'Source IP'}
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            # Show attacker details
            with st.expander("🔍 View Attacker Details"):
                for ip, count in source_counts.head(5).items():
                    st.markdown(f"""
                    <div style="background: rgba(239, 68, 68, 0.1); padding: 0.5rem; border-radius: 0.5rem; margin: 0.25rem 0;">
                        <strong>📍 {ip}</strong><br>
                        Attacks: {count} | Risk Level: {'High' if count > 10 else 'Medium' if count > 5 else 'Low'}
                    </div>
                    """, unsafe_allow_html=True)
    
    def _render_top_targets(self, df: pd.DataFrame):
        """Render top targets chart"""
        st.markdown("#### 🎯 Top Targets")
        
        if 'destination_ip' in df.columns:
            target_counts = df['destination_ip'].value_counts().head(10)
            
            if len(target_counts) > 0:
                fig = px.bar(
                    x=target_counts.values,
                    y=target_counts.index,
                    orientation='h',
                    title="Most Targeted IPs",
                    color=target_counts.values,
                    color_continuous_scale='Oranges',
                    labels={'x': 'Number of Attacks', 'y': 'Target IP'}
                )
                fig.update_layout(height=400)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Destination IP data not available in current alerts")
    
    def _render_time_series_analysis(self, df: pd.DataFrame):
        """Render time series analysis"""
        st.markdown("#### 📅 Time Series Analysis")
        
        # Resample by different intervals
        col1, col2 = st.columns([1, 3])
        
        with col1:
            resample_period = st.selectbox(
                "Time Interval",
                ["Minute", "Hour", "Day", "Week"],
                key="timeseries_interval"
            )
        
        period_map = {
            "Minute": '1min',
            "Hour": '1H',
            "Day": '1D',
            "Week": '1W'
        }
        
        df_sorted = df.sort_values('timestamp')
        df_sorted.set_index('timestamp', inplace=True)
        threat_counts = df_sorted.resample(period_map[resample_period]).size()
        
        if len(threat_counts) > 1:
            # Create DataFrame for plotting
            timeline_df = pd.DataFrame({
                'Time': threat_counts.index,
                'Threats': threat_counts.values
            })
            
            # Line chart
            fig = px.line(
                timeline_df,
                x='Time',
                y='Threats',
                title=f"Threat Frequency ({resample_period} Intervals)",
                markers=True
            )
            fig.update_traces(line=dict(color='#ef4444', width=2), marker=dict(size=6, color='#dc2626'))
            fig.update_layout(
                height=400,
                xaxis_title="Time",
                yaxis_title="Number of Threats",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Peak Threats", f"{threat_counts.max()}")
            with col2:
                st.metric("Average", f"{threat_counts.mean():.1f}")
            with col3:
                st.metric("Total Periods", len(threat_counts))
            with col4:
                busiest_period = threat_counts.idxmax()
                st.metric("Busiest Period", busiest_period.strftime("%Y-%m-%d %H:%M"))
    
    def _render_advanced_analytics(self, df: pd.DataFrame):
        """Render advanced analytics"""
        st.markdown("#### 🔬 Advanced Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Confidence distribution
            st.markdown("##### Confidence Score Distribution")
            fig = px.histogram(
                df, x='confidence', nbins=20,
                title="Detection Confidence",
                color_discrete_sequence=['#10b981']
            )
            fig.update_layout(height=300, xaxis_title="Confidence", yaxis_title="Frequency")
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Hourly attack patterns
            st.markdown("##### Hourly Attack Patterns")
            df['hour'] = df['timestamp'].dt.hour
            hourly_counts = df.groupby('hour').size().reset_index()
            hourly_counts.columns = ['Hour', 'Count']
            
            if len(hourly_counts) > 0:
                fig = px.line(
                    hourly_counts,
                    x='Hour',
                    y='Count',
                    title="Attacks by Hour",
                    markers=True
                )
                fig.update_layout(
                    xaxis_title="Hour of Day (0-23)",
                    yaxis_title="Number of Attacks",
                    height=300
                )
                fig.update_traces(line=dict(color='#f59e0b', width=2))
                st.plotly_chart(fig, use_container_width=True)
        
        # Risk trend
        st.markdown("##### Risk Score Trend")
        df_sorted = df.sort_values('timestamp').copy()
        df_sorted['risk_score'] = df_sorted['attack_type'].apply(
            lambda x: self.attack_mapper.get_severity_score(x)
        )
        
        # Calculate rolling average
        df_sorted['risk_trend'] = df_sorted['risk_score'].rolling(window=10, min_periods=1).mean()
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_sorted['timestamp'],
            y=df_sorted['risk_score'],
            mode='markers',
            name='Individual Risk',
            marker=dict(size=5, color='lightblue', opacity=0.5)
        ))
        fig.add_trace(go.Scatter(
            x=df_sorted['timestamp'],
            y=df_sorted['risk_trend'],
            mode='lines',
            name='Risk Trend (10-period MA)',
            line=dict(color='#ef4444', width=3)
        ))
        fig.update_layout(
            title="Security Risk Evolution",
            xaxis_title="Time",
            yaxis_title="Risk Score (0-10)",
            height=400,
            hovermode='closest'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    def _render_attack_patterns(self, df: pd.DataFrame):
        """Render attack pattern analysis"""
        st.markdown("#### 🕸️ Attack Pattern Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack correlation
            st.markdown("##### Attack Type Correlation")
            
            # Create correlation matrix
            correlation = df.groupby('attack_type').size().sort_values(ascending=False)
            
            if len(correlation) > 0:
                fig = px.bar(
                    x=correlation.values,
                    y=correlation.index,
                    orientation='h',
                    title="Attack Frequency Ranking",
                    color=correlation.values,
                    color_continuous_scale='RdBu',
                    labels={'x': 'Number of Attacks', 'y': 'Attack Type'}
                )
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Protocol distribution
            st.markdown("##### Protocol Distribution")
            if 'protocol' in df.columns:
                protocol_counts = df['protocol'].value_counts()
                
                if len(protocol_counts) > 0:
                    fig = px.pie(
                        values=protocol_counts.values,
                        names=protocol_counts.index,
                        title="Attack Protocols",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    fig.update_layout(height=300)
                    st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Protocol data not available")
        
        # Attack bursts detection
        st.markdown("##### 🚨 Attack Burst Detection")
        
        df_sorted = df.sort_values('timestamp').copy()
        df_sorted['time_diff'] = df_sorted['timestamp'].diff().dt.total_seconds()
        
        # Detect bursts (3+ attacks within 60 seconds)
        bursts = []
        current_burst = []
        
        for idx, row in df_sorted.iterrows():
            if not current_burst:
                current_burst.append(row)
            elif row['timestamp'] - current_burst[-1]['timestamp'] <= timedelta(seconds=60):
                current_burst.append(row)
            else:
                if len(current_burst) >= 3:
                    bursts.append(current_burst)
                current_burst = [row]
        
        if len(current_burst) >= 3:
            bursts.append(current_burst)
        
        if bursts:
            st.warning(f"⚠️ Detected {len(bursts)} attack bursts (3+ attacks within 60 seconds)")
            
            for i, burst in enumerate(bursts[:5], 1):
                start_time = burst[0]['timestamp']
                end_time = burst[-1]['timestamp']
                duration = (end_time - start_time).total_seconds()
                attack_types = [b['attack_type'] for b in burst]
                
                st.markdown(f"""
                <div style="background: rgba(245, 158, 11, 0.1); padding: 0.75rem; border-radius: 0.5rem; margin: 0.5rem 0; border-left: 3px solid #f59e0b;">
                    <strong>🔴 Burst {i}</strong><br>
                    📅 {start_time.strftime('%Y-%m-%d %H:%M:%S')} - {end_time.strftime('%H:%M:%S')}<br>
                    ⏱️ Duration: {duration:.1f} seconds | 🎯 {len(burst)} attacks<br>
                    🎭 Types: {', '.join(set(attack_types))}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No significant attack bursts detected")
