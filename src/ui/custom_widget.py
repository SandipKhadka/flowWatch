# src/ui/custom_widgets.py
import streamlit as st
from datetime import datetime
import pandas as pd

class CustomDashboardWidgets:
    """Custom Streamlit widgets for better UI"""
    
    @staticmethod
    def threat_gauge(risk_score):
        """Custom threat gauge widget"""
        color = "#10b981" if risk_score < 3 else "#f59e0b" if risk_score < 7 else "#ef4444"
        
        st.markdown(f"""
        <div style="text-align: center; padding: 1rem;">
            <div style="position: relative; width: 200px; height: 100px; margin: 0 auto;">
                <svg width="200" height="100" viewBox="0 0 200 100">
                    <path d="M10,90 A80,80 0 0,1 190,90" fill="none" stroke="#e5e7eb" stroke-width="15"/>
                    <path d="M10,90 A80,80 0 0,1 190,90" fill="none" stroke="{color}" stroke-width="15"
                          stroke-dasharray="{risk_score * 50.24} 502.4"/>
                    <text x="100" y="85" text-anchor="middle" font-size="24" font-weight="bold" fill="{color}">
                        {risk_score}/10
                    </text>
                </svg>
            </div>
            <p style="color: {color}; font-weight: bold;">Current Risk Level</p>
        </div>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def attack_clock(alerts):
        """24-hour attack clock visualization"""
        if not alerts:
            return
        
        df = pd.DataFrame(alerts)
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        hour_counts = df.groupby('hour').size().reindex(range(24), fill_value=0)
        
        fig = go.Figure()
        
        # Add bars in a circular layout
        theta = [f"{h:02d}:00" for h in range(24)]
        
        fig.add_trace(go.Barpolar(
            r=hour_counts.values,
            theta=theta,
            marker_color=hour_counts.values,
            marker_colorscale='Reds',
            name='Attacks per Hour'
        ))
        
        fig.update_layout(
            title="24-Hour Attack Clock",
            polar=dict(
                angularaxis=dict(rotation=90, direction="clockwise"),
                radialaxis=dict(showticklabels=True, ticks='')
            ),
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)
