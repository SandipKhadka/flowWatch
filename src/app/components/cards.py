"""
Reusable card components
"""

import streamlit as st
from typing import Dict, Any, Optional, Callable
from enum import Enum


class CardStyle(Enum):
    """Card style types"""
    PRIMARY = "primary"
    SUCCESS = "success"
    WARNING = "warning"
    DANGER = "danger"
    INFO = "info"


class MetricCard:
    """Reusable metric card component"""
    
    STYLE_COLORS = {
        CardStyle.PRIMARY: ("#667eea", "#764ba2"),
        CardStyle.SUCCESS: ("#10b981", "#059669"),
        CardStyle.WARNING: ("#f59e0b", "#d97706"),
        CardStyle.DANGER: ("#ef4444", "#dc2626"),
        CardStyle.INFO: ("#3b82f6", "#2563eb")
    }
    
    @classmethod
    def render(cls, title: str, value: str, delta: Optional[str] = None, 
               style: CardStyle = CardStyle.PRIMARY, **kwargs):
        """Render a metric card"""
        primary, secondary = cls.STYLE_COLORS[style]
        
        st.markdown(f"""
        <div style="
            background: linear-gradient(135deg, {primary} 0%, {secondary} 100%);
            border-radius: 1rem;
            padding: 1.5rem;
            color: white;
            text-align: center;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
        ">
            <h4 style="margin: 0 0 0.5rem 0; font-size: 0.9rem; opacity: 0.9;">{title}</h4>
            <h2 style="margin: 0; font-size: 2rem; font-weight: bold;">{value}</h2>
            {f'<div style="font-size: 0.8rem; margin-top: 0.5rem; opacity: 0.8;">{delta}</div>' if delta else ''}
        </div>
        """, unsafe_allow_html=True)


class AlertCard:
    """Alert card component for displaying threats"""
    
    @classmethod
    def render(cls, alert: Dict, on_click: Optional[Callable] = None):
        """Render an alert card"""
        severity = cls._get_severity_level(alert)
        
        styles = {
            "critical": {"icon": "🔴", "bg": "linear-gradient(135deg, #dc2626, #991b1b)", "border": "#ff0000"},
            "high": {"icon": "🟠", "bg": "linear-gradient(135deg, #f59e0b, #d97706)", "border": "#ff6600"},
            "medium": {"icon": "🟡", "bg": "linear-gradient(135deg, #eab308, #ca8a04)", "border": "#ffcc00"},
        }
        
        style = styles.get(severity, styles["high"])
        
        confidence = alert.get('confidence', 0.85)
        attack_type = alert['attack_type'].upper()
        source_ip = alert['source_ip']
        timestamp = alert.get('timestamp', '')
        severity_level = alert.get('severity_level', 'HIGH')
        
        st.markdown(f"""
        <div style="
            background: {style['bg']};
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
            color: white;
            border-left: 5px solid {style['border']};
            transition: transform 0.2s ease;
        ">
            <strong>{style['icon']} {severity_level}</strong> - {attack_type}<br>
            📍 {source_ip}<br>
            ⏰ {timestamp[:19] if timestamp else 'N/A'}<br>
            🎯 {confidence*100:.0f}% confidence | Severity: {alert.get('severity', 5)}/10
        </div>
        """, unsafe_allow_html=True)
    
    @staticmethod
    def _get_severity_level(alert: Dict) -> str:
        """Determine severity level from alert"""
        severity = alert.get('severity', 5)
        if severity >= 8:
            return "critical"
        elif severity >= 5:
            return "high"
        return "medium"


class InfoCard:
    """Information card component"""
    
    @classmethod
    def render(cls, title: str, content: str, icon: str = "ℹ️"):
        """Render an info card"""
        st.markdown(f"""
        <div style="
            background: rgba(31, 41, 55, 0.7);
            backdrop-filter: blur(10px);
            padding: 1rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
            border: 1px solid rgba(255,255,255,0.1);
        ">
            <strong>{icon} {title}</strong><br>
            {content}
        </div>
        """, unsafe_allow_html=True)
