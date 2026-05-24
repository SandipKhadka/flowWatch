"""
Reusable chart components with Plotly
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass


@dataclass
class ChartTheme:
    """Chart theme configuration"""
    colors: List[str] = None
    background_color: str = "rgba(0,0,0,0)"
    grid_color: str = "rgba(255,255,255,0.1)"
    font_color: str = "white"
    
    def __post_init__(self):
        if self.colors is None:
            self.colors = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6']


class ChartRenderer:
    """Render various chart types with consistent styling"""
    
    def __init__(self, theme: Optional[ChartTheme] = None):
        self.theme = theme or ChartTheme()
    
    def pie_chart(self, data: pd.Series, title: str, height: int = 400, 
                  hole: float = 0.3) -> None:
        """Render a pie chart"""
        if data.empty:
            st.info(f"No data available for {title}")
            return
        
        fig = px.pie(
            values=data.values,
            names=data.index,
            title=title,
            color_discrete_sequence=self.theme.colors,
            hole=hole
        )
        self._apply_layout(fig, height)
        st.plotly_chart(fig, use_container_width=True)
    
    def bar_chart(self, data: pd.Series, title: str, x_label: str = "", 
                  y_label: str = "", orientation: str = 'h', 
                  height: int = 400) -> None:
        """Render a bar chart"""
        if data.empty:
            st.info(f"No data available for {title}")
            return
        
        if orientation == 'h':
            fig = px.bar(
                x=data.values,
                y=data.index,
                orientation='h',
                title=title,
                color=data.values,
                color_continuous_scale='Reds',
                labels={'x': x_label, 'y': y_label}
            )
        else:
            fig = px.bar(
                x=data.index,
                y=data.values,
                title=title,
                color=data.values,
                color_continuous_scale='Reds',
                labels={'x': x_label, 'y': y_label}
            )
        
        self._apply_layout(fig, height)
        st.plotly_chart(fig, use_container_width=True)
    
    def line_chart(self, df: pd.DataFrame, x: str, y: str, title: str,
                   height: int = 400) -> None:
        """Render a line chart"""
        if df.empty:
            st.info(f"No data available for {title}")
            return
        
        fig = px.line(
            df, x=x, y=y,
            title=title,
            color_discrete_sequence=self.theme.colors
        )
        self._apply_layout(fig, height)
        st.plotly_chart(fig, use_container_width=True)
    
    def gauge_chart(self, value: float, title: str, min_val: float = 0,
                    max_val: float = 10, height: int = 300) -> None:
        """Render a gauge chart"""
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=value,
            title={"text": title, "font": {"size": 20}},
            delta={"reference": max_val/2},
            gauge={
                "axis": {"range": [min_val, max_val]},
                "bar": {"color": self._get_gauge_color(value, max_val)},
                "steps": [
                    {"range": [0, max_val*0.3], "color": "lightgreen"},
                    {"range": [max_val*0.3, max_val*0.6], "color": "yellow"},
                    {"range": [max_val*0.6, max_val*0.8], "color": "orange"},
                    {"range": [max_val*0.8, max_val], "color": "red"}
                ]
            }
        ))
        fig.update_layout(height=height, paper_bgcolor=self.theme.background_color)
        st.plotly_chart(fig, use_container_width=True)
    
    def histogram(self, data: pd.Series, title: str, nbins: int = 20,
                  height: int = 400) -> None:
        """Render a histogram"""
        if data.empty:
            st.info(f"No data available for {title}")
            return
        
        fig = px.histogram(
            data, nbins=nbins, title=title,
            color_discrete_sequence=['#10b981']
        )
        self._apply_layout(fig, height)
        st.plotly_chart(fig, use_container_width=True)
    
    def _apply_layout(self, fig, height: int):
        """Apply consistent layout styling"""
        fig.update_layout(
            height=height,
            paper_bgcolor=self.theme.background_color,
            plot_bgcolor=self.theme.background_color,
            font_color=self.theme.font_color,
            title_font_color=self.theme.font_color,
            xaxis=dict(gridcolor=self.theme.grid_color),
            yaxis=dict(gridcolor=self.theme.grid_color)
        )
    
    def _get_gauge_color(self, value: float, max_val: float) -> str:
        """Get color based on value"""
        ratio = value / max_val
        if ratio < 0.3:
            return "#10b981"
        elif ratio < 0.6:
            return "#f59e0b"
        elif ratio < 0.8:
            return "#f97316"
        return "#ef4444"


# Global chart renderer instance
chart_renderer = ChartRenderer()
