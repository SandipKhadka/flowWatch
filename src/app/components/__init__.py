"""
UI Components module
"""

from .cards import MetricCard, AlertCard, InfoCard, CardStyle
from .sidebar import SidebarRenderer

# Simple chart functions
def render_pie_chart(data, title, height=400):
    """Simple pie chart renderer"""
    import streamlit as st
    import plotly.express as px
    
    if data.empty:
        st.info(f"No data available for {title}")
        return
    
    fig = px.pie(
        values=data.values,
        names=data.index,
        title=title,
        color_discrete_sequence=['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6'],
        hole=0.3
    )
    fig.update_layout(height=height)
    st.plotly_chart(fig, use_container_width=True)


def render_bar_chart(data, title, height=400):
    """Simple bar chart renderer"""
    import streamlit as st
    import plotly.express as px
    
    if data.empty:
        st.info(f"No data available for {title}")
        return
    
    fig = px.bar(
        x=data.values,
        y=data.index,
        orientation='h',
        title=title,
        color=data.values,
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=height)
    st.plotly_chart(fig, use_container_width=True)


__all__ = [
    'MetricCard',
    'AlertCard', 
    'InfoCard',
    'CardStyle',
    'SidebarRenderer',
    'render_pie_chart',
    'render_bar_chart'
]
