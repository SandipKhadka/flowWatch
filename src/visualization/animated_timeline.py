# src/visualization/animated_timeline.py
import plotly.express as px
from datetime import timedelta

class AnimatedThreatTimeline:
    """Animated timeline showing threat evolution"""
    
    def create_animated_timeline(self, alerts):
        """Create animated bubble chart over time"""
        if not alerts:
            return go.Figure()
        
        df = pd.DataFrame(alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['severity'] = df['attack_type'].apply(AttackMapper.get_severity_score)
        
        fig = px.scatter(
            df,
            x='timestamp',
            y='severity',
            size='confidence',
            color='attack_type',
            animation_frame=df['timestamp'].dt.strftime('%H:%M'),
            hover_data=['source_ip'],
            title="Animated Threat Evolution",
            range_y=[0, 10],
            size_max=30
        )
        
        fig.update_layout(height=500)
        return fig
    
    def create_heatmap_animation(self, alerts):
        """Animated heatmap of attack patterns"""
        if not alerts:
            return go.Figure()
        
        df = pd.DataFrame(alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.dayofweek
        
        # Create frames for animation
        frames = []
        for hour in range(24):
            hour_df = df[df['hour'] == hour]
            heatmap_data = pd.crosstab(hour_df['day'], hour_df['attack_type'])
            
            frames.append(go.Frame(
                data=[go.Heatmap(z=heatmap_data.values, x=heatmap_data.columns, y=heatmap_data.index)],
                name=str(hour)
            ))
        
        fig = go.Figure(
            data=frames[0].data,
            frames=frames,
            layout=go.Layout(
                title="Attack Pattern Heatmap Animation",
                updatemenus=[dict(type="buttons", buttons=[dict(label="Play", method="animate", args=[None])])],
                sliders=[dict(steps=[dict(method="animate", label=str(i), args=[[str(i)]]) for i in range(24)])]
            )
        )
        
        return fig
