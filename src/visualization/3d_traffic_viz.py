import plotly.graph_objects as go
import numpy as np
from datetime import datetime

class TrafficVisualizer3D:
    """3D visualization of network traffic patterns"""
    
    def create_3d_attack_landscape(self, alerts):
        """Create 3D landscape of attacks"""
        if not alerts:
            return go.Figure()
        
        # Prepare data
        times = [datetime.strptime(a['timestamp'], '%Y-%m-%d %H:%M:%S') for a in alerts]
        severities = [AttackMapper.get_severity_score(a['attack_type']) for a in alerts]
        confidences = [a['confidence'] for a in alerts]
        
        fig = go.Figure(data=[
            go.Scatter3d(
                x=times,
                y=severities,
                z=confidences,
                mode='markers',
                marker=dict(
                    size=10,
                    color=severities,
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title="Severity")
                ),
                text=[f"{a['attack_type']}<br>{a['source_ip']}" for a in alerts],
                hoverinfo='text'
            )
        ])
        
        fig.update_layout(
            title="3D Attack Landscape",
            scene=dict(
                xaxis_title="Time",
                yaxis_title="Severity",
                zaxis_title="Confidence",
                camera=dict(eye=dict(x=1.5, y=1.5, z=1.5))
            ),
            height=600
        )
        return fig
    
    def create_network_topology(self, connections):
        """Create interactive network topology graph"""
        import networkx as nx
        
        G = nx.Graph()
        
        # Add nodes and edges
        for conn in connections:
            G.add_edge(conn['src'], conn['dst'], weight=conn['packets'])
        
        # Create 3D positions
        pos = nx.spring_layout(G, dim=3, seed=42)
        
        # Extract node coordinates
        x_nodes = [pos[node][0] for node in G.nodes()]
        y_nodes = [pos[node][1] for node in G.nodes()]
        z_nodes = [pos[node][2] for node in G.nodes()]
        
        # Create edge traces
        edge_traces = []
        for edge in G.edges():
            x0, y0, z0 = pos[edge[0]]
            x1, y1, z1 = pos[edge[1]]
            edge_traces.append(go.Scatter3d(
                x=[x0, x1, None],
                y=[y0, y1, None],
                z=[z0, z1, None],
                mode='lines',
                line=dict(color='gray', width=1),
                hoverinfo='none'
            ))
        
        # Node trace
        node_trace = go.Scatter3d(
            x=x_nodes, y=y_nodes, z=z_nodes,
            mode='markers+text',
            marker=dict(size=10, color='lightblue'),
            text=list(G.nodes()),
            textposition="top center"
        )
        
        fig = go.Figure(data=[*edge_traces, node_trace])
        fig.update_layout(title="Network Topology Map", height=600)
        return fig
