# src/analysis/benchmark.py
import time
import psutil
from collections import deque

class PerformanceBenchmark:
    """Benchmark IDS performance metrics"""
    
    def __init__(self):
        self.latency_metrics = deque(maxlen=1000)
        self.throughput_metrics = deque(maxlen=100)
        self.resource_usage = []
    
    def measure_latency(self, func):
        """Decorator to measure function latency"""
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            latency = (time.perf_counter() - start) * 1000  # ms
            self.latency_metrics.append(latency)
            return result
        return wrapper
    
    def get_performance_report(self):
        """Generate performance report"""
        report = {
            'avg_latency_ms': np.mean(self.latency_metrics) if self.latency_metrics else 0,
            'p95_latency_ms': np.percentile(self.latency_metrics, 95) if self.latency_metrics else 0,
            'p99_latency_ms': np.percentile(self.latency_metrics, 99) if self.latency_metrics else 0,
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent,
            'packet_throughput': self.throughput_metrics[-1] if self.throughput_metrics else 0
        }
        
        # Create performance dashboard
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Latency Distribution', 'CPU/Memory Usage', 'Throughput', 'Response Time Trend')
        )
        
        # Latency histogram
        fig.add_trace(
            go.Histogram(x=list(self.latency_metrics), nbinsx=20, name='Latency'),
            row=1, col=1
        )
        
        # Resource usage gauge
        fig.add_trace(
            go.Indicator(mode="gauge+number", value=report['cpu_usage'], title="CPU Usage"),
            row=1, col=2
        )
        
        fig.update_layout(height=600, title_text="IDS Performance Dashboard")
        return fig, report
