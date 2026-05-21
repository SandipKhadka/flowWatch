# src/reports/auto_reporter.py
from jinja2 import Template
import weasyprint

class AutoReportGenerator:
    """Generate professional HTML/PDF reports"""
    
    def generate_html_report(self, alerts, stats):
        """Generate HTML report with charts"""
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SecureNet AI - Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                         color: white; padding: 30px; border-radius: 10px; }
                .metric { display: inline-block; width: 200px; margin: 20px; 
                         padding: 20px; background: #f3f4f6; border-radius: 10px; }
                .critical { color: #ef4444; }
                .high { color: #f59e0b; }
                table { width: 100%; border-collapse: collapse; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                .chart-container { margin: 20px 0; padding: 20px; background: white; 
                                   border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ SecureNet AI Security Report</h1>
                <p>Generated: {{ date }}</p>
                <p>Analysis Period: {{ period }}</p>
            </div>
            
            <div style="text-align: center; margin: 40px 0;">
                <div class="metric">
                    <h3>Total Attacks</h3>
                    <h2>{{ total_attacks }}</h2>
                </div>
                <div class="metric">
                    <h3>Unique Attackers</h3>
                    <h2>{{ unique_attackers }}</h2>
                </div>
                <div class="metric">
                    <h3>Risk Score</h3>
                    <h2 class="critical">{{ risk_score }}/10</h2>
                </div>
                <div class="metric">
                    <h3>Detection Rate</h3>
                    <h2>{{ detection_rate }}%</h2>
                </div>
            </div>
            
            <div class="chart-container">
                <h3>Attack Distribution</h3>
                <img src="attack_chart.png" width="100%">
            </div>
            
            <div class="chart-container">
                <h3>Top Attackers</h3>
                <table>
                    <tr><th>Source IP</th><th>Attack Count</th><th>Risk Level</th></tr>
                    {% for attacker in top_attackers %}
                    <tr>
                        <td>{{ attacker.ip }}</td>
                        <td>{{ attacker.count }}</td>
                        <td class="{{ attacker.risk|lower }}">{{ attacker.risk }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div style="margin-top: 40px; text-align: center; color: #666;">
                <p>SecureNet AI - Advanced Intrusion Detection System</p>
                <p>This report is automatically generated and timestamped for audit purposes</p>
            </div>
        </body>
        </html>
        """)
        
        html_content = template.render(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            period="Last 24 Hours",
            total_attacks=len(alerts),
            unique_attackers=len(set(a['source_ip'] for a in alerts)),
            risk_score=AttackMapper.calculate_risk_score(alerts),
            detection_rate=stats.get('detection_rate', 0),
            top_attackers=self.get_top_attackers(alerts)
        )
        
        # Save HTML
        filename = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
