# src/utils/report_generator.py
from fpdf import FPDF
from datetime import datetime
import os

class ReportGenerator:
    def generate_report(self, alerts, total_packets, threats_detected):
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SecureNet AI - Intrusion Detection Report", ln=True, align="C")
        pdf.ln(10)
        
        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 10, f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.cell(0, 10, f"Total Packets Analyzed: {total_packets}", ln=True)
        pdf.cell(0, 10, f"Total Threats Detected: {threats_detected}", ln=True)
        pdf.ln(15)
        
        # Alerts Table
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Recent Detection Alerts:", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", "", 10)
        for alert in alerts[-15:]:   # Last 15 alerts
            line = f"{alert['timestamp']} | {alert['source_ip']} | {alert['attack_type']} | Confidence: {alert['confidence']}"
            pdf.cell(0, 8, line, ln=True)
        
        # Save report
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/IDS_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(filename)
        
        return filename
