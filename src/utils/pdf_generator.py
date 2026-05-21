# src/export/pdf_exporter.py
from fpdf import FPDF
import pandas as pd
from datetime import datetime
import os

class PDFExporter:
    """Generate PDF reports from alerts"""
    
    def __init__(self):
        self.pdf = None
    
    def export_alerts_to_pdf(self, alerts_df, filename=None):
        """Export filtered alerts to PDF"""
        
        if filename is None:
            filename = f"reports/alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "FlowWatch AI - Security Report", ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.cell(0, 8, f"Total Records: {len(alerts_df)}", ln=True, align="C")
        pdf.ln(10)
        
        # Summary statistics
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Summary Statistics", ln=True)
        pdf.set_font("Arial", "", 10)
        
        if not alerts_df.empty:
            # Attack type summary
            attack_counts = alerts_df['attack_type'].value_counts()
            pdf.cell(0, 8, f"Attack Types Detected: {len(attack_counts)}", ln=True)
            for attack, count in attack_counts.head(5).items():
                pdf.cell(0, 6, f"  - {attack.upper()}: {count} attacks", ln=True)
            
            pdf.ln(5)
            
            # Top attackers
            top_attackers = alerts_df['source_ip'].value_counts().head(5)
            pdf.cell(0, 8, f"Top Attackers:", ln=True)
            for ip, count in top_attackers.items():
                pdf.cell(0, 6, f"  - {ip}: {count} attacks", ln=True)
            
            pdf.ln(5)
            
            # Confidence stats
            avg_confidence = alerts_df['confidence'].mean() * 100
            pdf.cell(0, 8, f"Average Confidence: {avg_confidence:.1f}%", ln=True)
        
        pdf.ln(10)
        
        # Alerts table header
        pdf.set_font("Arial", "B", 10)
        pdf.cell(50, 8, "Timestamp", 1)
        pdf.cell(40, 8, "Source IP", 1)
        pdf.cell(40, 8, "Attack Type", 1)
        pdf.cell(30, 8, "Confidence", 1)
        pdf.cell(30, 8, "Severity", 1)
        pdf.ln()
        
        # Alerts table body
        pdf.set_font("Arial", "", 9)
        for _, row in alerts_df.head(50).iterrows():
            pdf.cell(50, 7, str(row['timestamp'])[:19], 1)
            pdf.cell(40, 7, str(row['source_ip']), 1)
            pdf.cell(40, 7, str(row['attack_type']).upper(), 1)
            pdf.cell(30, 7, f"{row['confidence']*100:.1f}%", 1)
            severity = row.get('severity', 5)
            pdf.cell(30, 7, f"{severity}/10", 1)
            pdf.ln()
        
        # Footer
        pdf.set_y(-20)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, "FlowWatch AI - Advanced Intrusion Detection System", ln=True, align="C")
        
        # Save PDF
        pdf.output(filename)
        
        return filename

    def export_filtered_report(self, alerts_df, filters_applied):
        """Export filtered report with applied filters"""
        
        filename = f"reports/filtered_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        os.makedirs("reports", exist_ok=True)
        
        pdf = FPDF()
        pdf.add_page()
        
        # Title
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "FlowWatch AI - Filtered Security Report", ln=True, align="C")
        pdf.ln(5)
        
        # Filters applied
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Filters Applied:", ln=True)
        pdf.set_font("Arial", "", 10)
        for key, value in filters_applied.items():
            if value:
                pdf.cell(0, 6, f"  • {key}: {value}", ln=True)
        
        pdf.ln(10)
        
        # Add the same content as above
        # ... (rest of the PDF generation)
        
        return filename
