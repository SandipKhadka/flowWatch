"""
Threat Intelligence Page - MITRE ATT&CK mapping and threat analysis
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from ..session_state import session
from ..components import MetricCard, CardStyle, InfoCard
from ...utils.attack_mapper import AttackMapper


class ThreatIntelPage:
    """Threat intelligence page with MITRE ATT&CK framework"""
    
    # MITRE ATT&CK Mapping
    MITRE_MAPPING = {
        "ddos": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": "Adversaries may perform Network Denial of Service attacks to degrade or block availability",
            "mitigation": "Network segmentation, rate limiting, DDoS protection services"
        },
        "dos": {
            "technique_id": "T1498",
            "technique_name": "Network Denial of Service",
            "tactic": "Impact",
            "description": "Denial of Service attacks targeting service availability",
            "mitigation": "Load balancing, rate limiting, auto-scaling"
        },
        "port_scan": {
            "technique_id": "T1040",
            "technique_name": "Network Sniffing",
            "tactic": "Discovery",
            "description": "Scanning networks to discover active hosts and services",
            "mitigation": "Network segmentation, port knocking, IDS/IPS"
        },
        "nmap": {
            "technique_id": "T1046",
            "technique_name": "Network Service Scanning",
            "tactic": "Discovery",
            "description": "Using nmap to discover network services and vulnerabilities",
            "mitigation": "Port security, firewall rules, intrusion detection"
        },
        "brute_force": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Attempting to gain access through password guessing",
            "mitigation": "Strong password policies, MFA, account lockout"
        },
        "web_attack": {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Exploiting vulnerabilities in web applications",
            "mitigation": "WAF, input validation, regular patching"
        },
        "sqli": {
            "technique_id": "T1190",
            "technique_name": "SQL Injection",
            "tactic": "Initial Access",
            "description": "Injecting malicious SQL queries to manipulate databases",
            "mitigation": "Parameterized queries, input validation, WAF"
        },
        "infiltration": {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Using application layer protocols for C2 communication",
            "mitigation": "Network monitoring, traffic analysis, allowlisting"
        },
        "botnet": {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Botnet communication for coordinated attacks",
            "mitigation": "DNS filtering, network monitoring, threat intelligence"
        },
        "r2l": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Privilege Escalation",
            "description": "Remote to local privilege escalation",
            "mitigation": "Least privilege principle, regular audits"
        },
        "u2r": {
            "technique_id": "T1068",
            "technique_name": "Exploitation for Privilege Escalation",
            "tactic": "Privilege Escalation",
            "description": "User to root privilege escalation",
            "mitigation": "System hardening, regular patching, SELinux"
        }
    }
    
    def __init__(self):
        self.attack_mapper = AttackMapper()
    
    def render(self):
        """Render the threat intelligence page"""
        st.markdown("## 🗺️ Threat Intelligence & MITRE ATT&CK")
        st.caption("Advanced threat analysis using MITRE ATT&CK framework")
        
        alerts = session.get('alerts', [])
        
        # MITRE Overview
        self._render_mitre_overview()
        
        st.markdown("---")
        
        if alerts:
            # Current threats analysis
            self._render_current_threats_analysis(alerts)
            
            st.markdown("---")
            
            # MITRE Matrix
            self._render_mitre_matrix(alerts)
            
            st.markdown("---")
            
            # Threat intelligence feed
            self._render_threat_intel_feed(alerts)
            
            st.markdown("---")
            
            # Recommendations
            self._render_security_recommendations(alerts)
        else:
            self._render_empty_state()
    
    def _render_mitre_overview(self):
        """Render MITRE ATT&CK overview"""
        st.markdown("### 🎯 MITRE ATT&CK Framework")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            InfoCard.render(
                "What is MITRE ATT&CK?",
                "A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.",
                "📚"
            )
        
        with col2:
            InfoCard.render(
                "Tactics",
                "14 tactical objectives representing the 'why' of an attack technique (e.g., Initial Access, Discovery).",
                "🎯"
            )
        
        with col3:
            InfoCard.render(
                "Techniques",
                "Specific methods used to achieve tactical objectives, representing the 'how' of an attack.",
                "🔧"
            )
    
    def _render_current_threats_analysis(self, alerts: list):
        """Render current threats with MITRE mapping"""
        st.markdown("### 🔍 Current Threat Analysis")
        
        # Create threat summary
        threat_summary = {}
        for alert in alerts:
            attack_type = alert['attack_type'].lower()
            if attack_type in self.MITRE_MAPPING:
                if attack_type not in threat_summary:
                    threat_summary[attack_type] = {
                        'count': 0,
                        'confidence': [],
                        'severity': []
                    }
                threat_summary[attack_type]['count'] += 1
                threat_summary[attack_type]['confidence'].append(alert.get('confidence', 0))
                threat_summary[attack_type]['severity'].append(alert.get('severity', 0))
        
        if threat_summary:
            # Display threat summary table
            summary_data = []
            for attack, data in threat_summary.items():
                mitre = self.MITRE_MAPPING.get(attack, {})
                summary_data.append({
                    'Attack Type': attack.upper(),
                    'Count': data['count'],
                    'Avg Confidence': f"{sum(data['confidence'])/len(data['confidence'])*100:.1f}%",
                    'Avg Severity': f"{sum(data['severity'])/len(data['severity']):.1f}/10",
                    'MITRE ID': mitre.get('technique_id', 'N/A'),
                    'Tactic': mitre.get('tactic', 'N/A')
                })
            
            df_summary = pd.DataFrame(summary_data)
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
            
            # Top threats visualization
            st.markdown("#### Top Threats by MITRE Tactic")
            tactic_counts = {}
            for attack, data in threat_summary.items():
                tactic = self.MITRE_MAPPING.get(attack, {}).get('tactic', 'Unknown')
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + data['count']
            
            if tactic_counts:
                fig = go.Figure(data=[go.Pie(
                    labels=list(tactic_counts.keys()),
                    values=list(tactic_counts.values()),
                    hole=0.3,
                    marker_colors=['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6']
                )])
                fig.update_layout(title="Threats by MITRE Tactic", height=400)
                st.plotly_chart(fig, use_container_width=True)
    
    def _render_mitre_matrix(self, alerts: list):
        """Render MITRE ATT&CK Matrix"""
        st.markdown("### 🎯 MITRE ATT&CK Matrix")
        st.caption("Detected threats mapped to MITRE ATT&CK framework")
        
        # Define tactics in order
        tactics = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]
        
        # Create matrix data
        matrix_data = {tactic: [] for tactic in tactics}
        
        for alert in alerts:
            attack_type = alert['attack_type'].lower()
            if attack_type in self.MITRE_MAPPING:
                mitre = self.MITRE_MAPPING[attack_type]
                tactic = mitre['tactic']
                if tactic in matrix_data:
                    technique_info = f"{mitre['technique_id']}: {mitre['technique_name']}"
                    if technique_info not in matrix_data[tactic]:
                        matrix_data[tactic].append(technique_info)
        
        # Display matrix
        for tactic in tactics:
            if matrix_data[tactic]:
                with st.expander(f"🔴 {tactic} ({len(matrix_data[tactic])} techniques detected)"):
                    for technique in matrix_data[tactic]:
                        st.markdown(f"""
                        <div style="background: rgba(239, 68, 68, 0.1); padding: 0.5rem; border-radius: 0.5rem; margin: 0.25rem 0;">
                            <strong>{technique}</strong>
                        </div>
                        """, unsafe_allow_html=True)
    
    def _render_threat_intel_feed(self, alerts: list):
        """Render threat intelligence feed"""
        st.markdown("### 🌐 Threat Intelligence Feed")
        
        # Get unique attackers
        unique_attackers = set()
        attacker_details = {}
        
        for alert in alerts:
            src_ip = alert['source_ip']
            if src_ip not in unique_attackers:
                unique_attackers.add(src_ip)
                attacker_details[src_ip] = {
                    'attack_count': 0,
                    'attack_types': set(),
                    'severity': []
                }
            attacker_details[src_ip]['attack_count'] += 1
            attacker_details[src_ip]['attack_types'].add(alert['attack_type'])
            attacker_details[src_ip]['severity'].append(alert.get('severity', 0))
        
        # Display top attackers with threat intelligence
        st.markdown("#### Top Threat Actors")
        
        for ip, details in sorted(attacker_details.items(), key=lambda x: x[1]['attack_count'], reverse=True)[:10]:
            avg_severity = sum(details['severity']) / len(details['severity'])
            threat_level = "Critical" if avg_severity >= 8 else "High" if avg_severity >= 5 else "Medium"
            threat_color = "#ef4444" if avg_severity >= 8 else "#f59e0b" if avg_severity >= 5 else "#eab308"
            
            st.markdown(f"""
            <div style="background: rgba(31, 41, 55, 0.7); padding: 1rem; border-radius: 0.5rem; margin: 0.5rem 0; border-left: 4px solid {threat_color};">
                <strong>📍 {ip}</strong>
                <span style="float: right; color: {threat_color};">{threat_level}</span><br>
                🎯 Attacks: {details['attack_count']} | 🎭 Types: {', '.join(list(details['attack_types'])[:3])}<br>
                ⚠️ Average Severity: {avg_severity:.1f}/10
            </div>
            """, unsafe_allow_html=True)
    
    def _render_security_recommendations(self, alerts: list):
        """Render security recommendations based on detected threats"""
        st.markdown("### 🛡️ Security Recommendations")
        
        # Analyze threat patterns
        recommendations = []
        
        attack_types = set([alert['attack_type'].lower() for alert in alerts])
        
        for attack in attack_types:
            if attack in self.MITRE_MAPPING:
                mitre = self.MITRE_MAPPING[attack]
                recommendations.append({
                    'attack': attack.upper(),
                    'mitigation': mitre['mitigation'],
                    'priority': 'High' if mitre['tactic'] in ['Initial Access', 'Privilege Escalation'] else 'Medium'
                })
        
        if recommendations:
            for rec in recommendations[:10]:
                priority_color = "#ef4444" if rec['priority'] == 'High' else "#f59e0b"
                st.markdown(f"""
                <div style="background: rgba(16, 185, 129, 0.1); padding: 0.75rem; border-radius: 0.5rem; margin: 0.5rem 0; border-left: 3px solid {priority_color};">
                    <strong>🎯 {rec['attack']}</strong>
                    <span style="float: right; color: {priority_color};">Priority: {rec['priority']}</span><br>
                    📋 <strong>Mitigation:</strong> {rec['mitigation']}
                </div>
                """, unsafe_allow_html=True)
    
    def _render_empty_state(self):
        """Render empty state"""
        st.info("🌐 No threat data available. Start monitoring to see threat intelligence.")
        st.markdown("""
        ### 🔍 Threat Intelligence Features:
        
        - **MITRE ATT&CK Mapping** - Map detected threats to MITRE framework
        - **Tactic Analysis** - Understand attacker objectives
        - **Technique Details** - Learn about specific attack methods
        - **Threat Actor Tracking** - Monitor attacker behavior patterns
        - **Security Recommendations** - Get actionable mitigation strategies
        """)
