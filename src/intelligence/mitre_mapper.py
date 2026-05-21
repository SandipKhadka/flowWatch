# src/intelligence/mitre_mapper.py
class MitreAttackMapper:
    """Map detected attacks to MITRE ATT&CK framework"""
    
    MITRE_MATRIX = {
        'Reconnaissance': {
            'techniques': ['T1040', 'T1046', 'T1595'],
            'tactics': ['Discovery'],
            'attacks': ['nmap', 'portsweep', 'ipsweep']
        },
        'Initial Access': {
            'techniques': ['T1078', 'T1133', 'T1190'],
            'tactics': ['Initial Access'],
            'attacks': ['ftp_write', 'guess_passwd', 'imap']
        },
        'Execution': {
            'techniques': ['T1059', 'T1204', 'T1569'],
            'tactics': ['Execution'],
            'attacks': ['buffer_overflow', 'loadmodule', 'perl']
        },
        'Persistence': {
            'techniques': ['T1098', 'T1136', 'T1547'],
            'tactics': ['Persistence'],
            'attacks': ['rootkit', 'xlock', 'xsnoop']
        },
        'Defense Evasion': {
            'techniques': ['T1070', 'T1222', 'T1564'],
            'tactics': ['Defense Evasion'],
            'attacks': ['httptunnel', 'sqlattack']
        },
        'Impact': {
            'techniques': ['T1485', 'T1486', 'T1498'],
            'tactics': ['Impact'],
            'attacks': ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop']
        }
    }
    
    @classmethod
    def map_attack(cls, attack_type):
        """Map attack to MITRE ATT&CK"""
        for category, info in cls.MITRE_MATRIX.items():
            if attack_type.lower() in info['attacks']:
                return {
                    'category': category,
                    'technique_ids': info['techniques'],
                    'tactics': info['tactics'],
                    'url': f"https://attack.mitre.org/techniques/{info['techniques'][0]}"
                }
        return {'category': 'Unknown', 'technique_ids': [], 'tactics': []}
    
    @classmethod
    def generate_attack_matrix(cls, alerts):
        """Generate MITRE ATT&CK matrix visualization"""
        matrix_data = {category: 0 for category in cls.MITRE_MATRIX.keys()}
        
        for alert in alerts:
            mapping = cls.map_attack(alert['attack_type'])
            if mapping['category'] in matrix_data:
                matrix_data[mapping['category']] += 1
        
        # Create heatmap
        fig = px.imshow(
            [list(matrix_data.values())],
            x=list(matrix_data.keys()),
            y=['Your IDS'],
            title="MITRE ATT&CK Coverage Matrix",
            color_continuous_scale="Reds",
            aspect="auto",
            height=300
        )
        
        fig.update_layout(
            xaxis={'tickangle': 45},
            yaxis={'visible': False}
        )
        
        return fig
