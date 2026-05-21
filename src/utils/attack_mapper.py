# src/utils/attack_mapper.py
def get_attack_category(attack_label: str) -> str:
    attack = str(attack_label).lower()
    
    dos = ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'processtable']
    probe = ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint']
    r2l = ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'warezmaster']
    u2r = ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel']
    
    if attack == 'normal':
        return "Normal"
    elif attack in dos:
        return "DoS"
    elif attack in probe:
        return "Probe"
    elif attack in r2l:
        return "R2L"
    elif attack in u2r:
        return "U2R"
    else:
        return "Unknown"
