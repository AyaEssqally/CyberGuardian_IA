import os
from typing import List, Dict, Tuple

# Enhanced scan configuration with new options
DEFAULT_SCAN_OPTIONS = {
    'quick': '-T4 -F',  # Quick scan of common ports
    'standard': '-T4 -sV --version-intensity 5',  # Service detection
    'aggressive': '-T4 -A',  # OS and service detection
    'full': '-T4 -p-',  # All ports
    'os': '-T4 -O --osscan-limit',  # OS detection
    'vuln': '-T4 --script=vuln,exploit,auth --script-args=unsafe=1',  # Vulnerability scan
    'deep': '-T4 -A --script=vuln,exploit,auth --script-args=unsafe=1',  # Deep scan (pentest)
    'wifi': '-T4 --script=wifi-discover',  # WiFi devices discovery
    'behavioral': '-T4 --script=behavioral-analysis'  # Behavioral analysis scan
}

# Expanded allowed IP ranges
ALLOWED_IP_RANGES = [
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '127.0.0.1/32',
    '169.254.0.0/16'  # Added for APIPA addresses
]

# Enhanced banned ports list
BANNED_PORTS = [21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 8080, 8443]

# Scan timeout (seconds)
SCAN_TIMEOUT = 600  # 10 minutes

# Enhanced protection configuration
PROTECTION_CONFIG = {
    'rate_limit': {
        'enabled': True,
        'requests_per_minute': 30,
        'ban_time': 300  # 5 minutes
    },
    'port_knocking': {
        'enabled': False,
        'sequence': [2000, 3000, 4000],
        'window': 10
    },
    'honeypot': {
        'enabled': True,
        'ports': [2222, 4444, 6666, 8888]
    },
    'auto_block': {
        'enabled': True,
        'block_duration': 86400  # 24 hours
    },
    'monitoring': {
        'enabled': True,
        'interval': 60  # seconds
    },
    'wifi_protection': {
        'enabled': True,
        'deauth_packets': 5,
        'monitor_interval': 300
    }
}

# AI model configuration
AI_CONFIG = {
    'model_path': 'models/threat_detection_model.pkl',
    'vectorizer_path': 'models/vectorizer.pkl',
    'threshold': 0.85,
    'training_data': 'data/threat_patterns.json'
}

# Paths for templates
REPORT_TEMPLATES = os.path.join(os.path.dirname(__file__), 'templates')

# Enhanced firewall rules
FIREWALL_RULES = [
    {'action': 'DROP', 'src': '0.0.0.0/0', 'dst': '0.0.0.0/0', 'dport': 22, 'comment': 'SSH Protection'},
    {'action': 'DROP', 'src': '0.0.0.0/0', 'dst': '0.0.0.0/0', 'dport': 23, 'comment': 'Telnet Protection'},
    {'action': 'DROP', 'src': '0.0.0.0/0', 'dst': '0.0.0.0/0', 'dport': 445, 'comment': 'SMB Protection'},
    {'action': 'DROP', 'src': '0.0.0.0/0', 'dst': '0.0.0.0/0', 'dport': 3389, 'comment': 'RDP Protection'}
]

# Logging configuration
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'logs/network_scanner.log',
    'max_size': 10485760,  # 10MB
    'backup_count': 5
}

# Vulnerability database
VULN_DB_CONFIG = {
    'nvd_api_url': 'https://services.nvd.nist.gov/rest/json/cves/1.0',
    'update_interval': 86400,  # 24 hours
    'local_db_path': 'data/vuln_db.json'
}

# WiFi configuration
WIFI_CONFIG = {
    'interface': 'wlan0',
    'monitor_interface': 'wlan0mon',
    'scan_interval': 300,
    'rogue_ap_detection': True,
    'max_clients': 50,
    'enabled': True
}

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('data', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('static/reports', exist_ok=True)
os.makedirs('templates', exist_ok=True)