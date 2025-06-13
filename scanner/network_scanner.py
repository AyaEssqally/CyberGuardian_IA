import nmap
import subprocess
import time
import logging
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import ipaddress
import threading
import sqlite3
from config import (
    DEFAULT_SCAN_OPTIONS, ALLOWED_IP_RANGES, BANNED_PORTS,
    PROTECTION_CONFIG, VULN_DB_CONFIG, WIFI_CONFIG, AI_CONFIG
)

logger = logging.getLogger(__name__)

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_progress = 0
        self.scan_cancelled = False
        self.rate_limits = {}
        self.blocked_devices = []
        self.security_alerts = []
        self.db_file = 'data/network_scanner.db'
        self._init_db()
        
    def _init_db(self):
        """Initialize the SQLite database"""
        os.makedirs('data', exist_ok=True)
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    mac TEXT,
                    reason TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT,
                    ip TEXT,
                    port INTEGER,
                    severity TEXT,
                    description TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    scan_type TEXT,
                    ip_range TEXT,
                    status TEXT,
                    start_time DATETIME,
                    end_time DATETIME,
                    results TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    src TEXT,
                    dst TEXT,
                    dport INTEGER,
                    protocol TEXT,
                    comment TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()

    def scan(self, ip_range: str, scan_type: str = 'quick', 
             options: Dict = None, callback: callable = None) -> Dict:
        """
        Perform a network scan with the specified parameters
        
        Args:
            ip_range: IP range to scan (e.g., '192.168.1.0/24')
            scan_type: Type of scan (quick, standard, aggressive, etc.)
            options: Additional scan options
            callback: Function to call with progress updates
            
        Returns:
            Dictionary containing scan results
        """
        self.scan_progress = 0
        self.scan_cancelled = False
        
        try:
            # Validate IP range
            if not self._validate_ip_range(ip_range):
                raise ValueError(f"Invalid or not allowed IP range: {ip_range}")
            
            # Get scan arguments based on type
            scan_args = DEFAULT_SCAN_OPTIONS.get(scan_type, '-T4 -F')
            
            # Apply additional options
            if options:
                if options.get('vuln', False):
                    scan_args += ' --script=vuln'
                if options.get('deep', False):
                    scan_args += ' -A'
                if options.get('wifi', False):
                    scan_args += ' --script=wifi-discover'
                if options.get('behavioral', False):
                    scan_args += ' --script=behavioral-analysis'
            
            logger.info(f"Starting {scan_type} scan on {ip_range} with args: {scan_args}")
            
            # Start the scan in a separate thread to allow progress monitoring
            scan_thread = threading.Thread(
                target=self._run_scan,
                args=(ip_range, scan_args, callback) )
            scan_thread.start()
            
            # Wait for scan to complete or be cancelled
            while scan_thread.is_alive() and not self.scan_cancelled:
                time.sleep(0.5)
            
            if self.scan_cancelled:
                logger.info("Scan was cancelled")
                return {'status': 'cancelled', 'progress': self.scan_progress}
            
            # Process results
            results = self._process_scan_results(ip_range, scan_type)
            self.scan_progress = 100
            if callback:
                callback(self.scan_progress)
            
            return results
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            raise

    def _run_scan(self, ip_range: str, scan_args: str, callback: callable = None):
        """
        Internal method to run the actual scan with progress updates
        """
        try:
            # Start the scan
            self.nm.scan(hosts=ip_range, arguments=scan_args)
            
            # Simulate progress updates (in a real implementation, this would track actual progress)
            for i in range(1, 101):
                if self.scan_cancelled:
                    break
                
                time.sleep(0.1)
                self.scan_progress = i
                if callback:
                    callback(i)
                    
        except Exception as e:
            logger.error(f"Scan thread failed: {str(e)}")

    def _process_scan_results(self, ip_range: str, scan_type: str) -> Dict:
        """
        Process raw scan results into a structured format
        
        Args:
            ip_range: The scanned IP range
            scan_type: Type of scan performed
            
        Returns:
            Dictionary containing processed scan results
        """
        results = {
            'summary': {
                'scan_type': scan_type,
                'ip_range': ip_range,
                'start_time': datetime.now().isoformat(),
                'total_hosts': 0,
                'up_hosts': 0,
                'open_ports': 0,
                'services': {},
                'os_distribution': {},
                'risk_score': 0,
                'vulnerabilities': []
            },
            'hosts': [],
            'threats': []
        }
        
        # Count hosts and gather basic info
        all_hosts = self.nm.all_hosts()
        results['summary']['total_hosts'] = len(all_hosts)
        
        for host in all_hosts:
            host_info = {
                'ip': host,
                'hostnames': [{'name': self.nm[host].hostname()}] if self.nm[host].hostname() else [],
                'status': 'up' if self.nm[host].state() == 'up' else 'down',
                'ports': [],
                'risk_score': 0,
                'vulnerabilities': []
            }
            
            if host_info['status'] == 'up':
                results['summary']['up_hosts'] += 1
                
                # Get OS information if available
                if 'osmatch' in self.nm[host]:
                    host_info['os'] = {
                        'name': self.nm[host]['osmatch'][0]['name'],
                        'accuracy': self.nm[host]['osmatch'][0]['accuracy']
                    }
                    # Update OS distribution stats
                    os_name = host_info['os']['name']
                    results['summary']['os_distribution'][os_name] = results['summary']['os_distribution'].get(os_name, 0) + 1
                
                # Process ports
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            results['summary']['open_ports'] += 1
                            
                            # Assess port risk
                            port_risk = self.assess_port_risk({
                                'port': port,
                                'protocol': proto,
                                'service': port_info
                            })
                            
                            host_info['ports'].append({
                                'port': port,
                                'protocol': proto,
                                'state': port_info['state'],
                                'service': {
                                    'name': port_info['name'],
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'extrainfo': port_info.get('extrainfo', '')
                                },
                                'risk': port_risk
                            })
                            
                            # Update service distribution stats
                            service_name = port_info['name'] or 'unknown'
                            results['summary']['services'][service_name] = results['summary']['services'].get(service_name, 0) + 1
                
                # Calculate host risk score
                host_info['risk_score'] = self.calculate_host_risk(host_info)
                
                # Check for vulnerabilities
                host_info['vulnerabilities'] = self.check_vulnerabilities(host_info)
                results['summary']['vulnerabilities'].extend(host_info['vulnerabilities'])
            
            results['hosts'].append(host_info)
        
        # Calculate overall risk score
        results['summary']['risk_score'] = self.calculate_network_risk(results)
        
        # Check for threats
        results['threats'] = self.check_threats(results)
        
        # Save scan to history
        self._save_scan_history(results)
        
        return results

    def _validate_ip_range(self, ip_range: str) -> bool:
        """
        Validate that the IP range is allowed
        
        Args:
            ip_range: IP range to validate
            
        Returns:
            True if valid and allowed, False otherwise
        """
        try:
            network = ipaddress.ip_network(ip_range)
            allowed = any(
                network.subnet_of(ipaddress.ip_network(allowed_range))
                for allowed_range in ALLOWED_IP_RANGES
            )
            return allowed
        except ValueError:
            return False

    def assess_port_risk(self, port_info: Dict) -> str:
        """
        Assess the risk level of an open port
        
        Args:
            port_info: Dictionary containing port information
            
        Returns:
            Risk level (critical, high, medium, low)
        """
        port = port_info.get('port')
        service = port_info.get('service', {})
        
        # Check for known vulnerable services
        if service.get('name') in ['http', 'ftp', 'telnet']:
            if 'anonymous' in service.get('extrainfo', '').lower():
                return 'critical'
            return 'high'
        
        # Check for risky ports
        if port in BANNED_PORTS:
            return 'high'
        
        # Common services with potential risks
        if port in [21, 22, 23, 80, 443, 3389, 5900]:
            return 'medium'
        
        return 'low'

    def calculate_host_risk(self, host_info: Dict) -> int:
        """
        Calculate a risk score (0-100) for a host
        
        Args:
            host_info: Host information dictionary
            
        Returns:
            Risk score (0-100)
        """
        risk_score = 0
        
        # Base risk based on open ports
        for port in host_info.get('ports', []):
            if port['state'] == 'open':
                if port['risk'] == 'critical':
                    risk_score += 20
                elif port['risk'] == 'high':
                    risk_score += 10
                elif port['risk'] == 'medium':
                    risk_score += 5
                else:
                    risk_score += 1
        
        # Cap at 100
        return min(100, risk_score)

    def calculate_network_risk(self, scan_results: Dict) -> int:
        """
        Calculate an overall network risk score (0-100)
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            Network risk score (0-100)
        """
        if not scan_results['hosts']:
            return 0
            
        total_risk = sum(host['risk_score'] for host in scan_results['hosts'])
        avg_risk = total_risk / len(scan_results['hosts'])
        
        # Adjust based on vulnerabilities
        vuln_count = len(scan_results['summary']['vulnerabilities'])
        if vuln_count > 0:
            avg_risk = min(100, avg_risk + (vuln_count * 5))
        
        return int(avg_risk)

    def check_vulnerabilities(self, host_info: Dict) -> List[Dict]:
        """
        Check for known vulnerabilities on a host
        
        Args:
            host_info: Host information dictionary
            
        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check each open port for vulnerabilities
        for port in host_info.get('ports', []):
            if port['state'] != 'open':
                continue
                
            # Check for known vulnerable services
            if port['service'].get('name') == 'http' and port['service'].get('version', '').startswith('Apache 2.4.49'):
                vulnerabilities.append({
                    'type': 'CVE-2021-41773',
                    'severity': 'critical',
                    'description': 'Apache HTTP Server Path Traversal and File Disclosure',
                    'port': port['port'],
                    'solution': 'Upgrade to Apache 2.4.50 or later'
                })
            
            # Add more vulnerability checks here...
        
        return vulnerabilities

    def check_threats(self, scan_results: Dict) -> List[Dict]:
        """
        Check scan results for potential security threats
        
        Args:
            scan_results: Complete scan results
            
        Returns:
            List of threats detected
        """
        threats = []
        
        # Check for open risky ports
        for host in scan_results['hosts']:
            for port in host['ports']:
                if port['port'] in BANNED_PORTS and port['state'] == 'open':
                    threats.append({
                        'type': 'risky_port',
                        'ip': host['ip'],
                        'port': port['port'],
                        'severity': 'high',
                        'timestamp': datetime.now().isoformat(),
                        'description': f"Risky port {port['port']} is open"
                    })
        
        # Check for vulnerabilities
        for vuln in scan_results['summary']['vulnerabilities']:
            threats.append({
                'type': 'vulnerability',
                'ip': vuln.get('ip', 'unknown'),
                'port': vuln.get('port', 'unknown'),
                'severity': vuln.get('severity', 'medium'),
                'timestamp': datetime.now().isoformat(),
                'description': vuln.get('description', 'Unknown vulnerability')
            })
        
        # Save threats to database
        self.save_threats(threats)
        
        return threats

    def save_threats(self, threats: List[Dict]):
        """
        Save detected threats to the database
        
        Args:
            threats: List of threat dictionaries
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            for threat in threats:
                cursor.execute('''
                    INSERT INTO security_alerts 
                    (type, ip, port, severity, description)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    threat['type'],
                    threat.get('ip'),
                    threat.get('port'),
                    threat.get('severity', 'medium'),
                    threat.get('description', '')
                ))
            
            conn.commit()

    def _save_scan_history(self, scan_results: Dict):
        """
        Save scan results to history database
        
        Args:
            scan_results: Complete scan results
        """
        with sqlite3.connect(self.db_file) as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO scan_history 
                (scan_id, scan_type, ip_range, status, start_time, end_time, results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                f"scan_{datetime.now().timestamp()}",
                scan_results['summary']['scan_type'],
                scan_results['summary']['ip_range'],
                'completed',
                scan_results['summary']['start_time'],
                datetime.now().isoformat(),
                json.dumps(scan_results)
            ))
            
            conn.commit()

    def cancel_scan(self):
        """Cancel the current scan"""
        self.scan_cancelled = True
        self.nm.stop()

    def is_rate_limited(self, ip: str) -> bool:
        """
        Check if an IP is rate limited
        
        Args:
            ip: IP address to check
            
        Returns:
            True if rate limited, False otherwise
        """
        if not PROTECTION_CONFIG['rate_limit']['enabled']:
            return False
            
        now = time.time()
        if ip not in self.rate_limits:
            self.rate_limits[ip] = {
                'count': 1,
                'last_time': now
            }
            return False
        
        time_diff = now - self.rate_limits[ip]['last_time']
        if time_diff > 60:  # Reset counter if more than 1 minute has passed
            self.rate_limits[ip] = {
                'count': 1,
                'last_time': now
            }
            return False
        
        self.rate_limits[ip]['count'] += 1
        self.rate_limits[ip]['last_time'] = now
        
        return self.rate_limits[ip]['count'] > PROTECTION_CONFIG['rate_limit']['requests_per_minute']

    def block_device(self, ip: str = None, mac: str = None, reason: str = 'Manual block') -> bool:
        """
        Block a device by IP or MAC address
        
        Args:
            ip: IP address to block
            mac: MAC address to block
            reason: Reason for blocking
            
        Returns:
            True if successful, False otherwise
        """
        if not ip and not mac:
            return False
            
        try:
            # In a real implementation, this would use iptables or similar
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO blocked_devices 
                    (ip, mac, reason)
                    VALUES (?, ?, ?)
                ''', (ip, mac, reason))
                
                conn.commit()
            
            # Add to in-memory list
            self.blocked_devices.append({
                'ip': ip,
                'mac': mac,
                'reason': reason,
                'timestamp': datetime.now().isoformat()
            })
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to block device: {str(e)}")
            return False

    def unblock_device(self, ip: str = None, mac: str = None) -> bool:
        """
        Unblock a device by IP or MAC address
        
        Args:
            ip: IP address to unblock
            mac: MAC address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        if not ip and not mac:
            return False
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                
                if ip:
                    cursor.execute('DELETE FROM blocked_devices WHERE ip = ?', (ip,))
                if mac:
                    cursor.execute('DELETE FROM blocked_devices WHERE mac = ?', (mac,))
                
                conn.commit()
            
            # Remove from in-memory list
            self.blocked_devices = [
                d for d in self.blocked_devices 
                if not (d['ip'] == ip or d['mac'] == mac)
            ]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock device: {str(e)}")
            return False

    def get_blocked_devices(self) -> List[Dict]:
        """
        Get list of currently blocked devices
        
        Returns:
            List of blocked devices
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM blocked_devices ORDER BY timestamp DESC')
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get blocked devices: {str(e)}")
            return []

    def get_security_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Get recent security alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of security alerts
        """
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM security_alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get security alerts: {str(e)}")
            return []

    def automatic_response(self, threat_type: str, ip: str, port: int = None) -> Dict:
        """
        Perform automatic response to a detected threat
        
        Args:
            threat_type: Type of threat detected
            ip: IP address of the threat source
            port: Port involved (if applicable)
            
        Returns:
            Dictionary of actions taken
        """
        actions = {}
        
        if PROTECTION_CONFIG['auto_block']['enabled']:
            # Block the IP
            success = self.block_device(ip=ip, reason=f"Automatic block for {threat_type}")
            actions['blocked'] = success
            
        if threat_type == 'bruteforce' and PROTECTION_CONFIG['rate_limit']['enabled']:
            # Add to rate limit blacklist
            self.rate_limits[ip] = {
                'count': PROTECTION_CONFIG['rate_limit']['requests_per_minute'] + 1,
                'last_time': time.time()
            }
            actions['rate_limited'] = True
            
        # Log the response
        logger.info(f"Automatic response to {threat_type} from {ip}: {actions}")
        
        return actions

    def get_network_info(self) -> Dict:
        """
        Get general network information
        
        Returns:
            Dictionary of network information
        """
        try:
            # Get default gateway
            gateway = subprocess.check_output("ip route | grep default | awk '{print $3}'", shell=True).decode().strip()
            
            # Get local IP
            local_ip = subprocess.check_output("hostname -I | awk '{print $1}'", shell=True).decode().strip()
            
            # Get DNS servers
            dns_servers = []
            with open('/etc/resolv.conf') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
            
            return {
                'gateway': gateway,
                'local_ip': local_ip,
                'dns_servers': dns_servers,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get network info: {str(e)}")
            return {}

    def get_wifi_clients(self) -> List[Dict]:
        """
        Get list of WiFi clients
        
        Returns:
            List of WiFi clients
        """
        if not WIFI_CONFIG['enabled']:
            return []
            
        try:
            # In a real implementation, this would use iw or similar
            return [
                {
                    'mac': '00:11:22:33:44:55',
                    'ip': '192.168.1.100',
                    'signal_strength': -65,
                    'first_seen': '2023-01-01T12:00:00',
                    'last_seen': datetime.now().isoformat()
                }
                # Add more dummy data for testing
            ]
        except Exception as e:
            logger.error(f"Failed to get WiFi clients: {str(e)}")
            return []

    def block_wifi_client(self, mac: str) -> bool:
        """
        Block a WiFi client by MAC address
        
        Args:
            mac: MAC address to block
            
        Returns:
            True if successful, False otherwise
        """
        if not WIFI_CONFIG['enabled']:
            return False
            
        try:
            # In a real implementation, this would use iptables or similar
            return True
        except Exception as e:
            logger.error(f"Failed to block WiFi client: {str(e)}")
            return False

    def update_settings(self, setting_type: str, settings: Dict) -> bool:
        """
        Update scanner settings
        
        Args:
            setting_type: Type of settings to update
            settings: Dictionary of settings
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # In a real implementation, this would update the configuration
            return True
        except Exception as e:
            logger.error(f"Failed to update settings: {str(e)}")
            return False