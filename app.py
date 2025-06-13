from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from scanner.network_scanner import NetworkScanner
from scanner.report_generator import generate_pdf_report, generate_html_report, generate_json_report, generate_csv_report
import os
from datetime import datetime
import logging
from werkzeug.utils import secure_filename

import threading
import time
from flask_cors import CORS
import re
import ipaddress
import psutil
from config import (
    ALLOWED_IP_RANGES, SCAN_TIMEOUT, PROTECTION_CONFIG, 
    LOG_CONFIG, VULN_DB_CONFIG, WIFI_CONFIG, AI_CONFIG,
    DEFAULT_SCAN_OPTIONS, BANNED_PORTS
)
import uuid
import json
from functools import wraps

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['REPORT_FOLDER'] = 'static/reports'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SCAN_TIMEOUT'] = SCAN_TIMEOUT

# Configure logging
logging.basicConfig(
    level=LOG_CONFIG['level'],
    format=LOG_CONFIG['format'],
    handlers=[
        logging.FileHandler(LOG_CONFIG['file']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

active_scans = {}
network_scanner = NetworkScanner()

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if PROTECTION_CONFIG['rate_limit']['enabled']:
            ip = request.remote_addr
            if network_scanner.is_rate_limited(ip):
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'message': 'Too many requests'
                }), 429
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('lanscan.html')

@app.route('/scan', methods=['POST'])
@rate_limit
def scan_network():
    try:
        data = request.json
        ip_range = data.get('ip_range', '').strip()
        scan_type = data.get('scan_type', 'quick')
        options = data.get('options', {})
        
        # Validate input
        if not ip_range:
            raise ValueError("IP range is required")
            
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip_range):
            raise ValueError("Invalid IP range format")
            
        # Check if IP range is allowed
        try:
            network = ipaddress.ip_network(ip_range)
            allowed = any(
                network.subnet_of(ipaddress.ip_network(allowed_range))
                for allowed_range in ALLOWED_IP_RANGES
            )
            if not allowed:
                raise ValueError("IP range not allowed")
        except ValueError as e:
            raise ValueError(f"Invalid IP range: {str(e)}")
        
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting {scan_type} scan for {ip_range} (ID: {scan_id})")
        
        scanner = NetworkScanner()
        active_scans[scan_id] = {
            'scanner': scanner,
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'type': scan_type,
            'ip_range': ip_range,
            'options': options
        }
        
        def run_scan():
            try:
                results = scanner.scan(
                    ip_range=ip_range,
                    scan_type=scan_type,
                    options=options,
                    callback=lambda p: update_scan_progress(scan_id, p)
                )
                active_scans[scan_id]['results'] = results
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['end_time'] = datetime.now()
                active_scans[scan_id]['progress'] = 100
                
                # Check for threats and vulnerabilities
                check_for_threats(results)
                
            except Exception as e:
                logger.error(f"Scan failed: {str(e)}")
                active_scans[scan_id]['error'] = str(e)
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['end_time'] = datetime.now()
        
        def update_scan_progress(scan_id, progress):
            if scan_id in active_scans:
                active_scans[scan_id]['progress'] = progress
        
        thread = threading.Thread(target=run_scan)
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        logger.error(f"Scan failed to start: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Scan failed to start'
        }), 400

def check_for_threats(scan_results):
    """Analyze scan results for potential threats"""
    threats = []
    
    # Check for open risky ports
    for host in scan_results.get('hosts', []):
        for port in host.get('ports', []):
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
    for vuln in scan_results.get('vulnerabilities', []):
        threats.append({
            'type': 'vulnerability',
            'ip': vuln.get('ip', 'unknown'),
            'port': vuln.get('port', 'unknown'),
            'severity': vuln.get('severity', 'medium'),
            'timestamp': datetime.now().isoformat(),
            'description': vuln.get('description', 'Unknown vulnerability')
        })
    
    # Save threats to database
    if threats:
        network_scanner.save_threats(threats)
        
        # Trigger automatic responses if configured
        if PROTECTION_CONFIG['auto_block']['enabled']:
            for threat in threats:
                if threat['severity'] in ['high', 'critical']:
                    network_scanner.block_device(ip=threat['ip'], reason=threat['description'])

@app.route('/scan_status/<scan_id>')
@rate_limit
def scan_status(scan_id):
    try:
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({
                'success': False,
                'error': 'Scan not found',
                'message': 'Invalid scan ID'
            }), 404
        
        scanner = scan['scanner']
        progress = scan['progress']
        
        if scan['status'] == 'completed':
            return jsonify({
                'success': True,
                'status': 'completed',
                'results': scan.get('results'),
                'progress': progress,
                'duration': (scan['end_time'] - scan['start_time']).total_seconds(),
                'scan_type': scan['type'],
                'ip_range': scan['ip_range']
            })
        elif scan['status'] == 'failed':
            return jsonify({
                'success': False,
                'status': 'failed',
                'error': scan.get('error'),
                'progress': progress,
                'duration': (scan['end_time'] - scan['start_time']).total_seconds()
            })
        else:
            return jsonify({
                'success': True,
                'status': 'running',
                'progress': progress,
                'duration': (datetime.now() - scan['start_time']).total_seconds(),
                'scan_type': scan['type'],
                'ip_range': scan['ip_range']
            })
            
    except Exception as e:
        logger.error(f"Failed to get scan status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get scan status'
        }), 500

@app.route('/generate_report', methods=['POST'])
@rate_limit
def handle_report_generation():
    try:
        data = request.json
        scan_results = data.get('results')
        report_type = data.get('report_type', 'pdf')
        
        if not scan_results:
            raise ValueError("No scan results provided")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
        report_filename = f"scan_report_{timestamp}.{report_type}"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        
        if report_type == 'pdf':
            success = generate_pdf_report(scan_results, report_path)
        elif report_type == 'html':
            success = generate_html_report(scan_results, report_path)
        elif report_type == 'json':
            success = generate_json_report(scan_results, report_path)
        elif report_type == 'csv':
            success = generate_csv_report(scan_results, report_path)
        else:
            raise ValueError("Invalid report type")
        
        if not success:
            raise ValueError("Report generation failed")
        
        return jsonify({
            'success': True,
            'report_url': f"/download_report/{report_filename}",
            'message': 'Report generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Report generation failed'
        }), 500

@app.route('/download_report/<filename>')
@rate_limit
def download_report(filename):
    try:
        safe_filename = secure_filename(filename)
        return send_from_directory(
            app.config['REPORT_FOLDER'],
            safe_filename,
            as_attachment=True,
            download_name=f"LANScan_Report_{safe_filename}"
        )
    except Exception as e:
        logger.error(f"Report download failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Report download failed'
        }), 404

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/cancel_scan/<scan_id>', methods=['POST'])
@rate_limit
def cancel_scan(scan_id):
    try:
        scan = active_scans.get(scan_id)
        if not scan:
            return jsonify({
                'success': False,
                'error': 'Scan not found',
                'message': 'Invalid scan ID'
            }), 404
        
        if scan['status'] == 'running':
            scan['scanner'].cancel_scan()
            scan['status'] = 'cancelled'
            scan['end_time'] = datetime.now()
            return jsonify({
                'success': True,
                'message': 'Scan cancelled successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Scan not running',
                'message': 'Scan cannot be cancelled as it is not running'
            }), 400
            
    except Exception as e:
        logger.error(f"Failed to cancel scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to cancel scan'
        }), 500

@app.route('/block_device', methods=['POST'])
@rate_limit
def block_device():
    try:
        data = request.json
        ip = data.get('ip')
        mac = data.get('mac')
        reason = data.get('reason', 'Manual block')
        
        if not ip and not mac:
            raise ValueError("IP or MAC address is required")
        
        success = network_scanner.block_device(ip=ip, mac=mac, reason=reason)
        
        return jsonify({
            'success': success,
            'message': 'Device blocked successfully' if success else 'Failed to block device'
        })
    except Exception as e:
        logger.error(f"Failed to block device: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to block device'
        }), 500

@app.route('/unblock_device', methods=['POST'])
@rate_limit
def unblock_device():
    try:
        data = request.json
        ip = data.get('ip')
        mac = data.get('mac')
        
        if not ip and not mac:
            raise ValueError("IP or MAC address is required")
        
        success = network_scanner.unblock_device(ip=ip, mac=mac)
        
        return jsonify({
            'success': success,
            'message': 'Device unblocked successfully' if success else 'Failed to unblock device'
        })
    except Exception as e:
        logger.error(f"Failed to unblock device: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to unblock device'
        }), 500

@app.route('/get_blocked_devices')
@rate_limit
def get_blocked_devices():
    try:
        blocked_devices = network_scanner.get_blocked_devices()
        return jsonify({
            'success': True,
            'blocked_devices': blocked_devices
        })
    except Exception as e:
        logger.error(f"Failed to get blocked devices: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get blocked devices'
        }), 500

@app.route('/get_security_alerts')
@rate_limit
def get_security_alerts():
    try:
        alerts = network_scanner.get_security_alerts()
        return jsonify({
            'success': True,
            'alerts': alerts
        })
    except Exception as e:
        logger.error(f"Failed to get security alerts: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get security alerts'
        }), 500

@app.route('/get_scan_history')
@rate_limit
def get_scan_history():
    try:
        history = []
        for scan_id, scan_data in active_scans.items():
            if scan_data['status'] in ['completed', 'failed']:
                history.append({
                    'id': scan_id,
                    'type': scan_data.get('type', 'unknown'),
                    'ip_range': scan_data.get('ip_range', 'unknown'),
                    'status': scan_data['status'],
                    'start_time': scan_data['start_time'].isoformat(),
                    'end_time': scan_data.get('end_time', datetime.now()).isoformat(),
                    'duration': (scan_data.get('end_time', datetime.now()) - scan_data['start_time']).total_seconds()
                })
        
        # Sort by most recent first
        history.sort(key=lambda x: x['start_time'], reverse=True)
        
        return jsonify({
            'success': True,
            'history': history[:10]  # Return only last 10 scans
        })
    except Exception as e:
        logger.error(f"Failed to get scan history: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get scan history'
        }), 500

@app.route('/get_active_scans')
@rate_limit
def get_active_scans():
    try:
        active = []
        for scan_id, scan_data in active_scans.items():
            if scan_data['status'] == 'running':
                active.append({
                    'id': scan_id,
                    'type': scan_data.get('type', 'unknown'),
                    'ip_range': scan_data.get('ip_range', 'unknown'),
                    'progress': scan_data.get('progress', 0),
                    'start_time': scan_data['start_time'].isoformat(),
                    'duration': (datetime.now() - scan_data['start_time']).total_seconds()
                })
        
        return jsonify({
            'success': True,
            'active_scans': active
        })
    except Exception as e:
        logger.error(f"Failed to get active scans: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get active scans'
        }), 500


@app.route('/get_system_stats')
@rate_limit
def get_system_stats():
    try:
        stats = {
            'cpu': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('C:\\').percent  # Disque C: pour Windows
        }
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Échec de récupération des stats système : {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Échec de récupération des statistiques système'
        }), 500

@app.route('/get_network_info')
@rate_limit
def get_network_info():
    try:
        info = network_scanner.get_network_info()
        return jsonify({
            'success': True,
            'network_info': info
        })
    except Exception as e:
        logger.error(f"Failed to get network info: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get network info'
        }), 500

@app.route('/get_wifi_clients')
@rate_limit
def get_wifi_clients():
    try:
        clients = network_scanner.get_wifi_clients()
        return jsonify({
            'success': True,
            'clients': clients
        })
    except Exception as e:
        logger.error(f"Failed to get WiFi clients: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to get WiFi clients'
        }), 500

@app.route('/block_wifi_client', methods=['POST'])
@rate_limit
def block_wifi_client():
    try:
        data = request.json
        mac = data.get('mac')
        
        if not mac:
            raise ValueError("MAC address is required")
        
        success = network_scanner.block_wifi_client(mac)
        
        return jsonify({
            'success': success,
            'message': 'WiFi client blocked successfully' if success else 'Failed to block WiFi client'
        })
    except Exception as e:
        logger.error(f"Failed to block WiFi client: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to block WiFi client'
        }), 500

@app.route('/automatic_response', methods=['POST'])
@rate_limit
def handle_automatic_response():
    try:
        data = request.json
        threat_type = data.get('threat_type')
        ip = data.get('ip')
        port = data.get('port')
        
        if not threat_type or not ip:
            raise ValueError("Threat type and IP are required")
        
        response = network_scanner.automatic_response(threat_type, ip, port)
        
        return jsonify({
            'success': True,
            'message': 'Automatic response executed',
            'actions_taken': response
        })
    except Exception as e:
        logger.error(f"Failed to execute automatic response: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to execute automatic response'
        }), 500

@app.route('/update_settings', methods=['POST'])
@rate_limit
def update_settings():
    try:
        data = request.json
        setting_type = data.get('type')
        settings = data.get('settings')
        
        if not setting_type or not settings:
            raise ValueError("Type and settings are required")
        
        success = network_scanner.update_settings(setting_type, settings)
        
        return jsonify({
            'success': success,
            'message': 'Settings updated successfully' if success else 'Failed to update settings'
        })
    except Exception as e:
        logger.error(f"Failed to update settings: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Failed to update settings'
        }), 500

if __name__ == '__main__':
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)