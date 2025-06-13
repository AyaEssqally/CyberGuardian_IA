from fpdf import FPDF
from datetime import datetime
import matplotlib.pyplot as plt
import os
import seaborn as sns
from typing import Dict, List, Tuple
import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader
import pdfkit
import plotly.express as px
import json
import csv
from config import REPORT_TEMPLATES
import numpy as np
import logging
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

class PDFReport(FPDF):
    """Enhanced PDF report generator with custom styling"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(10, 10, 10)
        self.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
        self.set_font('DejaVu', '', 10)
        self.set_title("Network Security Scan Report")
    
    def header(self):
        self.set_font('DejaVu', 'B', 12)
        self.cell(0, 10, 'Network Security Scan Report - CyberShield', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('DejaVu', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(scan_data: Dict, output_path: str) -> bool:
    """Generate comprehensive PDF report from scan data
    
    Args:
        scan_data: Dictionary containing scan results
        output_path: Path to save the PDF file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        pdf = PDFReport()
        pdf.add_page()
        
        # Report metadata
        pdf.set_font('DejaVu', 'B', 16)
        pdf.cell(0, 10, 'Network Security Assessment', 0, 1, 'C')
        pdf.set_font('DejaVu', '', 10)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
        pdf.ln(10)
        
        # Risk score
        risk_score = scan_data['summary'].get('risk_score', 0)
        pdf.set_font('DejaVu', 'B', 12)
        pdf.cell(0, 10, 'Executive Summary', 0, 1)
        pdf.set_font('DejaVu', '', 10)
        
        # Risk visualization
        pdf.cell(0, 10, f"Overall Risk Score: {risk_score}/100", 0, 1)
        pdf.set_draw_color(200, 200, 200)
        pdf.rect(10, pdf.get_y(), 190, 10)
        pdf.set_fill_color(_get_risk_color(risk_score))
        pdf.rect(10, pdf.get_y(), 1.9 * risk_score, 10, 'F')
        pdf.ln(15)
        
        # Key metrics
        pdf.cell(0, 10, f"Scanned Hosts: {scan_data['summary']['total_hosts']}", 0, 1)
        pdf.cell(0, 10, f"Active Hosts: {scan_data['summary']['up_hosts']}", 0, 1)
        pdf.cell(0, 10, f"Open Ports: {scan_data['summary']['open_ports']}", 0, 1)
        pdf.cell(0, 10, f"Detected Vulnerabilities: {len(scan_data['summary'].get('vulnerabilities', []))}", 0, 1)
        pdf.ln(10)
        
        # Risk assessment
        pdf.set_font('DejaVu', 'B', 12)
        pdf.cell(0, 10, 'Risk Assessment', 0, 1)
        pdf.set_font('DejaVu', '', 10)
        
        risk_level, recommendations = _get_risk_assessment(risk_score)
        pdf.cell(0, 10, f"Risk Level: {risk_level}", 0, 1)
        
        # Recommendations
        pdf.ln(5)
        pdf.set_font('DejaVu', 'B', 12)
        pdf.cell(0, 10, 'Recommendations', 0, 1)
        pdf.set_font('DejaVu', '', 10)
        pdf.multi_cell(0, 10, recommendations)
        pdf.ln(10)
        
        # Charts section
        pdf.set_font('DejaVu', 'B', 12)
        pdf.cell(0, 10, 'Network Statistics', 0, 1)
        pdf.set_font('DejaVu', '', 10)
        
        # Generate and add charts
        _add_charts(pdf, scan_data)
        
        # Host details
        pdf.add_page()
        pdf.set_font('DejaVu', 'B', 12)
        pdf.cell(0, 10, 'Host Details', 0, 1)
        pdf.set_font('DejaVu', '', 10)
        
        for host in scan_data.get('hosts', []):
            if host['status'] != 'up':
                continue
                
            pdf.cell(0, 10, f"Host: {host['ip']}", 0, 1)
            pdf.cell(0, 10, f"Hostname: {host['hostnames'][0]['name'] if host['hostnames'] else 'N/A'}", 0, 1)
            pdf.cell(0, 10, f"OS: {host.get('os', {}).get('name', 'Unknown')}", 0, 1)
            pdf.cell(0, 10, f"Open Ports: {len([p for p in host['ports'] if p['state'] == 'open'])}", 0, 1)
            pdf.cell(0, 10, f"Risk Score: {host.get('risk_score', 0)}/100", 0, 1)
            
            # List open ports
            pdf.ln(5)
            pdf.set_font('DejaVu', 'B', 10)
            pdf.cell(60, 10, 'Port', 1)
            pdf.cell(40, 10, 'Service', 1)
            pdf.cell(40, 10, 'Version', 1)
            pdf.cell(50, 10, 'Risk', 1)
            pdf.ln()
            
            pdf.set_font('DejaVu', '', 8)
            for port in host['ports']:
                if port['state'] == 'open':
                    pdf.cell(60, 10, str(port['port']), 1)
                    pdf.cell(40, 10, port['service'].get('name', 'unknown'), 1)
                    pdf.cell(40, 10, f"{port['service'].get('product', '')} {port['service'].get('version', '')}", 1)
                    pdf.cell(50, 10, port.get('risk', 'low'), 1)
                    pdf.ln()
            
            pdf.ln(15)
        
        # Threats and vulnerabilities
        if scan_data.get('threats') or scan_data['summary'].get('vulnerabilities'):
            pdf.add_page()
            pdf.set_font('DejaVu', 'B', 12)
            pdf.cell(0, 10, 'Security Issues', 0, 1)
            pdf.set_font('DejaVu', '', 10)
            
            if scan_data.get('threats'):
                pdf.cell(0, 10, 'Detected Threats:', 0, 1)
                pdf.ln(5)
                
                for threat in scan_data['threats']:
                    pdf.cell(0, 10, f"- {threat.get('type')} from {threat.get('ip')}: {threat.get('description')}", 0, 1)
                pdf.ln(10)
            
            if scan_data['summary'].get('vulnerabilities'):
                pdf.cell(0, 10, 'Detected Vulnerabilities:', 0, 1)
                pdf.ln(5)
                
                for vuln in scan_data['summary']['vulnerabilities']:
                    pdf.cell(0, 10, f"- {vuln.get('type')} on {vuln.get('ip')}:{vuln.get('port')}", 0, 1)
                    pdf.multi_cell(0, 10, f"  {vuln.get('description')}", 0, 1)
                    pdf.ln(5)
        
        # Save PDF
        pdf.output(output_path)
        return True
        
    except Exception as e:
        logger.error(f"PDF generation error: {str(e)}")
        return False

def _get_risk_color(score: int) -> Tuple[int, int, int]:
    """Get RGB color based on risk score
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Tuple of (R, G, B) values
    """
    if score > 70:
        return (255, 0, 0)  # Red
    elif score > 40:
        return (255, 165, 0)  # Orange
    elif score > 20:
        return (255, 255, 0)  # Yellow
    return (0, 128, 0)  # Green

def _get_risk_assessment(score: int) -> Tuple[str, str]:
    """Get risk level and recommendations based on score
    
    Args:
        score: Risk score (0-100)
        
    Returns:
        Tuple of (risk_level, recommendations)
    """
    if score > 70:
        return (
            "CRITICAL - Immediate action required",
            "1. Isolate critical systems immediately\n"
            "2. Close all non-essential ports\n"
            "3. Patch all vulnerable services\n"
            "4. Change all default credentials\n"
            "5. Conduct forensic analysis"
        )
    elif score > 40:
        return (
            "HIGH - Prompt remediation needed",
            "1. Close high-risk ports immediately\n"
            "2. Patch vulnerable services\n"
            "3. Audit user accounts\n"
            "4. Implement proper firewall rules"
        )
    elif score > 20:
        return (
            "MEDIUM - Should be addressed",
            "1. Close unused ports\n"
            "2. Update outdated services\n"
            "3. Implement basic firewall rules\n"
            "4. Monitor for suspicious activity"
        )
    else:
        return (
            "LOW - Minimal risk",
            "1. Maintain system updates\n"
            "2. Regular network monitoring\n"
            "3. User security training\n"
            "4. Conduct periodic scans"
        )

def _add_charts(pdf: FPDF, scan_data: Dict):
    """Add charts to the PDF report
    
    Args:
        pdf: FPDF instance
        scan_data: Scan results data
    """
    try:
        # Create temp directory for charts
        os.makedirs('temp', exist_ok=True)
        
        # Service distribution chart
        if scan_data['summary'].get('services'):
            services = scan_data['summary']['services']
            labels = list(services.keys())
            sizes = list(services.values())
            
            plt.figure(figsize=(8, 6))
            sns.set_palette("husl")
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
            plt.axis('equal')
            plt.title('Service Distribution')
            plt.tight_layout()
            plt.savefig('temp/services.png', dpi=100, bbox_inches='tight')
            plt.close()
            
            pdf.image('temp/services.png', x=10, y=pdf.get_y(), w=180)
            pdf.ln(100)
        
        # OS distribution chart
        if scan_data['summary'].get('os_distribution'):
            os_dist = scan_data['summary']['os_distribution']
            labels = list(os_dist.keys())
            values = list(os_dist.values())
            
            plt.figure(figsize=(10, 6))
            sns.set_style("whitegrid")
            sns.barplot(x=values, y=labels, palette="Blues_d")
            plt.title('OS Distribution')
            plt.xlabel('Count')
            plt.tight_layout()
            plt.savefig('temp/os.png', dpi=100, bbox_inches='tight')
            plt.close()
            
            pdf.image('temp/os.png', x=10, y=pdf.get_y(), w=180)
            pdf.ln(120)
        
        # Cleanup temp files
        if os.path.exists('temp/services.png'):
            os.remove('temp/services.png')
        if os.path.exists('temp/os.png'):
            os.remove('temp/os.png')
        
    except Exception as e:
        logger.error(f"Failed to add charts to PDF: {str(e)}")

def generate_html_report(scan_data: Dict, output_path: str) -> bool:
    """Generate interactive HTML report
    
    Args:
        scan_data: Dictionary containing scan results
        output_path: Path to save the HTML file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        env = Environment(loader=FileSystemLoader(REPORT_TEMPLATES))
        template = env.get_template('report_template.html')
        
        # Prepare data
        summary = scan_data.get('summary', {})
        risk_score = summary.get('risk_score', 0)
        
        # Generate interactive charts
        services_chart = generate_plotly_service_chart(summary.get('services', {}))
        os_chart = generate_plotly_os_chart(summary.get('os_distribution', {}))
        vuln_chart = generate_plotly_vulnerability_chart(summary.get('vulnerabilities', {}))
        
        # Render HTML
        html = template.render(
            scan_data=scan_data,
            risk_score=risk_score,
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            services_chart=services_chart,
            os_chart=os_chart,
            vuln_chart=vuln_chart,
            assess_port_risk=assess_port_risk
        )
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
            
        return True
        
    except Exception as e:
        logger.error(f"HTML generation error: {str(e)}")
        return False

def generate_json_report(scan_data: Dict, output_path: str) -> bool:
    """Generate JSON report
    
    Args:
        scan_data: Dictionary containing scan results
        output_path: Path to save the JSON file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(output_path, 'w') as f:
            json.dump(scan_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"JSON generation error: {str(e)}")
        return False

def generate_csv_report(scan_data: Dict, output_path: str) -> bool:
    """Generate CSV report
    
    Args:
        scan_data: Dictionary containing scan results
        output_path: Path to save the CSV file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow([
                'IP', 'Hostname', 'Status', 'OS', 
                'Open Ports', 'Risk Score', 'Vulnerabilities'
            ])
            
            # Data
            for host in scan_data.get('hosts', []):
                hostname = host.get('hostnames', [{}])[0].get('name', '')
                os = host.get('os', {}).get('name', '')
                open_ports = len([p for p in host.get('ports', []) if p.get('state') == 'open'])
                vulns = len(host.get('vulnerabilities', []))
                
                writer.writerow([
                    host.get('ip', ''),
                    hostname,
                    host.get('status', ''),
                    os,
                    open_ports,
                    host.get('risk_score', 0),
                    vulns
                ])
        
        return True
    except Exception as e:
        logger.error(f"CSV generation error: {str(e)}")
        return False

def assess_port_risk(port: Dict) -> str:
    """Assess the risk level of a port
    
    Args:
        port: Dictionary containing port information
        
    Returns:
        Risk level (critical, high, medium, low)
    """
    service = port.get('service', {})
    port_num = int(port.get('port', 0))
    
    # Known vulnerable services
    if service.get('name') in ['http', 'ftp', 'telnet']:
        if 'anonymous' in service.get('extrainfo', '').lower():
            return "Critical"
        return "High"
    
    # Known risky ports
    if port_num in [21, 22, 23, 80, 443, 3389, 5900]:
        return "Medium"
    
    # Default to low
    return "Low"

def generate_service_chart(services: Dict, output_path: str):
    """Generate service distribution pie chart
    
    Args:
        services: Dictionary of service counts
        output_path: Path to save the chart image
    """
    plt.figure(figsize=(10, 8))
    sns.set_palette("husl")
    
    labels = list(services.keys())
    sizes = list(services.values())
    
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('Service Distribution', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight')
    plt.close()

def generate_os_chart(os_dist: Dict, output_path: str):
    """Generate OS distribution bar chart
    
    Args:
        os_dist: Dictionary of OS counts
        output_path: Path to save the chart image
    """
    plt.figure(figsize=(10, 6))
    sns.set_style("whitegrid")
    
    labels = list(os_dist.keys())
    values = list(os_dist.values())
    
    sns.barplot(x=values, y=labels, palette="Blues_d")
    plt.title('OS Distribution', pad=20)
    plt.xlabel('Count')
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight')
    plt.close()

def generate_vulnerability_chart(vulns: Dict, output_path: str):
    """Generate vulnerability distribution bar chart
    
    Args:
        vulns: Dictionary of vulnerability counts
        output_path: Path to save the chart image
    """
    plt.figure(figsize=(10, 6))
    sns.set_style("whitegrid")
    
    labels = list(vulns.keys())
    values = list(vulns.values())
    
    sns.barplot(x=values, y=labels, palette="Reds_d")
    plt.title('Vulnerability Distribution', pad=20)
    plt.xlabel('Count')
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches='tight')
    plt.close()

def generate_plotly_service_chart(services: Dict) -> str:
    """Generate interactive Plotly service chart
    
    Args:
        services: Dictionary of service counts
        
    Returns:
        HTML string containing the chart
    """
    if not services:
        return ""
        
    fig = go.Figure(data=[go.Pie(
        labels=list(services.keys()),
        values=list(services.values()),
        hole=.3,
        marker_colors=px.colors.sequential.Blues_r
    )])
    fig.update_layout(title_text='Service Distribution')
    return fig.to_html(full_html=False)

def generate_plotly_os_chart(os_dist: Dict) -> str:
    """Generate interactive Plotly OS chart
    
    Args:
        os_dist: Dictionary of OS counts
        
    Returns:
        HTML string containing the chart
    """
    if not os_dist:
        return ""
        
    fig = go.Figure([go.Bar(
        x=list(os_dist.values()),
        y=list(os_dist.keys()),
        orientation='h',
        marker_color='#1f77b4'
    )])
    fig.update_layout(
        title_text='OS Distribution',
        yaxis_title='OS',
        xaxis_title='Count'
    )
    return fig.to_html(full_html=False)

def generate_plotly_vulnerability_chart(vulns: Dict) -> str:
    """Generate interactive Plotly vulnerability chart
    
    Args:
        vulns: Dictionary of vulnerability counts
        
    Returns:
        HTML string containing the chart
    """
    if not vulns:
        return ""
        
    fig = go.Figure([go.Bar(
        x=list(vulns.values()),
        y=list(vulns.keys()),
        orientation='h',
        marker_color='#d62728'
    )])
    fig.update_layout(
        title_text='Vulnerability Distribution',
        yaxis_title='Vulnerability',
        xaxis_title='Count'
    )
    return fig.to_html(full_html=False)