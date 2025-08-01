#!/usr/bin/env python3
"""
MX-Chan Domain Spoofing Vulnerability Analyzer
A specialized tool for detecting email spoofing vulnerabilities in domains
Analyzes SPF, DMARC, and DKIM configurations to determine spoofing risk
"""

import dns.resolver
import re
import sys
import argparse
import requests
import json
import time
import socket
import smtplib
import threading
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from email.utils import parseaddr
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align

# Initialize Rich console
console = Console()

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[35m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    @staticmethod
    def colorize(text: str, color: str) -> str:
        return f"{color}{text}{Colors.RESET}"

class SimpleProgressBar:
    def __init__(self, total: int, desc: str = "Progress"):
        self.total = total
        self.current = 0
        self.desc = desc
        
    def update(self, step: int = 1):
        self.current += step
        self.show_progress()
        
    def set_description(self, desc: str):
        self.desc = desc
        
    def show_progress(self):
        percentage = (self.current / self.total) * 100
        bar_length = 30
        filled = int((self.current / self.total) * bar_length)
        bar = '█' * filled + '░' * (bar_length - filled)
        print(f"\r{Colors.colorize(self.desc, Colors.CYAN)} [{Colors.colorize(bar, Colors.GREEN)}] {percentage:.0f}%", end='', flush=True)
        if self.current >= self.total:
            print()  # New line when complete

class SpoofingRisk(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low" 
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class SpoofingVulnerability:
    category: str
    vulnerability: str
    risk_level: SpoofingRisk
    impact: str
    recommendation: str
    technical_details: str

@dataclass
class EmailValidationResult:
    email: str
    is_valid_format: bool
    domain_matches: bool
    smtp_reachable: bool
    email_exists: bool
    validation_details: Dict[str, str]

@dataclass
class SpoofingAnalysis:
    domain: str
    overall_risk: SpoofingRisk
    spoofable: bool
    vulnerabilities: List[SpoofingVulnerability]
    protection_score: int  # 0-100
    records_found: Dict[str, List[str]]
    email_validation: Optional[EmailValidationResult] = None

class MXChanSpoofingAnalyzer:
    def __init__(self, domain: str, debug: bool = False):
        self.domain = domain.lower().strip()
        self.debug = debug
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '1.0.0.1']
        self.resolver.timeout = 3
        self.resolver.lifetime = 10
        
    def query_dns_record(self, record_type: str, domain: str = None) -> List[str]:
        """Query DNS records with error handling"""
        target = domain or self.domain
        
        if self.debug:
            print(f"Debug: Querying {record_type} record for {target}")
            
        try:
            answers = self.resolver.resolve(target, record_type)
            results = [str(answer).strip('"') for answer in answers]
            
            if self.debug:
                print(f"Debug: Found {len(results)} {record_type} records")
                
            return results
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception) as e:
            if self.debug:
                print(f"Debug: No {record_type} records for {target}: {type(e).__name__}")
            return []
    
    def analyze_spf_spoofing_risk(self) -> List[SpoofingVulnerability]:
        """Analyze SPF configuration for spoofing vulnerabilities"""
        vulnerabilities = []
        spf_records = self.query_dns_record('TXT')
        spf_record = None
        
        # Find SPF record
        for record in spf_records:
            if record.startswith('v=spf1'):
                spf_record = record
                break
        
        if not spf_record:
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Missing",
                vulnerability="No SPF record found",
                risk_level=SpoofingRisk.CRITICAL,
                impact="Domain can be easily spoofed from any IP address",
                recommendation="Implement SPF record immediately with '-all' mechanism",
                technical_details="Missing SPF allows unlimited spoofing potential"
            ))
            return vulnerabilities
        
        # Analyze SPF mechanisms
        if '+all' in spf_record:
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Dangerous Policy",
                vulnerability="SPF record contains '+all' mechanism",
                risk_level=SpoofingRisk.CRITICAL,
                impact="Any server worldwide can send emails on behalf of this domain",
                recommendation="Change '+all' to '-all' immediately",
                technical_details=f"SPF Record: {spf_record}"
            ))
        elif '~all' in spf_record:
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Weak Policy",
                vulnerability="SPF record uses soft fail (~all)",
                risk_level=SpoofingRisk.MEDIUM,
                impact="Spoofed emails may be delivered to inbox with soft fail",
                recommendation="Consider upgrading to hard fail (-all) for stronger protection",
                technical_details=f"SPF Record: {spf_record}"
            ))
        elif '?all' in spf_record:
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Neutral Policy",
                vulnerability="SPF record uses neutral policy (?all)",
                risk_level=SpoofingRisk.HIGH,
                impact="No protection against spoofing attempts",
                recommendation="Change to '-all' for proper protection",
                technical_details=f"SPF Record: {spf_record}"
            ))
        elif not any(policy in spf_record for policy in ['-all', '~all', '+all', '?all']):
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Incomplete",
                vulnerability="SPF record missing 'all' mechanism",
                risk_level=SpoofingRisk.HIGH,
                impact="Undefined behavior for unauthorized senders",
                recommendation="Add explicit 'all' mechanism (preferably -all)",
                technical_details=f"SPF Record: {spf_record}"
            ))
        
        # Check for overly permissive includes
        includes = re.findall(r'include:([^\s]+)', spf_record)
        if len(includes) > 5:
            vulnerabilities.append(SpoofingVulnerability(
                category="SPF Too Permissive",
                vulnerability=f"SPF record contains {len(includes)} include statements",
                risk_level=SpoofingRisk.MEDIUM,
                impact="Large attack surface with many authorized domains",
                recommendation="Review and minimize SPF includes to essential services only",
                technical_details=f"Includes: {', '.join(includes)}"
            ))
            
        return vulnerabilities
    
    def analyze_dmarc_spoofing_risk(self) -> List[SpoofingVulnerability]:
        """Analyze DMARC configuration for spoofing vulnerabilities"""
        vulnerabilities = []
        dmarc_domain = f"_dmarc.{self.domain}"
        dmarc_records = self.query_dns_record('TXT', dmarc_domain)
        dmarc_record = None
        
        # Find DMARC record
        for record in dmarc_records:
            if record.startswith('v=DMARC1'):
                dmarc_record = record
                break
        
        if not dmarc_record:
            vulnerabilities.append(SpoofingVulnerability(
                category="DMARC Missing",
                vulnerability="No DMARC record found",
                risk_level=SpoofingRisk.CRITICAL,
                impact="No policy enforcement against domain spoofing",
                recommendation="Implement DMARC policy starting with p=none, then escalate to p=reject",
                technical_details="Missing DMARC allows spoofing with no reporting"
            ))
            return vulnerabilities
        
        # Analyze DMARC policy
        policy_match = re.search(r'p=([^;]+)', dmarc_record)
        policy = policy_match.group(1) if policy_match else 'none'
        
        if policy == 'none':
            vulnerabilities.append(SpoofingVulnerability(
                category="DMARC Monitoring Only",
                vulnerability="DMARC policy set to 'none' (monitoring only)",
                risk_level=SpoofingRisk.HIGH,
                impact="Spoofed emails are not blocked, only reported",
                recommendation="Upgrade to p=quarantine or p=reject after monitoring period",
                technical_details=f"DMARC Record: {dmarc_record}"
            ))
        elif policy == 'quarantine':
            vulnerabilities.append(SpoofingVulnerability(
                category="DMARC Moderate Protection",
                vulnerability="DMARC policy set to 'quarantine'",
                risk_level=SpoofingRisk.MEDIUM,
                impact="Failed DMARC emails may reach spam folder",
                recommendation="Consider upgrading to p=reject for maximum protection",
                technical_details=f"DMARC Record: {dmarc_record}"
            ))
        
        # Check subdomain policy
        sp_match = re.search(r'sp=([^;]+)', dmarc_record)
        subdomain_policy = sp_match.group(1) if sp_match else policy
        
        if subdomain_policy in ['none', 'quarantine'] and policy == 'reject':
            vulnerabilities.append(SpoofingVulnerability(
                category="DMARC Subdomain Weakness",
                vulnerability=f"Subdomain policy weaker than main domain (sp={subdomain_policy})",
                risk_level=SpoofingRisk.MEDIUM,
                impact="Subdomains may be spoofed even if main domain is protected",
                recommendation="Set subdomain policy to match main domain protection level",
                technical_details=f"Main policy: {policy}, Subdomain policy: {subdomain_policy}"
            ))
        
        # Check percentage enforcement
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        percentage = int(pct_match.group(1)) if pct_match else 100
        
        if percentage < 100:
            vulnerabilities.append(SpoofingVulnerability(
                category="DMARC Partial Enforcement",
                vulnerability=f"DMARC policy applied to only {percentage}% of emails",
                risk_level=SpoofingRisk.MEDIUM,
                impact=f"{100-percentage}% of spoofed emails bypass DMARC enforcement",
                recommendation="Increase percentage to 100% for full protection",
                technical_details=f"Current enforcement: {percentage}%"
            ))
            
        return vulnerabilities
    
    def analyze_dkim_spoofing_risk(self) -> List[SpoofingVulnerability]:
        """Analyze DKIM configuration for spoofing vulnerabilities"""
        vulnerabilities = []
        selectors = ['default', 'selector1', 'selector2', 'google', 'k1', 's1', 's2']
        dkim_found = False
        weak_keys = []
        
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            dkim_records = self.query_dns_record('TXT', dkim_domain)
            
            for record in dkim_records:
                if 'v=DKIM1' in record or 'k=rsa' in record or 'p=' in record:
                    dkim_found = True
                    
                    # Check for weak key indicators
                    if 'k=rsa' in record:
                        # Extract key length if possible (simplified check)
                        if len(record) < 200:  # Very rough estimate for key strength
                            weak_keys.append(selector)
        
        if not dkim_found:
            vulnerabilities.append(SpoofingVulnerability(
                category="DKIM Missing",
                vulnerability="No DKIM records found",
                risk_level=SpoofingRisk.HIGH,
                impact="Emails cannot be cryptographically verified as authentic",
                recommendation="Implement DKIM signing with strong RSA keys (2048+ bits)",
                technical_details="Missing DKIM reduces email authentication strength"
            ))
        elif weak_keys:
            vulnerabilities.append(SpoofingVulnerability(
                category="DKIM Weak Keys",
                vulnerability=f"Potentially weak DKIM keys detected: {', '.join(weak_keys)}",
                risk_level=SpoofingRisk.MEDIUM,
                impact="Weak cryptographic keys may be compromised",
                recommendation="Use RSA keys of 2048 bits or stronger",
                technical_details=f"Weak selectors: {', '.join(weak_keys)}"
            ))
            
        return vulnerabilities
    
    def check_additional_spoofing_vectors(self) -> List[SpoofingVulnerability]:
        """Check for additional spoofing vulnerabilities"""
        vulnerabilities = []
        
        # Check for wildcard MX records (simplified)
        mx_records = self.query_dns_record('MX')
        for mx in mx_records:
            if '*' in mx:
                vulnerabilities.append(SpoofingVulnerability(
                    category="MX Wildcard Risk",
                    vulnerability="Wildcard MX record detected",
                    risk_level=SpoofingRisk.MEDIUM,
                    impact="May allow mail routing manipulation",
                    recommendation="Use specific MX hostnames instead of wildcards",
                    technical_details=f"Wildcard MX: {mx}"
                ))
        
        # Check for missing MX records
        if not mx_records:
            vulnerabilities.append(SpoofingVulnerability(
                category="MX Missing",
                vulnerability="No MX records found",
                risk_level=SpoofingRisk.LOW,
                impact="Domain cannot receive legitimate emails",
                recommendation="Configure MX records if domain should receive emails",
                technical_details="Domain appears to not handle email"
            ))
            
        return vulnerabilities
    
    def calculate_protection_score(self, vulnerabilities: List[SpoofingVulnerability]) -> int:
        """Calculate overall protection score (0-100)"""
        base_score = 100
        
        for vuln in vulnerabilities:
            if vuln.risk_level == SpoofingRisk.CRITICAL:
                base_score -= 30
            elif vuln.risk_level == SpoofingRisk.HIGH:
                base_score -= 20
            elif vuln.risk_level == SpoofingRisk.MEDIUM:
                base_score -= 10
            elif vuln.risk_level == SpoofingRisk.LOW:
                base_score -= 5
        
        return max(0, base_score)
    
    def determine_overall_risk(self, vulnerabilities: List[SpoofingVulnerability]) -> Tuple[SpoofingRisk, bool]:
        """Determine overall spoofing risk and spoofability"""
        critical_count = sum(1 for v in vulnerabilities if v.risk_level == SpoofingRisk.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.risk_level == SpoofingRisk.HIGH)
        
        if critical_count > 0:
            return SpoofingRisk.CRITICAL, True
        elif high_count >= 2:
            return SpoofingRisk.HIGH, True
        elif high_count == 1:
            return SpoofingRisk.MEDIUM, True
        else:
            medium_count = sum(1 for v in vulnerabilities if v.risk_level == SpoofingRisk.MEDIUM)
            if medium_count >= 3:
                return SpoofingRisk.MEDIUM, True
            elif medium_count >= 1:
                return SpoofingRisk.LOW, False
            else:
                return SpoofingRisk.VERY_LOW, False
    
    def get_all_records(self) -> Dict[str, List[str]]:
        """Gather all relevant DNS records"""
        records = {}
        
        # SPF Records
        txt_records = self.query_dns_record('TXT')
        spf_records = [r for r in txt_records if r.startswith('v=spf1')]
        if spf_records:
            records['SPF'] = spf_records
            
        # DMARC Records
        dmarc_records = self.query_dns_record('TXT', f'_dmarc.{self.domain}')
        dmarc_policy = [r for r in dmarc_records if r.startswith('v=DMARC1')]
        if dmarc_policy:
            records['DMARC'] = dmarc_policy
            
        # MX Records
        mx_records = self.query_dns_record('MX')
        if mx_records:
            records['MX'] = mx_records
            
        return records
    
    def analyze_domain(self) -> SpoofingAnalysis:
        """Perform comprehensive spoofing vulnerability analysis"""
        # Progress tracking
        analysis_steps = [
            "Analyzing SPF records",
            "Analyzing DMARC records", 
            "Analyzing DKIM records",
            "Checking additional vectors",
            "Calculating protection score"
        ]
        
        print(Colors.colorize(f"🔍 MX-Chan analyzing spoofing vulnerabilities for {self.domain}...", Colors.CYAN))
        print(Colors.colorize("🎯 Scanning email authentication mechanisms...\n", Colors.BLUE))
        
        vulnerabilities = []
        
        # Perform all vulnerability analyses with progress bar
        progress_bar = SimpleProgressBar(total=len(analysis_steps), desc="🔍 Analysis Progress")
        
        progress_bar.set_description("🔍 " + analysis_steps[0])
        vulnerabilities.extend(self.analyze_spf_spoofing_risk())
        progress_bar.update(1)
        
        progress_bar.set_description("🔍 " + analysis_steps[1])
        vulnerabilities.extend(self.analyze_dmarc_spoofing_risk())
        progress_bar.update(1)
        
        progress_bar.set_description("🔍 " + analysis_steps[2])
        vulnerabilities.extend(self.analyze_dkim_spoofing_risk())
        progress_bar.update(1)
        
        progress_bar.set_description("🔍 " + analysis_steps[3])
        vulnerabilities.extend(self.check_additional_spoofing_vectors())
        progress_bar.update(1)
        
        progress_bar.set_description("🔍 " + analysis_steps[4])
        protection_score = self.calculate_protection_score(vulnerabilities)
        progress_bar.update(1)
        
        # Calculate remaining metrics
        overall_risk, spoofable = self.determine_overall_risk(vulnerabilities)
        records_found = self.get_all_records()
        
        return SpoofingAnalysis(
            domain=self.domain,
            overall_risk=overall_risk,
            spoofable=spoofable,
            vulnerabilities=vulnerabilities,
            protection_score=protection_score,
            records_found=records_found
        )
    
    def print_banner(self):
        """Print MX-Chan spoofing analyzer banner with Rich formatting"""
        # ASCII art banner text
        banner_text = fr"""
⠄⠄⣼⡟⣿⠏⢀⣿⣇⣿⣏⣿⣿⣿⣿⣿⣿⣿⢸⡇⣿⣿⣿⣟⣿⣿⣿⣿
⡆⣸⡟⣼⣯⠏⣾⣿⢸⣿⢸⣿⣿⣿⣿⣿⣿⡟⠸⠁⢹⡿⣿⣿⢻⣿⣿⣿ 
⡇⡟⣸⢟⣫⡅⣶⢆⡶⡆⣿⣿⣿⣿⣿⢿⣛⠃⠰⠆⠈⠁⠈⠙⠈⠻⣿⢹  
⣧⣱⡷⣱⠿⠟⠛⠼⣇⠇⣿⣿⣿⣿⣿⣿⠃⣰⣿⣿⡆⠄⠄⠄⠄⠄⠉⠈  
⡏⡟⢑⠃⡠⠂⠄⠄⠈⣾⢻⣿⣿⡿⡹⡳⠋⠉⠁⠉⠙⠄⢀⠄⠄⠄⠄⠄  ░  ░░░░  ░░  ░░░░  ░░░      ░░░  ░░░░  ░░░      ░░░   ░░░  ░
⡇⠁⢈⢰⡇⠄⠄⡙⠂⣿⣿⣿⣿⣱⣿⡗⠄⠄⠄⢀⡀⠄⠈⢰⠄⠄⠄⠐  ▒   ▒▒   ▒▒▒  ▒▒  ▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒
⠄⠄⠘⣿⣧⠴⣄⣡⢄⣿⣿⣿⣷⣿⣿⡇⢀⠄⠤⠈⠁⣠⣠⣸⢠⠄⠄⠄  ▓        ▓▓▓▓    ▓▓▓▓  ▓▓▓▓▓▓▓▓        ▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓
⢀⠄⠄⣿⣿⣷⣬⣵⣿⣿⣿⣿⣿⣿⣿⣷⣟⢷⡶⢗⡰⣿⣿⠇⠘⠄⠄⠄  █  █  █  ███  ██  ███  ████  ██  ████  ██        ██  ██    █
⣿⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⡟⢀⠃⠄⢸⡄  █  ████  ██  ████  ███      ███  ████  ██  ████  ██  ███   █
⣿⠄⠄⠘⢿⣿⣿⣿⣿⣿⣿⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⢄⡆⠄⢀⣪⡆  
⡟⠄⠄⠄⠄⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣟⣻⣩⣾⣃⣴⣿⣿⡇  
"""
        
        panel = Panel(
            Align.left(
                Text(banner_text, style="magenta") +
                Text("\n\n🎯 Domain Spoofing Vulnerability Analyzer (◕‿◕)", style="bold red") +
                Text("\nSHUT UP and --------------> HACKKK", style="bold yellow") +
                Text("\nDetecting email spoofing attack vectors...", style="yellow") +
                Text("\nCreated by Max Muxammil", style="bold cyan") +
                Text("\nv2.0 - Enhanced with Rich Dashboard, Email Validation & Analysis\n", style="green")
            ),
            title="[bold cyan]MX-Chan Spoofing Analyzer[/bold cyan]",
            border_style="magenta",
            padding=(1, 2)
        )
        console.print(panel)
    
    def get_risk_color(self, risk_level: SpoofingRisk) -> str:
        """Get color for risk level"""
        colors = {
            SpoofingRisk.VERY_LOW: Colors.GREEN,
            SpoofingRisk.LOW: Colors.GREEN,
            SpoofingRisk.MEDIUM: Colors.YELLOW,
            SpoofingRisk.HIGH: Colors.MAGENTA,
            SpoofingRisk.CRITICAL: Colors.RED
        }
        return colors.get(risk_level, Colors.WHITE)
    
    def validate_email_format(self, email: str) -> Tuple[bool, str]:
        """Validate email format and extract domain"""
        try:
            parsed_name, parsed_email = parseaddr(email)
            if '@' not in parsed_email:
                return False, ""
            
            local, domain = parsed_email.split('@', 1)
            
            # Basic format validation
            if not local or not domain:
                return False, ""
            
            # Check for valid characters
            if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', parsed_email):
                return True, domain.lower()
            
            return False, ""
        except:
            return False, ""
    
    def test_smtp_connectivity(self, domain: str, timeout: int = 10) -> Tuple[bool, str, List[str]]:
        """Test SMTP server connectivity"""
        mx_records = self.query_dns_record('MX', domain)
        if not mx_records:
            return False, "No MX records found", []
        
        # Extract MX hostnames and priorities
        mx_servers = []
        for mx in mx_records:
            parts = mx.split()
            if len(parts) >= 2:
                priority = parts[0]
                hostname = parts[1].rstrip('.')
                mx_servers.append((int(priority), hostname))
        
        # Sort by priority (lowest first)
        mx_servers.sort()
        
        reachable_servers = []
        for priority, hostname in mx_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((hostname, 25))
                sock.close()
                
                if result == 0:
                    reachable_servers.append(f"{hostname}:25")
            except:
                continue
        
        if reachable_servers:
            return True, f"SMTP servers reachable: {', '.join(reachable_servers)}", reachable_servers
        else:
            return False, "No SMTP servers reachable on port 25", []
    
    def verify_email_existence(self, email: str, timeout: int = 10) -> Tuple[bool, str]:
        """Verify if email address exists (simplified check)"""
        try:
            domain = email.split('@')[1]
            mx_records = self.query_dns_record('MX', domain)
            
            if not mx_records:
                return False, "No MX records found for domain"
            
            # Get the primary MX server
            mx_servers = []
            for mx in mx_records:
                parts = mx.split()
                if len(parts) >= 2:
                    priority = int(parts[0])
                    hostname = parts[1].rstrip('.')
                    mx_servers.append((priority, hostname))
            
            mx_servers.sort()
            primary_mx = mx_servers[0][1] if mx_servers else None
            
            if not primary_mx:
                return False, "Could not determine primary MX server"
            
            # Simple SMTP connection test (without actually sending)
            try:
                with smtplib.SMTP(primary_mx, 25, timeout=timeout) as server:
                    server.ehlo()
                    # Note: Many servers don't allow VRFY anymore for security
                    # This is a basic connectivity test
                    return True, f"SMTP server {primary_mx} accepts connections"
            except smtplib.SMTPConnectError:
                return False, f"Cannot connect to SMTP server {primary_mx}"
            except smtplib.SMTPServerDisconnected:
                return False, f"SMTP server {primary_mx} disconnected"
            except Exception as e:
                return False, f"SMTP error: {str(e)}"
                
        except Exception as e:
            return False, f"Email verification error: {str(e)}"
    
    def validate_email_comprehensive(self, email: str) -> EmailValidationResult:
        """Perform comprehensive email validation"""
        validation_details = {}
        
        # Format validation
        is_valid_format, email_domain = self.validate_email_format(email)
        validation_details['format'] = "Valid format" if is_valid_format else "Invalid format"
        
        # Domain matching
        domain_matches = email_domain == self.domain if is_valid_format else False
        validation_details['domain_match'] = f"Email domain {'matches' if domain_matches else 'does not match'} target domain"
        
        # SMTP connectivity
        smtp_reachable = False
        smtp_details = "Not tested due to format issues"
        if is_valid_format:
            smtp_reachable, smtp_details, _ = self.test_smtp_connectivity(email_domain)
        validation_details['smtp'] = smtp_details
        
        # Email existence
        email_exists = False
        existence_details = "Not tested due to format issues"
        if is_valid_format:
            email_exists, existence_details = self.verify_email_existence(email)
        validation_details['existence'] = existence_details
        
        return EmailValidationResult(
            email=email,
            is_valid_format=is_valid_format,
            domain_matches=domain_matches,
            smtp_reachable=smtp_reachable,
            email_exists=email_exists,
            validation_details=validation_details
        )
    
    def print_email_validation_report(self, validation: EmailValidationResult):
        """Print email validation report"""
        print(f"\n{Colors.colorize('📧 EMAIL VALIDATION REPORT', Colors.BOLD + Colors.BLUE)}")
        print(Colors.colorize("="*80, Colors.BLUE))
        print(f"📧 {Colors.colorize('Email Address:', Colors.BOLD)} {Colors.colorize(validation.email, Colors.CYAN)}")
        
        # Format validation
        format_color = Colors.GREEN if validation.is_valid_format else Colors.RED
        format_status = "✅ VALID" if validation.is_valid_format else "❌ INVALID"
        print(f"📝 {Colors.colorize('Format:', Colors.BOLD)} {Colors.colorize(format_status, Colors.BOLD + format_color)}")
        
        # Domain matching
        domain_color = Colors.GREEN if validation.domain_matches else Colors.YELLOW
        domain_status = "✅ MATCHES" if validation.domain_matches else "⚠️ DIFFERENT"
        print(f"🌐 {Colors.colorize('Domain Match:', Colors.BOLD)} {Colors.colorize(domain_status, Colors.BOLD + domain_color)}")
        
        # SMTP connectivity
        smtp_color = Colors.GREEN if validation.smtp_reachable else Colors.RED
        smtp_status = "✅ REACHABLE" if validation.smtp_reachable else "❌ UNREACHABLE"
        print(f"📬 {Colors.colorize('SMTP Server:', Colors.BOLD)} {Colors.colorize(smtp_status, Colors.BOLD + smtp_color)}")
        
        # Email existence
        exists_color = Colors.GREEN if validation.email_exists else Colors.RED
        exists_status = "✅ EXISTS" if validation.email_exists else "❓ UNKNOWN"
        print(f"🔍 {Colors.colorize('Email Exists:', Colors.BOLD)} {Colors.colorize(exists_status, Colors.BOLD + exists_color)}")
        
        # Detailed information
        print(f"\n{Colors.colorize('📋 VALIDATION DETAILS', Colors.BOLD + Colors.BLUE)}")
        print(Colors.colorize("-"*60, Colors.BLUE))
        for key, detail in validation.validation_details.items():
            print(f"   {Colors.colorize('•', Colors.CYAN)} {Colors.colorize(key.title()+':', Colors.BOLD)} {detail}")
    
    def print_analysis_report(self, analysis: SpoofingAnalysis):
        """Print comprehensive spoofing analysis report"""
        # Don't print banner again - it's already shown in main()
        
        risk_color = self.get_risk_color(analysis.overall_risk)
        spoofable_status = "SPOOFABLE" if analysis.spoofable else "PROTECTED"
        spoofable_color = Colors.RED if analysis.spoofable else Colors.GREEN
        
        print(Colors.colorize("="*80, Colors.BLUE))
        print(Colors.colorize("🎯 DOMAIN SPOOFING VULNERABILITY REPORT", Colors.BOLD + Colors.BLUE))
        print(Colors.colorize("="*80, Colors.BLUE))
        print(f"🌐 {Colors.colorize('Target Domain:', Colors.BOLD)} {Colors.colorize(analysis.domain, Colors.CYAN)}")
        print(f"🚨 {Colors.colorize('Spoofing Risk:', Colors.BOLD)} {Colors.colorize(analysis.overall_risk.value.upper(), Colors.BOLD + risk_color)}")
        print(f"🎯 {Colors.colorize('Domain Status:', Colors.BOLD)} {Colors.colorize(spoofable_status, Colors.BOLD + spoofable_color)}")
        print(f"🛡️ {Colors.colorize('Protection Score:', Colors.BOLD)} {Colors.colorize(f'{analysis.protection_score}/100', Colors.CYAN)}")
        print(f"🔍 {Colors.colorize('Vulnerabilities Found:', Colors.BOLD)} {Colors.colorize(str(len(analysis.vulnerabilities)), Colors.YELLOW)}")
        print(Colors.colorize("="*80, Colors.BLUE))
        
        if analysis.vulnerabilities:
            print(f"\n{Colors.colorize('🚨 DISCOVERED VULNERABILITIES', Colors.BOLD + Colors.RED)}")
            print(Colors.colorize("="*80, Colors.BLUE))
            
            for i, vuln in enumerate(analysis.vulnerabilities, 1):
                vuln_color = self.get_risk_color(vuln.risk_level)
                
                # Risk level icons
                risk_icons = {
                    SpoofingRisk.VERY_LOW: "✅",
                    SpoofingRisk.LOW: "✅", 
                    SpoofingRisk.MEDIUM: "⚠️",
                    SpoofingRisk.HIGH: "🔶",
                    SpoofingRisk.CRITICAL: "🚨"
                }
                icon = risk_icons.get(vuln.risk_level, "❓")
                
                print(f"\n{Colors.colorize(f'{i}.', Colors.CYAN)} {icon} {Colors.colorize(f'[{vuln.risk_level.value.upper()}]', Colors.BOLD + vuln_color)} {Colors.colorize(vuln.category, Colors.BOLD)}")
                print(f"   🎯 {Colors.colorize('Vulnerability:', Colors.BOLD)} {vuln.vulnerability}")
                print(f"   💥 {Colors.colorize('Impact:', Colors.BOLD)} {vuln.impact}")
                print(f"   🔧 {Colors.colorize('Recommendation:', Colors.BOLD)} {Colors.colorize(vuln.recommendation, Colors.CYAN)}")
                print(f"   🔍 {Colors.colorize('Technical Details:', Colors.BOLD)} {vuln.technical_details}")
                print(Colors.colorize("-" * 60, Colors.BLUE))
        else:
            print(f"\n{Colors.colorize('✅ No critical spoofing vulnerabilities detected!', Colors.GREEN)}")
        
        # Show email validation results if available
        if analysis.email_validation:
            self.print_email_validation_report(analysis.email_validation)
        
        # Show discovered records
        if analysis.records_found:
            print(f"\n{Colors.colorize('📋 AUTHENTICATION RECORDS FOUND', Colors.BOLD + Colors.BLUE)}")
            print(Colors.colorize("="*80, Colors.BLUE))
            
            for record_type, records in analysis.records_found.items():
                print(f"\n{Colors.colorize(f'{record_type} Records:', Colors.BOLD + Colors.GREEN)}")
                for record in records:
                    print(f"   {Colors.colorize('•', Colors.CYAN)} {Colors.colorize(record, Colors.WHITE)}")
        
        # Summary and recommendations
        print(f"\n{Colors.colorize('📊 SPOOFING ANALYSIS SUMMARY', Colors.BOLD + Colors.BLUE)}")
        print(Colors.colorize("="*80, Colors.BLUE))
        
        if analysis.spoofable:
            print(f"{Colors.colorize('🚨 WARNING:', Colors.BOLD + Colors.RED)} This domain is vulnerable to email spoofing attacks!")
            print(f"{Colors.colorize('⚡ Immediate Action Required:', Colors.BOLD + Colors.YELLOW)} Implement missing email authentication mechanisms")
        else:
            print(f"{Colors.colorize('✅ GOOD:', Colors.BOLD + Colors.GREEN)} This domain has reasonable protection against spoofing")
            print(f"{Colors.colorize('🔍 Continuous Monitoring:', Colors.BOLD + Colors.CYAN)} Regular security reviews recommended")
        
        print(f"\n{Colors.colorize('✨ MX-Chan spoofing analysis completed for', Colors.GREEN)} {Colors.colorize(analysis.domain, Colors.BOLD + Colors.CYAN)}")
        print(Colors.colorize("🎯 Remember: Strong email authentication prevents domain spoofing! (◕‿◕)", Colors.YELLOW))
        print(Colors.colorize("🛡️ Stay secure and keep those spoofing attacks away! ~(＾◡＾)~", Colors.MAGENTA))

class CustomHelpFormatter(argparse.HelpFormatter):
    def format_help(self):
        # Create Rich banner for help
        banner_text = fr"""
⠄⠄⣼⡟⣿⠏⢀⣿⣇⣿⣏⣿⣿⣿⣿⣿⣿⣿⢸⡇⣿⣿⣿⣟⣿⣿⣿⣿
⡆⣸⡟⣼⣯⠏⣾⣿⢸⣿⢸⣿⣿⣿⣿⣿⣿⡟⠸⠁⢹⡿⣿⣿⢻⣿⣿⣿ 
⡇⡟⣸⢟⣫⡅⣶⢆⡶⡆⣿⣿⣿⣿⣿⢿⣛⠃⠰⠆⠈⠁⠈⠙⠈⠻⣿⢹  
⣧⣱⡷⣱⠿⠟⠛⠼⣇⠇⣿⣿⣿⣿⣿⣿⠃⣰⣿⣿⡆⠄⠄⠄⠄⠄⠉⠈  
⡏⡟⢑⠃⡠⠂⠄⠄⠈⣾⢻⣿⣿⡿⡹⡳⠋⠉⠁⠉⠙⠄⢀⠄⠄⠄⠄⠄  ░  ░░░░  ░░  ░░░░  ░░░      ░░░  ░░░░  ░░░      ░░░   ░░░  ░
⡇⠁⢈⢰⡇⠄⠄⡙⠂⣿⣿⣿⣿⣱⣿⡗⠄⠄⠄⢀⡀⠄⠈⢰⠄⠄⠄⠐  ▒   ▒▒   ▒▒▒  ▒▒  ▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒
⠄⠄⠘⣿⣧⠴⣄⣡⢄⣿⣿⣿⣷⣿⣿⡇⢀⠄⠤⠈⠁⣠⣠⣸⢠⠄⠄⠄  ▓        ▓▓▓▓    ▓▓▓▓  ▓▓▓▓▓▓▓▓        ▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓
⢀⠄⠄⣿⣿⣷⣬⣵⣿⣿⣿⣿⣿⣿⣿⣷⣟⢷⡶⢗⡰⣿⣿⠇⠘⠄⠄⠄  █  █  █  ███  ██  ███  ████  ██  ████  ██        ██  ██    █
⣿⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⡟⢀⠃⠄⢸⡄  █  ████  ██  ████  ███      ███  ████  ██  ████  ██  ███   █
⣿⠄⠄⠘⢿⣿⣿⣿⣿⣿⣿⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⢄⡆⠄⢀⣪⡆  
⡟⠄⠄⠄⠄⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣟⣻⣩⣾⣃⣴⣿⣿⡇  
"""

        panel = Panel(
            Align.left(
                Text(banner_text, style="magenta") +
                Text("\n🎯 Domain Spoofing Vulnerability Analyzer (◕‿◕)", style="bold red") +
                Text("\nSHUT UP and --------------> HACKKK", style="bold yellow") +
                Text("\nDetecting email spoofing attack vectors...", style="yellow") +
                Text("\nCreated by Max Muxammil", style="bold cyan") +
                Text("\nv1.0 - Enhanced with Rich Dashboard, Email Validation & Analysis\n", style="green")
            ),
            title="[bold cyan]MX-Chan Spoofing Analyzer[/bold cyan]",
            border_style="magenta",
            padding=(1, 2)
        )
        console.print(panel)
        return super().format_help()

def main():
    parser = argparse.ArgumentParser(
        description='MX-Chan - Domain Spoofing Vulnerability Analyzer',
        formatter_class=CustomHelpFormatter
    )
    parser.add_argument('domain', help='Domain to analyze for spoofing vulnerabilities')
    parser.add_argument('--email', '-e', help='Email address to validate (optional)')
    parser.add_argument('--debug', '-d', action='store_true', help='Enable debug output')
    
    # Check if this is a help request before printing banner
    if len(sys.argv) > 1 and ('-h' in sys.argv or '--help' in sys.argv):
        args = parser.parse_args()
        return
    
    # Print banner immediately when script starts (but not for help)
    banner_text = fr"""
⠄⠄⣼⡟⣿⠏⢀⣿⣇⣿⣏⣿⣿⣿⣿⣿⣿⣿⢸⡇⣿⣿⣿⣟⣿⣿⣿⣿
⡆⣸⡟⣼⣯⠏⣾⣿⢸⣿⢸⣿⣿⣿⣿⣿⣿⡟⠸⠁⢹⡿⣿⣿⢻⣿⣿⣿ 
⡇⡟⣸⢟⣫⡅⣶⢆⡶⡆⣿⣿⣿⣿⣿⢿⣛⠃⠰⠆⠈⠁⠈⠙⠈⠻⣿⢹  
⣧⣱⡷⣱⠿⠟⠛⠼⣇⠇⣿⣿⣿⣿⣿⣿⠃⣰⣿⣿⡆⠄⠄⠄⠄⠄⠉⠈  
⡏⡟⢑⠃⡠⠂⠄⠄⠈⣾⢻⣿⣿⡿⡹⡳⠋⠉⠁⠉⠙⠄⢀⠄⠄⠄⠄⠄  ░  ░░░░  ░░  ░░░░  ░░░      ░░░  ░░░░  ░░░      ░░░   ░░░  ░
⡇⠁⢈⢰⡇⠄⠄⡙⠂⣿⣿⣿⣿⣱⣿⡗⠄⠄⠄⢀⡀⠄⠈⢰⠄⠄⠄⠐  ▒   ▒▒   ▒▒▒  ▒▒  ▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒    ▒▒  ▒
⠄⠄⠘⣿⣧⠴⣄⣡⢄⣿⣿⣿⣷⣿⣿⡇⢀⠄⠤⠈⠁⣠⣠⣸⢠⠄⠄⠄  ▓        ▓▓▓▓    ▓▓▓▓  ▓▓▓▓▓▓▓▓        ▓▓  ▓▓▓▓  ▓▓  ▓  ▓  ▓
⢀⠄⠄⣿⣿⣷⣬⣵⣿⣿⣿⣿⣿⣿⣿⣷⣟⢷⡶⢗⡰⣿⣿⠇⠘⠄⠄⠄  █  █  █  ███  ██  ███  ████  ██  ████  ██        ██  ██    █
⣿⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣾⣿⣿⡟⢀⠃⠄⢸⡄  █  ████  ██  ████  ███      ███  ████  ██  ████  ██  ███   █
⣿⠄⠄⠘⢿⣿⣿⣿⣿⣿⣿⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⢄⡆⠄⢀⣪⡆  
⡟⠄⠄⠄⠄⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣟⣻⣩⣾⣃⣴⣿⣿⡇  
"""

    panel = Panel(
        Align.left(
            Text(banner_text, style="magenta") +
            Text("\n\n🎯 Domain Spoofing Vulnerability Analyzer (◕‿◕)", style="bold red") +
            Text("\nSHUT UP and --------------> HACKKK", style="bold yellow") +
            Text("\nDetecting email spoofing attack vectors...", style="yellow") +
            Text("\nCreated by Max Muxammil", style="bold cyan") +
            Text("\nv1.0 - Enhanced with Rich Dashboard, Email Validation & Analysis\n", style="green")
        ),
        title="[bold cyan]MX-Chan Spoofing Analyzer[/bold cyan]",
        border_style="magenta",
        padding=(1, 2)
    )
    console.print(panel)
    
    args = parser.parse_args()
    
    if not args.domain:
        print(Colors.colorize("❌ Error: Domain is required", Colors.RED))
        sys.exit(1)
    
    analyzer = MXChanSpoofingAnalyzer(args.domain, debug=args.debug)
    analysis = analyzer.analyze_domain()
    
    # Add email validation if provided
    if args.email:
        print(f"\n{Colors.colorize('📧 Performing email validation...', Colors.CYAN)}")
        email_validation = analyzer.validate_email_comprehensive(args.email)
        analysis.email_validation = email_validation
    
    analyzer.print_analysis_report(analysis)

if __name__ == "__main__":
    main()