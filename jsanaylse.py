#!/usr/bin/env python3
"""
██████╗ ███████╗ █████╗ ███╗   ██╗██╗   ██╗███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗████╗  ██║╚██╗ ██╔╝██╔════╝██╔══██╗
██████╔╝███████╗███████║██╔██╗ ██║ ╚████╔╝ ███████╗██████╔╝
██╔══██╗╚════██║██╔══██║██║╚██╗██║  ╚██╔╝  ╚════██║██╔══██╗
██████╔╝███████║██║  ██║██║ ╚████║   ██║   ███████║██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                  JS Analyzer Pro v3.0 - Ultimate Edition
"""

import re
import json
import requests
import argparse
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import hashlib
import base64
from collections import defaultdict
import sys
from colorama import init, Fore, Style, Back
import os
import time
import subprocess
import mmap
import gzip
import zlib
from typing import Dict, List, Set, Tuple, Optional
import logging
from datetime import datetime
import ipaddress
import dns.resolver
import ssl
import socket
from dataclasses import dataclass, field
from enum import Enum

# Initialize colorama
init(autoreset=True)

class Severity(Enum):
    CRITICAL = "🔴 CRITICAL"
    HIGH = "🟠 HIGH"
    MEDIUM = "🟡 MEDIUM"
    LOW = "🔵 LOW"
    INFO = "⚪ INFO"

class FindingType(Enum):
    API_ENDPOINT = "API Endpoint"
    SENSITIVE_KEY = "Sensitive Key"
    AUTH_TOKEN = "Auth Token"
    CRYPTO = "Crypto Operation"
    XSS = "XSS Vulnerability"
    SQL_INJECTION = "SQL Injection"
    CODE_EXECUTION = "Code Execution"
    PATH_TRAVERSAL = "Path Traversal"
    CSRF = "CSRF Vulnerability"
    CORS = "CORS Misconfiguration"
    WEAK_CRYPTO = "Weak Cryptography"
    BUSINESS_LOGIC = "Business Logic"
    OT_2FA = "OTP/2FA Logic"
    PAYMENT = "Payment Processing"
    ADMIN = "Admin Function"
    DEBUG = "Debug Information"
    WEBHOOK = "Webhook URL"
    CLOUD_RESOURCE = "Cloud Resource"
    INTERNAL_IP = "Internal IP"
    EMAIL = "Email Address"
    DOM_SINK = "DOM Sink"
    AJAX_CALL = "AJAX Call"
    WEBSOCKET = "WebSocket"
    GRAPHQL = "GraphQL"
    SWAGGER = "Swagger/OpenAPI"
    RATE_LIMIT = "Rate Limiting"
    CACHE = "Cache Control"
    SECURITY_HEADER = "Security Header"
    SUBDOMAIN = "Subdomain"

@dataclass
class Finding:
    type: FindingType
    severity: Severity
    file: str
    match: str
    value: str
    line: int
    context: str
    confidence: float
    remediation: str
    metadata: Dict = field(default_factory=dict)

class UltimateJSAnalyzer:
    def __init__(self, verbose=False, output_file=None, timeout=15, threads=20, max_size=10*1024*1024):
        self.verbose = verbose
        self.output_file = output_file
        self.timeout = timeout
        self.threads = threads
        self.max_size = max_size
        self.findings: List[Finding] = []
        self.analyzed_files: Set[str] = set()
        self.failed_urls: List[str] = []
        self.start_time = datetime.now()
        
        # Session setup
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/javascript, */*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        
        # Advanced patterns with context capture
        self.patterns = {
            FindingType.API_ENDPOINT: [
                (r'["\'](?:/api/|/v\d+/|/rest/|/graphql|/oauth|/auth|/service/|/ws/|/websocket/)([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'url\s*[:=]\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'endpoint\s*[:=]\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'base(?:URL|Url)\s*[:=]\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'API_(?:BASE|ROOT|URL)\s*=\s*["\']([^"\']+)["\']', Severity.MEDIUM),
            ],
            
            FindingType.SENSITIVE_KEY: [
                (r'["\'](?:api[_-]?key|apikey|api_key|client[_-]?id|clientid)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:secret|SECRET|secret_key|secretKey|private_key|privateKey)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:aws|s3|azure|gcp|google|firebase)[_-]?(?:key|secret|token)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:stripe|paypal|braintree|square|razorpay|paytm)[_-]?(?:key|secret|token)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:jwt|JWT)[_-]?(?:secret|key)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:oauth|OAuth)[_-]?(?:client|secret|token)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:github|gitlab|bitbucket)[_-]?(?:token|key)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:slack|discord|telegram|whatsapp)[_-]?(?:webhook|token|key)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:twilio|sendgrid|mailgun|ses)[_-]?(?:key|token|secret)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
                (r'["\'](?:cloudflare|cloudfront|fastly)[_-]?(?:key|token)["\']\s*[:=]\s*["\']([^"\']{8,})["\']', Severity.CRITICAL),
            ],
            
            FindingType.AUTH_TOKEN: [
                (r'Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+)', Severity.CRITICAL),
                (r'Authorization["\']?\s*[:=]\s*["\']?Bearer\s+([A-Za-z0-9\-_=]{20,})', Severity.HIGH),
                (r'["\'](?:token|jwt|accessToken|refreshToken)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_=]{20,})["\']', Severity.HIGH),
                (r'["\'](?:session|sid|sessionId)["\']\s*[:=]\s*["\']([A-Fa-f0-9]{16,})["\']', Severity.HIGH),
                (r'["\'](?:csrf|xsrf|x-csrf)["\']\s*[:=]\s*["\']([A-Za-z0-9\-_=]{16,})["\']', Severity.MEDIUM),
            ],
            
            FindingType.XSS: [
                (r'document\.write\s*\(\s*[^()]*\)', Severity.CRITICAL),
                (r'innerHTML\s*=\s*(?:[^;]+|\$\([^)]+\))', Severity.CRITICAL),
                (r'outerHTML\s*=\s*(?:[^;]+|\$\([^)]+\))', Severity.CRITICAL),
                (r'insertAdjacentHTML\s*\(', Severity.CRITICAL),
                (r'\$\.(?:html|append|prepend|after|before)\s*\(', Severity.HIGH),
                (r'\.html\s*\(\s*[^)]*\)', Severity.HIGH),
                (r'setTimeout\s*\(\s*["\']([^"\']+)["\']', Severity.HIGH),
                (r'setInterval\s*\(\s*["\']([^"\']+)["\']', Severity.HIGH),
                (r'location\.href\s*=\s*[^;]+', Severity.HIGH),
                (r'location\.(?:replace|assign)\s*\(\s*[^)]*\)', Severity.HIGH),
                (r'window\.open\s*\(\s*[^)]*\)', Severity.MEDIUM),
                (r'postMessage\s*\(\s*[^,)]*,\s*["\']\*["\']', Severity.CRITICAL),
            ],
            
            FindingType.SQL_INJECTION: [
                (r'\.(?:query|execute|exec|prepare)\s*\(\s*["\']([^"\']*?(?:\+|\$|#|%)[^"\']*?)["\']', Severity.CRITICAL),
                (r'new\s+SQL\(["\']([^"\']*?(?:\+|\$|#|%)[^"\']*?)["\']', Severity.CRITICAL),
                (r'\.(?:find|findOne|update|insert|delete|remove)\s*\(\s*\{[^}]*?(?:\+|\$|#|%)[^}]*?\}', Severity.HIGH),
            ],
            
            FindingType.CODE_EXECUTION: [
                (r'eval\s*\(', Severity.CRITICAL),
                (r'new\s+Function\s*\(', Severity.CRITICAL),
                (r'setTimeout\s*\(\s*[^,)]*?\)', Severity.HIGH),
                (r'setInterval\s*\(\s*[^,)]*?\)', Severity.HIGH),
                (r'exec\s*\(\s*["\']([^"\']*?)(?:\+|\$)[^"\']*?["\']', Severity.CRITICAL),
                (r'spawn\s*\(\s*["\']([^"\']*?)(?:\+|\$)[^"\']*?["\']', Severity.CRITICAL),
            ],
            
            FindingType.CRYPTO: [
                (r'CryptoJS\.(?:AES|DES|TripleDES|Rabbit|RC4)\.(?:encrypt|decrypt)', Severity.HIGH),
                (r'(?:encrypt|decrypt)\s*\(\s*[^,)]*,\s*["\']([^"\']{8,})["\']', Severity.HIGH),
                (r'crypto\.(?:createCipher|createDecipher|createHash|createHmac)', Severity.MEDIUM),
                (r'new\s+(?:CryptoJS|forge)\.', Severity.MEDIUM),
                (r'atob\s*\(\s*[^)]*\)', Severity.LOW),
                (r'btoa\s*\(\s*[^)]*\)', Severity.LOW),
            ],
            
            FindingType.WEAK_CRYPTO: [
                (r'CryptoJS\.(?:DES|Rabbit|RC4|TripleDES)', Severity.CRITICAL),
                (r'crypto\.createCipher\s*\(\s*["\'](?:des|rc4|bf|blowfish)["\']', Severity.CRITICAL),
                (r'md5\s*\(', Severity.HIGH),
                (r'sha1\s*\(', Severity.HIGH),
            ],
            
            FindingType.BUSINESS_LOGIC: [
                (r'function\s+(?:login|signin|authenticate|verify|validate)\s*\(', Severity.HIGH),
                (r'function\s+(?:register|signup|createUser)\s*\(', Severity.HIGH),
                (r'function\s+(?:resetPassword|forgotPassword|changePassword)\s*\(', Severity.CRITICAL),
                (r'function\s+(?:pay|payment|checkout|processPayment|charge)\s*\(', Severity.CRITICAL),
                (r'function\s+(?:transfer|send|withdraw|deposit)\s*\(', Severity.CRITICAL),
                (r'function\s+(?:upload|uploadFile|uploadImage|uploadDocument)\s*\(', Severity.HIGH),
                (r'function\s+(?:delete|remove|destroy|purge)\s*\(', Severity.HIGH),
                (r'function\s+(?:admin|superuser|root|sudo)\s*\(', Severity.CRITICAL),
                (r'function\s+(?:otp|sendOTP|verifyOTP|generateOTP)\s*\(', Severity.HIGH),
                (r'function\s+(?:2fa|twoFactor|multiFactor)\s*\(', Severity.HIGH),
                (r'function\s+(?:captcha|verifyCaptcha|solveCaptcha)\s*\(', Severity.MEDIUM),
                (r'function\s+(?:export|import|migrate|backup|restore)\s*\(', Severity.HIGH),
            ],
            
            FindingType.ADMIN: [
                (r'["\']/admin(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/dashboard(?:/|$)["\']', Severity.HIGH),
                (r'["\']/console(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/manager(?:/|$)["\']', Severity.HIGH),
                (r'["\']/supervisor(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/control(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/root(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/internal(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/private(?:/|$)["\']', Severity.CRITICAL),
                (r'["\']/beta(?:/|$)["\']', Severity.HIGH),
                (r'["\']/staging(?:/|$)["\']', Severity.HIGH),
                (r'["\']/dev(?:/|$)["\']', Severity.HIGH),
                (r'["\']/test(?:/|$)["\']', Severity.HIGH),
            ],
            
            FindingType.DEBUG: [
                (r'console\.(?:log|debug|info|warn|error|trace|dir|table)\s*\(', Severity.LOW),
                (r'debugger;', Severity.HIGH),
                (r'//.*?(?:TODO|FIXME|HACK|BUG|XXX|NOTE|SECURITY)', Severity.MEDIUM),
                (r'alert\s*\(', Severity.LOW),
                (r'window\.alert\s*\(', Severity.LOW),
            ],
            
            FindingType.WEBHOOK: [
                (r'webhook[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', Severity.CRITICAL),
                (r'hook[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', Severity.CRITICAL),
                (r'callback[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', Severity.CRITICAL),
                (r'notify[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', Severity.CRITICAL),
            ],
            
            FindingType.CLOUD_RESOURCE: [
                (r's3\.amazonaws\.com/([^\s"\'?&#]*)', Severity.HIGH),
                (r'[A-Za-z0-9-]+\.s3\.amazonaws\.com', Severity.HIGH),
                (r'firebaseio\.com/([^\s"\'?&#]*)', Severity.HIGH),
                (r'[A-Za-z0-9-]+\.firebaseio\.com', Severity.HIGH),
                (r'cloudfront\.net/([^\s"\'?&#]*)', Severity.HIGH),
                (r'azure(?:cdn|static|blob|files)\.net/([^\s"\'?&#]*)', Severity.HIGH),
                (r'googleapis\.com/([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'herokuapp\.com/([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'vercel\.app/([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'netlify\.app/([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'digitalocean\.com/([^\s"\'?&#]*)', Severity.MEDIUM),
                (r'[A-Za-z0-9-]+\.(?:onrender|render)\.com', Severity.MEDIUM),
            ],
            
            FindingType.INTERNAL_IP: [
                (r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})', Severity.HIGH),
                (r'(?:172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})', Severity.HIGH),
                (r'(?:192\.168\.\d{1,3}\.\d{1,3})', Severity.HIGH),
                (r'(?:127\.0\.0\.1|localhost)', Severity.MEDIUM),
                (r'(?:0\.0\.0\.0)', Severity.MEDIUM),
            ],
            
            FindingType.EMAIL: [
                (r'[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Z|a-z]{2,}', Severity.MEDIUM),
            ],
            
            FindingType.DOM_SINK: [
                (r'document\.(?:write|writeln)\s*\(', Severity.CRITICAL),
                (r'(?:innerHTML|outerHTML)\s*=', Severity.CRITICAL),
                (r'insertAdjacent(?:HTML|Text|Element)\s*\(', Severity.CRITICAL),
                (r'(?:document|element)\.(?:appendChild|insertBefore|replaceChild)\s*\(', Severity.HIGH),
            ],
            
            FindingType.AJAX_CALL: [
                (r'fetch\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'\$\.(?:get|post|ajax|put|delete|patch|jsonp)\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'axios\.(?:get|post|put|delete|patch|request|head|options)\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'XMLHttpRequest\s*\(\s*\)', Severity.LOW),
                (r'superagent\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'request\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
                (r'http\.(?:get|request)\s*\(\s*["\']([^"\']+)["\']', Severity.LOW),
            ],
            
            FindingType.WEBSOCKET: [
                (r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', Severity.MEDIUM),
                (r'ws:\/\/[^\s"\'?&#]+', Severity.MEDIUM),
                (r'wss:\/\/[^\s"\'?&#]+', Severity.MEDIUM),
            ],
            
            FindingType.GRAPHQL: [
                (r'graphql[_-]?(?:url|endpoint|uri)\s*[:=]\s*["\']([^"\']+)["\']', Severity.HIGH),
                (r'graphql\s*:\s*["\']([^"\']+)["\']', Severity.HIGH),
                (r'query\s*{\s*[^}]*}', Severity.MEDIUM),
                (r'mutation\s*{\s*[^}]*}', Severity.MEDIUM),
            ],
            
            FindingType.SWAGGER: [
                (r'["\']/(?:swagger|openapi|api-docs|api-documentation)[^\s"\'?&#]*["\']', Severity.HIGH),
                (r'swagger\s*[:=]\s*["\']([^"\']+)["\']', Severity.HIGH),
                (r'openapi\s*[:=]\s*["\']([^"\']+)["\']', Severity.HIGH),
            ],
            
            FindingType.PATH_TRAVERSAL: [
                (r'\.\./\.\./[^\s"\'?&#]+', Severity.CRITICAL),
                (r'\.\.\/[^\s"\'?&#]+', Severity.CRITICAL),
                (r'\.\.\\[^\s"\'?&#]+', Severity.CRITICAL),
            ],
            
            FindingType.CSRF: [
                (r'csrf[_-]?(?:token|key)\s*[:=]\s*["\']([^"\']+)["\']', Severity.MEDIUM),
                (r'xsrf[_-]?(?:token|key)\s*[:=]\s*["\']([^"\']+)["\']', Severity.MEDIUM),
                (r'X-CSRF-TOKEN', Severity.MEDIUM),
            ],
            
            FindingType.CORS: [
                (r'credentials\s*[:=]\s*["\']include["\']', Severity.HIGH),
                (r'withCredentials\s*[:=]\s*true', Severity.HIGH),
                (r'Access-Control-Allow-Origin\s*[:=]\s*["\']\*["\']', Severity.HIGH),
                (r'Access-Control-Allow-Credentials\s*[:=]\s*["\']true["\']', Severity.HIGH),
            ],
        }
        
        # Additional analysis rules
        self.context_rules = {
            'contains_user_input': re.compile(r'(?:req|request|body|params|query|headers)\s*\.'),
            'contains_sanitization': re.compile(r'(?:escape|sanitize|validate|filter|clean)\s*\(', re.IGNORECASE),
            'contains_dangerous': re.compile(r'(?:password|secret|token|key|credential|auth)', re.IGNORECASE),
        }

    def log(self, message, level="INFO", color=Fore.CYAN):
        """Enhanced logging with colors"""
        if self.verbose or level in ["SUCCESS", "ERROR", "CRITICAL", "FINDING"]:
            timestamp = datetime.now().strftime("%H:%M:%S")
            colors = {
                "INFO": Fore.CYAN,
                "SUCCESS": Fore.GREEN,
                "WARNING": Fore.YELLOW,
                "ERROR": Fore.RED,
                "CRITICAL": Fore.MAGENTA,
                "FINDING": Fore.GREEN,
                "PROGRESS": Fore.BLUE
            }
            print(f"{Fore.WHITE}[{timestamp}]{Style.RESET_ALL} {colors.get(level, Fore.WHITE)}[{level}]{Style.RESET_ALL} {message}")

    def remove_comments(self, content):
        """Advanced comment removal with context preservation"""
        # Remove single line comments but preserve line numbers
        content = re.sub(r'//.*?$', ' ', content, flags=re.MULTILINE)
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', ' ', content, flags=re.DOTALL)
        return content

    def get_context(self, content, position, window=100):
        """Extract context around a finding"""
        start = max(0, position - window)
        end = min(len(content), position + window)
        context = content[start:end]
        # Clean up context
        context = context.replace('\n', ' ').replace('\r', ' ')
        return context

    def calculate_confidence(self, match, finding_type):
        """Calculate confidence score for a finding"""
        confidence = 0.8  # Base confidence
        
        # Boost confidence based on patterns
        if finding_type == FindingType.SENSITIVE_KEY:
            if re.search(r'(?:key|secret|token|password)', match, re.IGNORECASE):
                confidence += 0.1
            if re.search(r'[A-Za-z0-9]{16,}', match):
                confidence += 0.05
        
        elif finding_type == FindingType.XSS:
            if re.search(r'(?:innerHTML|document\.write|eval)', match):
                confidence += 0.1
            if re.search(r'(?:\+|concat|join)', match):
                confidence += 0.05
        
        elif finding_type == FindingType.AUTH_TOKEN:
            if re.search(r'[A-Za-z0-9\-_=]{32,}', match):
                confidence += 0.1
            if re.search(r'\.', match):
                confidence += 0.05
        
        # Check for false positives
        if re.search(r'(?:example|demo|test|sample|dummy)', match, re.IGNORECASE):
            confidence -= 0.3
        
        if re.search(r'(?:console\.log|alert|debug)', match, re.IGNORECASE):
            confidence -= 0.1
            
        return min(1.0, max(0.0, confidence))

    def add_finding(self, finding_type, severity, file, match, value, line, context, confidence, metadata=None):
        """Add a finding with enhanced validation"""
        # Validate finding
        if not value or len(value) < 2:
            return
            
        # Skip obvious false positives
        if len(value) > 1000:  # Too long, likely not a real finding
            return
            
        # Create finding object
        finding = Finding(
            type=finding_type,
            severity=severity,
            file=file,
            match=match[:200],  # Truncate for display
            value=value[:200],   # Truncate for display
            line=line,
            context=context[:300],  # Truncate for display
            confidence=confidence,
            remediation=self.get_remediation(finding_type),
            metadata=metadata or {}
        )
        
        self.findings.append(finding)
        
        # Log the finding
        if self.verbose:
            self.log(
                f"{finding_type.value} found: {value[:50]}... (Confidence: {confidence:.2f})",
                "FINDING",
                Fore.GREEN
            )

    def get_remediation(self, finding_type):
        """Get remediation advice for finding type"""
        remediations = {
            FindingType.SENSITIVE_KEY: "Remove hardcoded credentials and use environment variables or secure vaults",
            FindingType.AUTH_TOKEN: "Use secure session management, implement token rotation, and proper invalidation",
            FindingType.XSS: "Implement proper input sanitization, use Content Security Policy, and escape output",
            FindingType.SQL_INJECTION: "Use parameterized queries/prepared statements and input validation",
            FindingType.CODE_EXECUTION: "Avoid eval/exec, use safer alternatives, and validate all input",
            FindingType.WEAK_CRYPTO: "Use strong encryption algorithms (AES-256-GCM, bcrypt, Argon2)",
            FindingType.BUSINESS_LOGIC: "Implement server-side validation and authorization checks",
            FindingType.CORS: "Restrict CORS to specific origins and avoid wildcard with credentials",
            FindingType.WEBHOOK: "Validate webhook URLs and use secret verification tokens",
            FindingType.DEBUG: "Remove debug code in production and implement proper logging",
            FindingType.ADMIN: "Restrict admin paths and implement proper authentication/authorization",
        }
        return remediations.get(finding_type, "Review and implement proper security controls")

    def analyze_file(self, file_path, content=None, base_url=None):
        """Comprehensive file analysis with advanced detection"""
        if file_path in self.analyzed_files:
            return
        
        self.analyzed_files.add(file_path)
        self.log(f"Analyzing: {file_path}", "PROGRESS", Fore.BLUE)
        
        try:
            if content is None:
                if file_path.startswith(('http://', 'https://')):
                    content = self.fetch_url_content(file_path)
                    if not content:
                        self.failed_urls.append(file_path)
                        return
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Memory efficient reading
                        if os.path.getsize(file_path) > self.max_size:
                            self.log(f"File too large: {file_path}", "WARNING")
                            return
                        content = f.read()
            
            if not content or len(content) < 10:
                return
            
            # Pre-process content
            content_no_comments = self.remove_comments(content)
            lines = content_no_comments.split('\n')
            
            # Analyze with all patterns
            for finding_type, pattern_list in self.patterns.items():
                for pattern, default_severity in pattern_list:
                    matches = re.finditer(pattern, content_no_comments, re.IGNORECASE)
                    for match in matches:
                        value = match.group(1) if match.groups() else match.group(0)
                        line = self.get_line_number(content, match.start())
                        context = self.get_context(content, match.start())
                        confidence = self.calculate_confidence(match.group(0), finding_type)
                        
                        if confidence > 0.5:  # Only report high-confidence findings
                            self.add_finding(
                                finding_type,
                                default_severity,
                                file_path,
                                match.group(0),
                                value,
                                line,
                                context,
                                confidence
                            )
            
            # Additional advanced analysis
            self.analyze_advanced_patterns(content_no_comments, file_path)
            self.check_security_headers(content_no_comments, file_path)
            self.find_github_repos(content_no_comments, file_path)
            self.find_aws_accounts(content_no_comments, file_path)
            self.find_jwt_secrets(content_no_comments, file_path)
            self.find_webhooks_advanced(content_no_comments, file_path)
            
            # Client-side logic analysis
            self.analyze_client_side_logic(content_no_comments, file_path)
            
            # Vulnerability correlation
            self.correlate_vulnerabilities(content_no_comments, file_path)
            
        except Exception as e:
            self.log(f"Error analyzing {file_path}: {str(e)}", "ERROR")

    def analyze_advanced_patterns(self, content, file_path):
        """Additional advanced pattern detection"""
        # AWS Account IDs
        aws_pattern = r'[0-9]{12}'
        for match in re.finditer(aws_pattern, content):
            if self.calculate_confidence(match.group(0), FindingType.SENSITIVE_KEY) > 0.7:
                self.add_finding(
                    FindingType.SENSITIVE_KEY,
                    Severity.CRITICAL,
                    file_path,
                    match.group(0),
                    match.group(0),
                    self.get_line_number(content, match.start()),
                    self.get_context(content, match.start()),
                    0.85,
                    {'type': 'AWS Account ID'}
                )
        
        # Google reCAPTCHA keys
        recaptcha_pattern = r'6L[0-9A-Za-z-_]{20,}'
        for match in re.finditer(recaptcha_pattern, content):
            self.add_finding(
                FindingType.SENSITIVE_KEY,
                Severity.HIGH,
                file_path,
                match.group(0),
                match.group(0),
                self.get_line_number(content, match.start()),
                self.get_context(content, match.start()),
                0.9,
                {'type': 'reCAPTCHA Key'}
            )
        
        # Stripe publishable keys
        stripe_pattern = r'pk_(live|test)_[0-9A-Za-z]{24,}'
        for match in re.finditer(stripe_pattern, content):
            self.add_finding(
                FindingType.SENSITIVE_KEY,
                Severity.CRITICAL,
                file_path,
                match.group(0),
                match.group(0),
                self.get_line_number(content, match.start()),
                self.get_context(content, match.start()),
                0.95,
                {'type': 'Stripe Key'}
            )

    def check_security_headers(self, content, file_path):
        """Check for security headers in responses"""
        security_headers = [
            ('Content-Security-Policy', 'CSP Header', Severity.MEDIUM),
            ('X-XSS-Protection', 'XSS Protection Header', Severity.LOW),
            ('X-Content-Type-Options', 'Content Type Options', Severity.LOW),
            ('X-Frame-Options', 'Clickjacking Protection', Severity.LOW),
            ('Strict-Transport-Security', 'HSTS Header', Severity.MEDIUM),
        ]
        
        for header, name, severity in security_headers:
            if re.search(header, content, re.IGNORECASE):
                self.add_finding(
                    FindingType.SECURITY_HEADER,
                    severity,
                    file_path,
                    header,
                    header,
                    0,
                    self.get_context(content, content.find(header)),
                    0.8,
                    {'type': name}
                )

    def find_github_repos(self, content, file_path):
        """Find GitHub repository references"""
        github_patterns = [
            (r'github\.com/([^/"\']+)/([^/"\']+)/', Severity.MEDIUM),
            (r'github\.com/([^/"\']+)/([^/"\']+)\b', Severity.MEDIUM),
        ]
        
        for pattern, severity in github_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if match.groups():
                    repo = f"{match.group(1)}/{match.group(2)}"
                    self.add_finding(
                        FindingType.SUBDOMAIN,
                        severity,
                        file_path,
                        match.group(0),
                        repo,
                        self.get_line_number(content, match.start()),
                        self.get_context(content, match.start()),
                        0.7,
                        {'type': 'GitHub Repository'}
                    )

    def find_aws_accounts(self, content, file_path):
        """Find AWS account IDs"""
        aws_patterns = [
            (r'[0-9]{4}-[0-9]{4}-[0-9]{4}', Severity.HIGH),  # Formatted
            (r'[0-9]{12}', Severity.MEDIUM),  # Raw
        ]
        
        for pattern, severity in aws_patterns:
            for match in re.finditer(pattern, content):
                if self.calculate_confidence(match.group(0), FindingType.SENSITIVE_KEY) > 0.7:
                    self.add_finding(
                        FindingType.SENSITIVE_KEY,
                        severity,
                        file_path,
                        match.group(0),
                        match.group(0),
                        self.get_line_number(content, match.start()),
                        self.get_context(content, match.start()),
                        0.75,
                        {'type': 'AWS Account ID'}
                    )

    def find_jwt_secrets(self, content, file_path):
        """Find potential JWT secrets"""
        jwt_patterns = [
            (r'"secret"\s*:\s*"([^"]{32,})"', Severity.CRITICAL),
            (r'secret\s*=\s*"([^"]{32,})"', Severity.CRITICAL),
            (r'jwtSecret\s*[:=]\s*"([^"]{32,})"', Severity.CRITICAL),
        ]
        
        for pattern, severity in jwt_patterns:
            for match in re.finditer(pattern, content):
                self.add_finding(
                    FindingType.SENSITIVE_KEY,
                    severity,
                    file_path,
                    match.group(0),
                    match.group(1),
                    self.get_line_number(content, match.start()),
                    self.get_context(content, match.start()),
                    0.95,
                    {'type': 'JWT Secret'}
                )

    def find_webhooks_advanced(self, content, file_path):
        """Advanced webhook detection"""
        webhook_patterns = [
            r'(?:https?://)?[^\s"\'?&#]+/webhook(?:/[^\s"\'?&#]*)?',
            r'(?:https?://)?[^\s"\'?&#]+/hook(?:/[^\s"\'?&#]*)?',
            r'(?:https?://)?[^\s"\'?&#]+/callback(?:/[^\s"\'?&#]*)?',
        ]
        
        for pattern in webhook_patterns:
            for match in re.finditer(pattern, content):
                if self.calculate_confidence(match.group(0), FindingType.WEBHOOK) > 0.6:
                    self.add_finding(
                        FindingType.WEBHOOK,
                        Severity.CRITICAL,
                        file_path,
                        match.group(0),
                        match.group(0),
                        self.get_line_number(content, match.start()),
                        self.get_context(content, match.start()),
                        0.8,
                        {'type': 'Webhook URL'}
                    )

    def analyze_client_side_logic(self, content, file_path):
        """Deep client-side logic analysis"""
        # Check for authentication flow issues
        auth_flows = [
            ('login|signin|authenticate', Severity.HIGH, 'Authentication Flow'),
            ('register|signup|createUser', Severity.HIGH, 'Registration Flow'),
            ('resetPassword|forgotPassword|changePassword', Severity.CRITICAL, 'Password Flow'),
            ('otp|2fa|twoFactor|multiFactor', Severity.HIGH, '2FA/OTP Flow'),
        ]
        
        for pattern, severity, flow_type in auth_flows:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Check if client-side validation exists
                if re.search(r'(?:validate|check|verify|confirm)\s*\(', content[max(0, match.start()-200):match.end()+200]):
                    self.add_finding(
                        FindingType.BUSINESS_LOGIC,
                        severity,
                        file_path,
                        match.group(0),
                        match.group(0),
                        self.get_line_number(content, match.start()),
                        self.get_context(content, match.start()),
                        0.7,
                        {'type': flow_type, 'validation': 'Client-side validation detected'}
                    )
                else:
                    self.add_finding(
                        FindingType.BUSINESS_LOGIC,
                        Severity.CRITICAL,
                        file_path,
                        match.group(0),
                        match.group(0),
                        self.get_line_number(content, match.start()),
                        self.get_context(content, match.start()),
                        0.9,
                        {'type': flow_type, 'validation': 'Missing client-side validation'}
                    )
        
        # Check for payment logic
        payment_patterns = [
            ('pay|payment|checkout|processPayment|charge', Severity.CRITICAL),
            ('transfer|send|withdraw|deposit', Severity.CRITICAL),
            ('cart|order|checkout|purchase', Severity.HIGH),
        ]
        
        for pattern, severity in payment_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.add_finding(
                    FindingType.PAYMENT,
                    severity,
                    file_path,
                    match.group(0),
                    match.group(0),
                    self.get_line_number(content, match.start()),
                    self.get_context(content, match.start()),
                    0.8,
                    {'type': 'Payment processing'}
                )

    def correlate_vulnerabilities(self, content, file_path):
        """Correlate findings to identify complex vulnerabilities"""
        # Check for DOM-based XSS chains
        if re.search(r'document\.(?:write|writeln)', content) and re.search(r'(?:innerHTML|outerHTML)', content):
            self.add_finding(
                FindingType.XSS,
                Severity.CRITICAL,
                file_path,
                "Multiple DOM sinks detected",
                "Multiple DOM sinks",
                0,
                "Multiple DOM manipulation methods detected",
                0.85,
                {'type': 'DOM XSS Chain'}
            )
        
        # Check for eval with user input
        if re.search(r'eval\s*\(', content) and re.search(r'(?:req|request|body|params|query|headers)', content):
            self.add_finding(
                FindingType.CODE_EXECUTION,
                Severity.CRITICAL,
                file_path,
                "Eval with potential user input",
                "Eval with user input",
                0,
                "eval() used with external input",
                0.9,
                {'type': 'RCE via eval'}
            )
        
        # Check for insecure CORS with credentials
        if re.search(r'credentials["\']?\s*[:=]\s*["\']?include', content) and re.search(r'Access-Control-Allow-Origin["\']?\s*[:=]\s*["\']?\*', content):
            self.add_finding(
                FindingType.CORS,
                Severity.CRITICAL,
                file_path,
                "Insecure CORS with credentials",
                "CORS Misconfiguration",
                0,
                "CORS with credentials and wildcard origin",
                0.95,
                {'type': 'CORS Misconfiguration'}
            )

    def fetch_url_content(self, url):
        """Fetch URL content with advanced error handling"""
        try:
            self.log(f"Fetching: {url}", "PROGRESS", Fore.BLUE)
            
            # Try HTTPS first, fallback to HTTP
            for protocol in ['https://', 'http://']:
                if not url.startswith(protocol):
                    continue
                
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        # Check content type
                        content_type = response.headers.get('Content-Type', '').lower()
                        if 'javascript' in content_type or 'json' in content_type or 'text' in content_type:
                            return response.text
                        elif 'gzip' in response.headers.get('Content-Encoding', ''):
                            try:
                                return gzip.decompress(response.content).decode('utf-8', errors='ignore')
                            except:
                                return response.text
                        else:
                            return response.text
                except requests.exceptions.SSLError:
                    continue
                except Exception as e:
                    self.log(f"Error fetching {url}: {str(e)}", "WARNING")
            
            return None
            
        except Exception as e:
            self.log(f"Error fetching {url}: {str(e)}", "ERROR")
            return None

    def get_line_number(self, content, position):
        """Get line number for a position in text"""
        return content[:position].count('\n') + 1

    def process_targets(self, targets):
        """Process multiple targets with threading"""
        self.log(f"Processing {len(targets)} targets with {self.threads} threads", "INFO")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_target = {}
            for target in targets:
                future = executor.submit(self.analyze_file, target)
                future_to_target[future] = target
            
            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1
                try:
                    future.result(timeout=30)
                except TimeoutError:
                    self.log(f"Timeout processing {target}", "WARNING")
                    self.failed_urls.append(target)
                except Exception as e:
                    self.log(f"Error processing {target}: {str(e)}", "ERROR")
                    self.failed_urls.append(target)
                
                if completed % 5 == 0:
                    self.log(f"Progress: {completed}/{len(targets)} files analyzed", "PROGRESS")

    def generate_report(self):
        """Generate comprehensive report"""
        report = {
            'metadata': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration': str(datetime.now() - self.start_time),
                'total_files': len(self.analyzed_files),
                'failed_urls': len(self.failed_urls)
            },
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': {
                    'CRITICAL': len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                    'HIGH': len([f for f in self.findings if f.severity == Severity.HIGH]),
                    'MEDIUM': len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                    'LOW': len([f for f in self.findings if f.severity == Severity.LOW]),
                },
                'by_type': {}
            },
            'findings': [],
            'failed_urls': self.failed_urls,
            'analyzed_files': list(self.analyzed_files)
        }
        
        # Group findings by type
        for finding in self.findings:
            type_name = finding.type.value
            if type_name not in report['summary']['by_type']:
                report['summary']['by_type'][type_name] = 0
            report['summary']['by_type'][type_name] += 1
            
            # Add to findings list (without context for readability)
            report['findings'].append({
                'type': finding.type.value,
                'severity': finding.severity.value,
                'file': finding.file,
                'value': finding.value,
                'match': finding.match,
                'line': finding.line,
                'confidence': finding.confidence,
                'remediation': finding.remediation,
                'metadata': finding.metadata
            })
        
        return report

    def print_report(self):
        """Print formatted report"""
        print("\n" + "="*100)
        print(f"{Fore.GREEN}🔥 ULTIMATE JS ANALYSIS COMPLETE 🔥{Style.RESET_ALL}")
        print("="*100)
        
        # Header with stats
        print(f"\n{Fore.CYAN}📊 ANALYSIS STATISTICS{Style.RESET_ALL}")
        print(f"  • Files Analyzed: {len(self.analyzed_files)}")
        print(f"  • Total Findings: {len(self.findings)}")
        print(f"  • Failed URLs: {len(self.failed_urls)}")
        print(f"  • Duration: {datetime.now() - self.start_time}")
        
        # Severity breakdown
        print(f"\n{Fore.CYAN}⚠️  SEVERITY BREAKDOWN{Style.RESET_ALL}")
        critical = len([f for f in self.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in self.findings if f.severity == Severity.HIGH])
        medium = len([f for f in self.findings if f.severity == Severity.MEDIUM])
        low = len([f for f in self.findings if f.severity == Severity.LOW])
        
        print(f"  {Fore.RED}🔴 CRITICAL: {critical}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}🟠 HIGH: {high}{Style.RESET_ALL}")
        print(f"  {Fore.MAGENTA}🟡 MEDIUM: {medium}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}🔵 LOW: {low}{Style.RESET_ALL}")
        
        # Critical findings
        if critical > 0:
            print(f"\n{Fore.RED}🚨 CRITICAL FINDINGS (Must Fix){Style.RESET_ALL}")
            for i, finding in enumerate([f for f in self.findings if f.severity == Severity.CRITICAL][:10]):
                print(f"  {i+1}. {Fore.RED}[{finding.type.value}]{Style.RESET_ALL}")
                print(f"     Value: {finding.value[:100]}")
                print(f"     File: {finding.file}")
                print(f"     Line: {finding.line}")
                print(f"     Confidence: {finding.confidence:.2f}")
                print(f"     Fix: {finding.remediation[:100]}...")
                print()
            if critical > 10:
                print(f"  ... and {critical - 10} more critical findings")
        
        # High findings
        if high > 0:
            print(f"\n{Fore.YELLOW}⚠️  HIGH PRIORITY FINDINGS{Style.RESET_ALL}")
            for i, finding in enumerate([f for f in self.findings if f.severity == Severity.HIGH][:5]):
                print(f"  {i+1}. [{finding.type.value}] - {finding.value[:50]}")
            if high > 5:
                print(f"  ... and {high - 5} more high findings")
        
        # Summary by type
        print(f"\n{Fore.CYAN}📈 FINDINGS BY TYPE{Style.RESET_ALL}")
        type_counts = {}
        for finding in self.findings:
            type_name = finding.type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        for type_name, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  • {type_name}: {count}")
        
        # Recommendations
        print(f"\n{Fore.GREEN}🎯 RECOMMENDATIONS{Style.RESET_ALL}")
        print("  1. 🚨 Fix all CRITICAL findings immediately")
        print("  2. 🔧 Review HIGH severity findings in detail")
        print("  3. 🔍 Test all discovered API endpoints for vulnerabilities")
        print("  4. 🛡️ Remove any hardcoded secrets/tokens")
        print("  5. 📝 Implement proper input sanitization for DOM sinks")
        print("  6. 🔒 Add security headers (CSP, HSTS, etc.)")
        print("  7. 🧪 Test business logic flaws in client-side code")
        print("  8. 📊 Review webhook configurations for security")
        
        print(f"\n{Fore.GREEN}✅ Happy Hunting! 🚀{Style.RESET_ALL}")
        print("="*100 + "\n")

    def save_results(self, filename=None):
        """Save results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"js_analysis_{timestamp}.json"
        
        try:
            report = self.generate_report()
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self.log(f"Results saved to {filename}", "SUCCESS", Fore.GREEN)
            return filename
        except Exception as e:
            self.log(f"Error saving results: {str(e)}", "ERROR")
            return None

def load_urls_from_file(file_path):
    """Load URLs from a text file"""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse line, handling comma-separated or space-separated
                    for url in re.split(r'[,\s]+', line):
                        url = url.strip()
                        if url and url.startswith(('http://', 'https://')):
                            urls.append(url)
    except Exception as e:
        print(f"Error loading URLs from {file_path}: {str(e)}")
    return urls

def main():
    parser = argparse.ArgumentParser(
        description='Ultimate JS Analyzer for Bug Bounty Hunting',
        epilog='Example: python js_analyzer.py -f urls.txt -t 20 -v'
    )
    parser.add_argument('targets', nargs='*', help='JS files or URLs to analyze')
    parser.add_argument('-f', '--file', help='Text file containing URLs (one per line)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout in seconds (default: 15)')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        init(strip=True)
    
    # Collect targets
    targets = []
    
    # Load from file
    if args.file:
        file_urls = load_urls_from_file(args.file)
        targets.extend(file_urls)
        print(f"Loaded {len(file_urls)} URLs from {args.file}")
    
    # Add command line targets
    if args.targets:
        targets.extend(args.targets)
    
    if not targets:
        print("Error: No targets specified. Use -f for file or provide URLs/files as arguments.")
        parser.print_help()
        sys.exit(1)
    
    # Remove duplicates
    targets = list(dict.fromkeys(targets))
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║   ██╗███████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗ ███████╗██████╗  ║
║   ██║██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝ ██╔════╝██╔══██╗ ║
║   ██║███████╗    ███████║██╔██╗ ██║███████║██║   ╚████╔╝  ███████╗██████╔╝ ║
║   ██║╚════██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ╚════██║██╔══██╗ ║
║   ██║███████║    ██║  ██║██║ ╚████║██║  ██║███████╗██║    ███████║██║  ██║ ║
║   ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝    ╚══════╝╚═╝  ╚═╝ ║
║                    Ultimate JS Analyzer v3.0                          ║
╚══════════════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"📋 Targets: {len(targets)}")
    print(f"🧵 Threads: {args.threads}")
    print(f"⏱️  Timeout: {args.timeout}s")
    print(f"🔍 Verbose: {args.verbose}")
    print("="*80)
    
    # Initialize analyzer
    analyzer = UltimateJSAnalyzer(
        verbose=args.verbose,
        output_file=args.output,
        timeout=args.timeout,
        threads=args.threads
    )
    
    # Start analysis
    try:
        analyzer.process_targets(targets)
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user. Generating partial report...")
    
    # Generate and print report
    analyzer.print_report()
    
    # Save results
    if args.output or len(analyzer.findings) > 0:
        output_file = args.output or analyzer.save_results()
        if output_file:
            print(f"\n💾 Results saved to: {output_file}")
    
    # Print failed URLs
    if analyzer.failed_urls:
        print(f"\n⚠️  Failed to analyze {len(analyzer.failed_urls)} URLs:")
        for url in analyzer.failed_urls[:5]:
            print(f"  • {url}")
        if len(analyzer.failed_urls) > 5:
            print(f"  ... and {len(analyzer.failed_urls) - 5} more")

if __name__ == "__main__":
    main()
