from flask import Flask, request, jsonify
from flask_cors import CORS
import os  # Already there
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, JavascriptException
import requests
import time
import re
import json
import os
import sys
from urllib.parse import urljoin, urlparse
from collections import defaultdict

app = Flask(__name__)
CORS(app)  # Allow n8n and your website to call this API

class AdvancedSeleniumScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.issues = []
        self.driver = None
        self.vulnerable_params = defaultdict(list)
        
        # XSS payloads (more comprehensive)
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            '\"><script>alert(\"XSS\")</script>',
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "';alert('XSS');//"
        ]
        
        # SQL injection payloads
        self.sql_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR 1=1--",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "' WAITFOR DELAY '00:00:05'--",
            "' OR (SELECT COUNT(*) FROM users) > 0--"
        ]
        
        # Sensitive endpoints to check
        self.sensitive_endpoints = [
            "/admin", "/administrator", "/wp-admin", "/login", "/signin",
            "/dashboard", "/console", "/backup", "/backups", "/temp",
            "/.env", "/.git/config", "/config.php", "/config.json",
            "/phpinfo.php", "/info.php", "/server-status", "/.htaccess",
            "/database.sql", "/dump.sql", "/backup.sql", "/api-docs",
            "/swagger", "/v2/api-docs", "/graphql", "/graphiql"
        ]
        
        # Secrets patterns
        self.secret_patterns = {
            'API Key': r'(api[_-]?key|apikey|access[_-]?token)[\s]*[:=][\s]*["\']?([A-Za-z0-9]{16,50})',
            'AWS Key': r'(AKIA|ASIA)[A-Z0-9]{16}',
            'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            'Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            'Password': r'(password|passwd|pwd)[\s]*[:=][\s]*["\']([^"\']{4,50})',
            'Bearer Token': r'Bearer[\s]+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+',
            'Internal IP': r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})'
        }
        
    def setup_driver(self):
        """Configure Selenium for Docker/Railway environment"""
        options = Options()
        
        # Critical for headless containers
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        options.add_argument("--disable-setuid-sandbox")
        options.add_argument("--disable-software-rasterizer")
        options.add_argument("--disable-logging")
        options.add_argument("--log-level=3")
        
        # Force Chromium binary location for Docker
        options.binary_location = "/usr/bin/chromium"
        
        # Disable DevTools error logs
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        
        # Create driver with suppressed logs
        service = Service(log_output=open(os.devnull, 'w'))
        self.driver = webdriver.Chrome(options=options, service=service)
        self.wait = WebDriverWait(self.driver, 10)
            
    def scan(self):
        """Main scanning orchestration"""
        print(f"[+] Starting comprehensive Selenium scan on: {self.target_url}")
        
        try:
            self.setup_driver()
        except Exception as e:
            self.issues.append({
                "type": "Driver Error",
                "severity": "INFO",
                "detail": f"Could not initialize Chrome driver: {str(e)}"
            })
            return self.issues
        
        try:
            # 1. Initial page load and basic checks
            self.driver.get(self.target_url)
            time.sleep(3)
            
            self.check_security_headers_selenium()
            self.check_cookies_selenium()
            self.check_forms_and_inputs()
            self.check_javascript_vulnerabilities()
            self.check_network_requests()
            self.check_local_storage()
            self.check_dom_sources()
            self.check_iframe_vulnerabilities()
            
            # 2. Crawl and discover pages
            print("[+] Crawling site for more pages...")
            discovered_urls = self.crawl_for_urls()
            print(f"[+] Discovered {len(discovered_urls)} pages")
            
            # 3. Test each discovered page
            for url in discovered_urls[:30]:
                print(f"  Testing: {url}")
                self.test_url_for_vulnerabilities(url)
            
            # 4. Test endpoint access control
            self.test_sensitive_endpoints()
            
        except Exception as e:
            self.issues.append({
                "type": "Scan Error",
                "severity": "INFO",
                "detail": f"Scan failed: {str(e)}"
            })
        finally:
            if self.driver:
                self.driver.quit()
        
        return self.issues
    
    # ... (keep all other methods exactly as they were: 
    # check_security_headers_selenium, check_cookies_selenium, 
    # check_forms_and_inputs, check_javascript_vulnerabilities,
    # check_network_requests, check_local_storage, check_dom_sources,
    # check_iframe_vulnerabilities, crawl_for_urls, 
    # test_url_for_vulnerabilities, check_for_xss_execution,
    # test_sensitive_endpoints, generate_report)
    
    # NOTE: Copy all the other methods from your original script here
    # They remain unchanged

# Flask API endpoints
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Railway"""
    return jsonify({"status": "healthy", "service": "selenium-scanner"})

@app.route('/scan', methods=['POST'])
def scan_endpoint():
    """Main scan endpoint - receives URL and returns security report"""
    data = request.json
    
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    target_url = data.get('url')
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    print(f"[+] Scan requested for: {target_url}")
    
    # Run the scanner
    scanner = AdvancedSeleniumScanner(target_url)
    issues = scanner.scan()
    
    # Generate report
    report = {
        "url": target_url,
        "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "total_issues": len(issues),
        "issues": issues,
        "status": "completed"
    }
    
    # Group by severity for easier reading
    by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'INFO': []
    }
    
    for issue in issues:
        severity = issue.get('severity', 'INFO')
        by_severity[severity].append(issue)
    
    report['issues_by_severity'] = by_severity
    
    print(f"[+] Scan completed. Found {len(issues)} issues.")
    
    return jsonify(report)

@app.route('/scan/async', methods=['POST'])
def scan_async_endpoint():
    """Async scan endpoint for longer scans (returns immediately with scan ID)"""
    import uuid
    from threading import Thread
    
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' parameter"}), 400
    
    scan_id = str(uuid.uuid4())
    target_url = data.get('url')
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Store scan status (in production, use Redis or database)
    scans_store[scan_id] = {"status": "running", "url": target_url}
    
    # Run scan in background
    def run_scan():
        scanner = AdvancedSeleniumScanner(target_url)
        issues = scanner.scan()
        scans_store[scan_id] = {
            "status": "completed",
            "url": target_url,
            "total_issues": len(issues),
            "issues": issues,
            "scan_date": time.strftime('%Y-%m-%d %H:%M:%S')
        }
    
    thread = Thread(target=run_scan)
    thread.start()
    
    return jsonify({"scan_id": scan_id, "status": "running", "message": "Scan started"})

@app.route('/scan/status/<scan_id>', methods=['GET'])
def scan_status(scan_id):
    """Get status of async scan"""
    result = scans_store.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)

# Simple in-memory store for async scans (for production, use Redis)
scans_store = {}

# For local testing
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[+] Starting Flask server on port {port}")
    app.run(host="0.0.0.0", port=port)