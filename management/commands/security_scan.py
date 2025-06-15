from django.core.management.base import BaseCommand
from shortener.models import URL, SecurityScan
from shortener.security.utils import SecurityScanner
from datetime import timedelta
from django.utils import timezone
import requests
from django.conf import settings
import logging

class Command(BaseCommand):
    help = 'Run comprehensive security scans on all URLs using Google Safe Browsing and VirusTotal'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force scan all URLs regardless of last scan date',
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Limit number of URLs to scan (default: 100)',
        )
        parser.add_argument(
            '--service',
            choices=['google', 'virustotal', 'both'],
            default='both',
            help='Which security service to use (default: both)',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('Starting comprehensive security scan...')
        
        # Determine which URLs to scan
        if options['force']:
            urls_to_scan = URL.objects.filter(is_active=True)[:options['limit']]
            self.stdout.write(f'Force scanning {urls_to_scan.count()} URLs')
        else:
            # Scan URLs that haven't been scanned in 7 days or never scanned
            urls_to_scan = (
                URL.objects.filter(
                    last_security_scan__lt=timezone.now() - timedelta(days=7),
                    is_active=True
                ) | URL.objects.filter(
                    last_security_scan__isnull=True,
                    is_active=True
                )
            )[:options['limit']]
            self.stdout.write(f'Scanning {urls_to_scan.count()} URLs that need updates')
        
        scanned_count = 0
        blocked_count = 0
        error_count = 0
        
        for url in urls_to_scan:
            self.stdout.write(f'Scanning {url.short_code}: {url.original_url}')
            
            try:
                # Perform comprehensive scan
                scan_results = self.perform_comprehensive_scan(
                    url, 
                    options['service']
                )
                
                # Process results
                overall_status = self.process_scan_results(url, scan_results)
                
                # Update URL status
                url.last_security_scan = timezone.now()
                
                if overall_status == 'malicious':
                    url.is_safe = False
                    url.temporarily_blocked = True
                    url.block_reason = 'Flagged by automated security scan'
                    url.security_score = 0
                    blocked_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'⚠️  BLOCKED: {url.short_code} - Malicious content detected')
                    )
                elif overall_status == 'suspicious':
                    url.security_score = max(30, url.security_score - 20)
                    self.stdout.write(
                        self.style.WARNING(f'⚡ SUSPICIOUS: {url.short_code} - Flagged as suspicious')
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(f'✅ SAFE: {url.short_code} - No threats detected')
                    )
                
                url.save()
                scanned_count += 1
                
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f'❌ ERROR scanning {url.short_code}: {str(e)}')
                )
                logging.error(f'Security scan error for {url.short_code}: {str(e)}')
        
        # Print summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('SECURITY SCAN SUMMARY'))
        self.stdout.write('='*50)
        self.stdout.write(f'URLs scanned: {scanned_count}')
        self.stdout.write(f'URLs blocked: {blocked_count}')
        self.stdout.write(f'Errors encountered: {error_count}')
        
        if blocked_count > 0:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  {blocked_count} malicious URLs were blocked!')
            )
        
        self.stdout.write(self.style.SUCCESS('\nSecurity scan completed successfully!'))
    
    def perform_comprehensive_scan(self, url, service_choice):
        """Perform comprehensive security scan using multiple services"""
        scan_results = {}
        
        # Google Safe Browsing scan
        if service_choice in ['google', 'both']:
            try:
                google_result = self.check_google_safebrowsing(url.original_url)
                scan_results['google_safebrowsing'] = google_result
                
                # Create scan record
                SecurityScan.objects.create(
                    url=url,
                    scan_type='reputation',
                    result=google_result.get('status', 'error'),
                    details={'google_safebrowsing': google_result},
                    scanner_service='google_safebrowsing'
                )
                
            except Exception as e:
                self.stdout.write(f'Google Safe Browsing error: {str(e)}')
                scan_results['google_safebrowsing'] = {'status': 'error', 'message': str(e)}
        
        # VirusTotal scan
        if service_choice in ['virustotal', 'both']:
            try:
                vt_result = SecurityScanner.scan_url_with_virustotal(url.original_url)
                scan_results['virustotal'] = vt_result
                
                # Create scan record
                SecurityScan.objects.create(
                    url=url,
                    scan_type='malware',
                    result=vt_result.get('status', 'error'),
                    details={'virustotal': vt_result},
                    scanner_service='virustotal'
                )
                
            except Exception as e:
                self.stdout.write(f'VirusTotal error: {str(e)}')
                scan_results['virustotal'] = {'status': 'error', 'message': str(e)}
        
        # Local security checks
        try:
            local_result = SecurityScanner.comprehensive_url_check(url.original_url)
            scan_results['local_scan'] = local_result
            
            # Create scan record
            SecurityScan.objects.create(
                url=url,
                scan_type='reputation',
                result=local_result.get('status', 'safe'),
                details={'local_scan': local_result},
                scanner_service='internal'
            )
            
        except Exception as e:
            self.stdout.write(f'Local scan error: {str(e)}')
            scan_results['local_scan'] = {'status': 'error', 'message': str(e)}
        
        return scan_results
    
    def check_google_safebrowsing(self, url):
        """Check URL with Google Safe Browsing API"""
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
            return {'status': 'error', 'message': 'Google Safe Browsing API key not configured'}
        
        api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "url-shortener-security-scan",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE", 
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(api_url, json=payload, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('matches'):
                    # Found threats
                    threats = []
                    for match in result['matches']:
                        threats.append({
                            'threatType': match.get('threatType'),
                            'platformType': match.get('platformType'),
                            'threatEntryType': match.get('threatEntryType')
                        })
                    
                    return {
                        'status': 'malicious',
                        'threats': threats,
                        'details': result
                    }
                else:
                    # No threats found
                    return {'status': 'safe', 'details': result}
            else:
                return {
                    'status': 'error', 
                    'message': f'API request failed with status {response.status_code}'
                }
                
        except requests.exceptions.Timeout:
            return {'status': 'error', 'message': 'API request timed out'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'message': f'API request failed: {str(e)}'}
        except Exception as e:
            return {'status': 'error', 'message': f'Unexpected error: {str(e)}'}
    
    def process_scan_results(self, url, scan_results):
        """Process all scan results and determine overall status"""
        malicious_count = 0
        suspicious_count = 0
        safe_count = 0
        error_count = 0
        
        # Count results from each service
        for service, result in scan_results.items():
            status = result.get('status', 'error')
            
            if status == 'malicious':
                malicious_count += 1
            elif status == 'suspicious':
                suspicious_count += 1
            elif status == 'safe':
                safe_count += 1
            else:
                error_count += 1
        
        # Determine overall status (any malicious result blocks the URL)
        if malicious_count > 0:
            return 'malicious'
        elif suspicious_count > 0:
            return 'suspicious'
        elif safe_count > 0:
            return 'safe'
        else:
            return 'error'
    
    def get_threat_summary(self, scan_results):
        """Get a summary of detected threats"""
        threats = []
        
        # Google Safe Browsing threats
        google_result = scan_results.get('google_safebrowsing', {})
        if google_result.get('threats'):
            for threat in google_result['threats']:
                threats.append(f"Google: {threat.get('threatType', 'Unknown')}")
        
        # VirusTotal threats
        vt_result = scan_results.get('virustotal', {})
        if vt_result.get('positives', 0) > 0:
            threats.append(f"VirusTotal: {vt_result['positives']}/{vt_result.get('total', 0)} engines")
        
        # Local scan warnings
        local_result = scan_results.get('local_scan', {})
        if local_result.get('blocked_reasons'):
            threats.extend([f"Local: {reason}" for reason in local_result['blocked_reasons']])
        
        return threats