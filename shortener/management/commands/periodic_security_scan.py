from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from django.db import models
from shortener.models import URL, SecurityScan
from datetime import timedelta
import requests
import time

class Command(BaseCommand):
    help = 'Run periodic security scans on URLs'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=5,
            help='Number of URLs to scan (default: 5)',
        )
        parser.add_argument(
            '--delay',
            type=int,
            default=2,
            help='Delay in seconds between API calls (default: 2)',
        )
        parser.add_argument(
            '--priority-only',
            action='store_true',
            help='Only scan high-priority URLs (flagged, low security score)',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('🔒 Starting periodic security scan...')
        start_time = timezone.now()
        
        # Get URLs to scan
        if options['priority_only']:
            urls_to_scan = self.get_priority_urls(options['batch_size'])
            self.stdout.write(f'📊 Scanning {len(urls_to_scan)} priority URLs')
        else:
            urls_to_scan = self.get_stale_urls(options['batch_size'])
            self.stdout.write(f'📊 Scanning {len(urls_to_scan)} URLs that need updates')
        
        if not urls_to_scan:
            self.stdout.write(self.style.SUCCESS('✅ No URLs need scanning at this time'))
            return
        
        # Process URLs
        scanned_count = 0
        blocked_count = 0
        error_count = 0
        
        for url in urls_to_scan:
            try:
                self.stdout.write(f'🔍 Scanning: {url.short_code} -> {url.original_url[:50]}...')
                
                # Perform security scan
                scan_result = self.perform_security_scan(url)
                
                if scan_result == 'malicious':
                    blocked_count += 1
                    self.stdout.write(
                        self.style.ERROR(f'   ⚠️  BLOCKED: Malicious content detected')
                    )
                elif scan_result == 'suspicious':
                    self.stdout.write(
                        self.style.WARNING(f'   ⚡ FLAGGED: Suspicious content detected')
                    )
                else:
                    self.stdout.write(f'   ✅ SAFE: No threats detected')
                
                scanned_count += 1
                
                # Rate limiting delay
                if options['delay'] > 0:
                    time.sleep(options['delay'])
                    
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f'   ❌ ERROR: {str(e)}')
                )
        
        # Summary
        duration = timezone.now() - start_time
        self.stdout.write('\n' + '='*50)
        self.stdout.write(self.style.SUCCESS('📈 SECURITY SCAN SUMMARY'))
        self.stdout.write('='*50)
        self.stdout.write(f'⏱️  Duration: {duration.total_seconds():.1f} seconds')
        self.stdout.write(f'🔍 URLs scanned: {scanned_count}')
        self.stdout.write(f'🚫 URLs blocked: {blocked_count}')
        self.stdout.write(f'❌ Errors: {error_count}')
        
        if blocked_count > 0:
            self.stdout.write(
                self.style.WARNING(f'\n⚠️  {blocked_count} malicious URLs were blocked!')
            )
        
        self.stdout.write(self.style.SUCCESS('\n🎉 Security scan completed!'))
    
    def get_stale_urls(self, batch_size):
        """Get URLs that haven't been scanned recently"""
        seven_days_ago = timezone.now() - timedelta(days=7)
        
        return list(URL.objects.filter(
            models.Q(last_security_scan__lt=seven_days_ago) |
            models.Q(last_security_scan__isnull=True),
            is_active=True
        ).order_by('last_security_scan')[:batch_size])
    
    def get_priority_urls(self, batch_size):
        """Get high-priority URLs that need immediate scanning"""
        return list(URL.objects.filter(
            models.Q(flagged_by_users__gt=0) |
            models.Q(security_score__lt=70),
            is_active=True
        ).order_by('-flagged_by_users', 'security_score')[:batch_size])
    
    def perform_security_scan(self, url):
        """Perform security scan on a URL"""
        scan_details = {}
        threat_found = False
        block_reasons = []
        
        # Check with Google Safe Browsing
        google_result = self.check_google_safebrowsing(url.original_url)
        scan_details['google_safebrowsing'] = google_result
        
        if google_result['status'] == 'malicious':
            threat_found = True
            threats = google_result.get('threats', [])
            threat_types = [t.get('threatType', 'Unknown') for t in threats]
            block_reasons.append(f"Google Safe Browsing: {', '.join(threat_types)}")
        
        # Check with VirusTotal
        vt_result = self.check_virustotal(url.original_url)
        scan_details['virustotal'] = vt_result
        
        if vt_result['status'] == 'malicious':
            threat_found = True
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            block_reasons.append(f"VirusTotal: {positives}/{total} engines detected threats")
        
        # Determine final result
        if threat_found:
            scan_result = 'malicious'
            url.is_safe = False
            url.security_score = 0
            url.temporarily_blocked = True
            url.block_reason = '; '.join(block_reasons)
        elif vt_result['status'] == 'suspicious':
            scan_result = 'suspicious'
            url.security_score = max(30, url.security_score - 20)
        else:
            scan_result = 'safe'
            url.security_score = 100
        
        # Update URL
        url.last_security_scan = timezone.now()
        url.save()
        
        # Create SecurityScan record
        try:
            SecurityScan.objects.create(
                url=url,
                scan_type='periodic',
                result=scan_result,
                details=scan_details,
                scanner_service='periodic_scan'
            )
        except Exception as e:
            self.stdout.write(f'Warning: Could not create scan record: {e}')
        
        return scan_result
    
    def check_google_safebrowsing(self, url):
        """Check URL with Google Safe Browsing API"""
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
            return {'status': 'unknown', 'message': 'API not configured'}
        
        try:
            api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            payload = {
                "client": {"clientId": "url-shortener", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('matches'):
                    threats = [{'threatType': m.get('threatType')} for m in result['matches']]
                    return {'status': 'malicious', 'threats': threats}
                else:
                    return {'status': 'safe'}
            else:
                return {'status': 'error', 'message': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_virustotal(self, url):
        """Check URL with VirusTotal API"""
        if not hasattr(settings, 'VIRUSTOTAL_API_KEY') or not settings.VIRUSTOTAL_API_KEY:
            return {'status': 'unknown', 'message': 'API not configured'}
        
        try:
            api_key = settings.VIRUSTOTAL_API_KEY
            report_url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {'apikey': api_key, 'resource': url}
            
            response = requests.get(report_url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    
                    if positives > 2:
                        return {'status': 'malicious', 'positives': positives, 'total': total}
                    elif positives > 0:
                        return {'status': 'suspicious', 'positives': positives, 'total': total}
                    else:
                        return {'status': 'safe', 'positives': positives, 'total': total}
                else:
                    return {'status': 'unknown', 'message': 'URL not in database'}
            else:
                return {'status': 'error', 'message': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}