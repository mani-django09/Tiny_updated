# Save as: shortener/management/commands/test_malicious_detection.py

from django.core.management.base import BaseCommand
from django.conf import settings
import requests

class Command(BaseCommand):
    help = 'Test malicious URL detection with known test URLs'
    
    def handle(self, *args, **options):
        self.stdout.write('🦠 Testing malicious URL detection...')
        self.stdout.write('='*60)
        
        # Test URLs (Google's official test URLs)
        test_urls = [
            {
                'url': 'http://malware.testing.google.test/testing/malware/',
                'expected': 'malicious',
                'description': 'Google Safe Browsing test malware URL'
            },
            {
                'url': 'http://testsafebrowsing.appspot.com/s/malware.html',
                'expected': 'malicious', 
                'description': 'Alternative malware test URL'
            },
            {
                'url': 'https://www.google.com',
                'expected': 'safe',
                'description': 'Known safe URL'
            },
            {
                'url': 'http://g00gle.com',
                'expected': 'suspicious',
                'description': 'Typosquatting attempt'
            }
        ]
        
        for i, test in enumerate(test_urls, 1):
            self.stdout.write(f'\n🧪 Test {i}/4: {test["description"]}')
            self.stdout.write(f'   🔗 URL: {test["url"]}')
            self.stdout.write(f'   📊 Expected: {test["expected"]}')
            
            # Test with Google Safe Browsing
            google_result = self.check_google_safebrowsing(test['url'])
            self.display_result('Google Safe Browsing', google_result, test['expected'])
            
            # Test with VirusTotal  
            vt_result = self.check_virustotal(test['url'])
            self.display_result('VirusTotal', vt_result, test['expected'])
            
            self.stdout.write('   ' + '-'*50)
        
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('🎉 Malicious detection testing completed!'))
        self.stdout.write('\n💡 Note: Some test URLs may not be detected by all services')
        self.stdout.write('💡 This is normal - different services have different databases')
    
    def display_result(self, service, result, expected):
        """Display test result with color coding"""
        status = result.get('status', 'unknown')
        
        if status == expected:
            self.stdout.write(self.style.SUCCESS(f'   ✅ {service}: {status} (CORRECT)'))
        elif status == 'safe' and expected == 'malicious':
            self.stdout.write(self.style.WARNING(f'   ⚠️  {service}: {status} (missed threat)'))
        elif status == 'malicious' and expected == 'safe':
            self.stdout.write(self.style.ERROR(f'   🚨 {service}: {status} (false positive)'))
        else:
            self.stdout.write(f'   ℹ️  {service}: {status}')
        
        # Show additional details
        if status == 'malicious' and 'threats' in result:
            threats = [t.get('threatType', 'Unknown') for t in result['threats']]
            self.stdout.write(f'      Threats: {", ".join(threats)}')
        elif status in ['malicious', 'suspicious'] and 'positives' in result:
            self.stdout.write(f'      Detection: {result["positives"]}/{result.get("total", 0)} engines')
        elif status == 'error':
            self.stdout.write(f'      Error: {result.get("message", "Unknown error")}')
    
    def check_google_safebrowsing(self, url):
        """Check URL with Google Safe Browsing API"""
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
            return {'status': 'error', 'message': 'API not configured'}
        
        try:
            api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            payload = {
                "client": {"clientId": "url-shortener-test", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('matches'):
                    threats = []
                    for match in result['matches']:
                        threats.append({
                            'threatType': match.get('threatType'),
                            'platformType': match.get('platformType')
                        })
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
            return {'status': 'error', 'message': 'API not configured'}
        
        try:
            api_key = settings.VIRUSTOTAL_API_KEY
            
            # Submit URL for scanning first
            submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
            submit_data = {'apikey': api_key, 'url': url}
            requests.post(submit_url, data=submit_data, timeout=10)
            
            # Check report
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
                    return {'status': 'unknown', 'message': 'URL not in database yet'}
            else:
                return {'status': 'error', 'message': f'HTTP {response.status_code}'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}