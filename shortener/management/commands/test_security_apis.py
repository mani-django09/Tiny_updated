from django.core.management.base import BaseCommand
from django.conf import settings
import requests

class Command(BaseCommand):
    help = 'Test security API configurations and connectivity'
    
    def handle(self, *args, **options):
        self.stdout.write('🧪 Testing security API configurations...')
        self.stdout.write('='*50)
        
        # Test Google Safe Browsing
        self.test_google_safebrowsing()
        
        # Test VirusTotal
        self.test_virustotal()
        
        # Test Redis Cache
        self.test_redis_cache()
        
        self.stdout.write('='*50)
        self.stdout.write(self.style.SUCCESS('✅ API testing completed!'))
    
    def test_google_safebrowsing(self):
        """Test Google Safe Browsing API"""
        self.stdout.write('\n🛡️ Testing Google Safe Browsing API...')
        
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
            self.stdout.write(self.style.ERROR('   ❌ Google Safe Browsing API key not configured'))
            return
        
        self.stdout.write(self.style.SUCCESS('   ✅ API key configured'))
        
        try:
            api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            
            payload = {
                "client": {
                    "clientId": "url-shortener-test",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "https://www.google.com"}]
                }
            }
            
            self.stdout.write('   🔍 Testing API connectivity...')
            response = requests.post(api_url, json=payload, timeout=10)
            
            if response.status_code == 200:
                self.stdout.write(self.style.SUCCESS('   ✅ Google Safe Browsing API working correctly'))
                self.stdout.write('   📊 Response: Clean URL detected successfully')
            elif response.status_code == 400:
                self.stdout.write(self.style.ERROR('   ❌ Bad request - check API key validity'))
            elif response.status_code == 403:
                self.stdout.write(self.style.ERROR('   ❌ Forbidden - API key might be invalid or quota exceeded'))
            else:
                self.stdout.write(self.style.ERROR(f'   ❌ API returned status {response.status_code}'))
                
        except requests.exceptions.Timeout:
            self.stdout.write(self.style.ERROR('   ❌ Request timed out'))
        except requests.exceptions.ConnectionError:
            self.stdout.write(self.style.ERROR('   ❌ Connection error - check internet connection'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'   ❌ Error: {e}'))
    
    def test_virustotal(self):
        """Test VirusTotal API"""
        self.stdout.write('\n🦠 Testing VirusTotal API...')
        
        if not hasattr(settings, 'VIRUSTOTAL_API_KEY') or not settings.VIRUSTOTAL_API_KEY:
            self.stdout.write(self.style.ERROR('   ❌ VirusTotal API key not configured'))
            return
        
        self.stdout.write(self.style.SUCCESS('   ✅ API key configured'))
        
        try:
            api_key = settings.VIRUSTOTAL_API_KEY
            
            # Test with URL report endpoint
            report_url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {
                'apikey': api_key, 
                'resource': 'https://www.google.com'
            }
            
            self.stdout.write('   🔍 Testing API connectivity...')
            response = requests.get(report_url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                self.stdout.write(self.style.SUCCESS('   ✅ VirusTotal API working correctly'))
                
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 0)
                    self.stdout.write(f'   📊 Response: {positives}/{total} engines analyzed URL')
                elif result.get('response_code') == 0:
                    self.stdout.write('   📊 Response: URL not in database (normal for test)')
                else:
                    self.stdout.write('   📊 Response: Scan queued')
            elif response.status_code == 403:
                self.stdout.write(self.style.ERROR('   ❌ Forbidden - API key might be invalid'))
            elif response.status_code == 204:
                self.stdout.write(self.style.WARNING('   ⚠️  Rate limit exceeded - try again later'))
            else:
                self.stdout.write(self.style.ERROR(f'   ❌ API returned status {response.status_code}'))
                
        except requests.exceptions.Timeout:
            self.stdout.write(self.style.ERROR('   ❌ Request timed out'))
        except requests.exceptions.ConnectionError:
            self.stdout.write(self.style.ERROR('   ❌ Connection error - check internet connection'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'   ❌ Error: {e}'))
    
    def test_redis_cache(self):
        """Test Redis cache connectivity"""
        self.stdout.write('\n🔴 Testing Redis cache...')
        
        try:
            from django.core.cache import cache
            
            # Test cache operations
            test_key = 'security_test_key'
            test_value = 'security_test_value'
            
            self.stdout.write('   🔍 Testing cache operations...')
            cache.set(test_key, test_value, 30)
            retrieved_value = cache.get(test_key)
            
            if retrieved_value == test_value:
                self.stdout.write(self.style.SUCCESS('   ✅ Redis cache working correctly'))
                cache.delete(test_key)  # Cleanup
            else:
                self.stdout.write(self.style.ERROR('   ❌ Redis cache not working properly'))
                
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'   ⚠️  Redis cache error: {e}'))
            self.stdout.write('   💡 Note: Redis is optional but recommended for rate limiting')