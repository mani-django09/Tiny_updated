import requests
import re
import socket
from urllib.parse import urlparse
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

# Import models from parent directory
from ..models import (
    BlockedDomain, WhitelistedDomain, SecuritySettings, 
    RateLimitLog, SuspiciousActivity
)

class SecurityScanner:
    """Enhanced security scanning utilities"""
    
    # Only block major competitors - not legitimate services
    BLOCKED_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
        'short.link', 'tiny.cc', 'v.gd', 'cutt.ly'
    ]
    
    # Allow these legitimate services (don't treat as "shorteners")
    ALLOWED_SERVICES = [
        'sharepoint.com', 'onedrive.live.com', 'drive.google.com',
        'dropbox.com', 'imgur.com', 'imgchest.com', 'gyazo.com',
        'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
        'cloudfront.net', 'amazonaws.com', 'azure.com'
    ]
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        # Executable files
        r'\.(exe|scr|bat|cmd|pif|vbs|jar|msi|dmg|pkg|deb|rpm)(\?|$)',
        # Suspicious protocols
        r'^(javascript|data|file|ftp):', 
        # IP addresses instead of domains
        r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        # Very long suspicious domains
        r'[a-z0-9]{30,}\.(com|net|org)',
        # Common phishing patterns
        r'(secure|account|verify|update|confirm).*(login|signin|bank|paypal|amazon)',
        # Suspicious subdomains
        r'[a-z0-9]{15,}\.[a-z]+\.(com|net|org)',
        # URL shortening attempts
        r'(short|tiny|bit|link|url)\.',
    ]
    
    @staticmethod
    def comprehensive_url_check(url):
        """Updated comprehensive security check with better logic"""
        results = {
            'status': 'safe',
            'risk_score': 0,
            'warnings': [],
            'blocked_reasons': []
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # 1. Check against local blocklist
            if BlockedDomain.objects.filter(domain=domain, is_active=True).exists():
                results['status'] = 'blocked'
                results['blocked_reasons'].append('Domain in local blocklist')
                return results
            
            # 2. Check whitelist (if whitelisted, skip other checks)
            if WhitelistedDomain.objects.filter(domain=domain).exists():
                results['status'] = 'safe'
                return results
            
            # 3. Check for allowed services first
            if any(allowed in domain for allowed in SecurityScanner.ALLOWED_SERVICES):
                results['status'] = 'safe'
                results['risk_score'] = 10  # Very low risk
                return results
            
            # 4. Check for nested shorteners (only competing ones)
            if SecurityScanner.is_nested_shortener(url):
                results['status'] = 'blocked'
                results['blocked_reasons'].append('Competing URL shortener detected')
                return results
            
            # 5. Check suspicious TLDs (but don't auto-block)
            for tld in SecurityScanner.SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    results['risk_score'] += 20  # Reduced from 30
                    results['warnings'].append(f'Suspicious TLD: {tld}')
            
            # 6. Check suspicious patterns (but be less aggressive)
            pattern_count = 0
            for pattern in SecurityScanner.SUSPICIOUS_PATTERNS:
                if re.search(pattern, url.lower()):
                    pattern_count += 1
                    results['warnings'].append(f'Suspicious pattern detected')
            
            # Only add risk if multiple patterns match
            if pattern_count >= 2:
                results['risk_score'] += 25
            elif pattern_count == 1:
                results['risk_score'] += 10
            
            # 7. Domain risk check (less aggressive)
            domain_risk = SecurityScanner.check_domain_risk(domain)
            results['risk_score'] += domain_risk['score'] * 0.5  # Reduce impact by 50%
            results['warnings'].extend(domain_risk['warnings'])
            
            # 8. URL structure analysis (less aggressive)
            structure_risk = SecurityScanner.analyze_url_structure(url)
            results['risk_score'] += structure_risk['score'] * 0.5  # Reduce impact by 50%
            results['warnings'].extend(structure_risk['warnings'])
            
            # 9. Domain resolution check
            if not SecurityScanner.can_resolve_domain(domain):
                results['risk_score'] += 30  # Reduced from 40
                results['warnings'].append('Domain cannot be resolved')
            
            # Determine final status with higher thresholds
            if results['risk_score'] >= 80:  # Increased from 70
                results['status'] = 'blocked'
                results['blocked_reasons'].append(f'High risk score: {results["risk_score"]}')
            elif results['risk_score'] >= 50:  # Increased from 40
                results['status'] = 'suspicious'
            else:
                results['status'] = 'safe'
                
        except Exception as e:
            results['status'] = 'error'
            results['warnings'].append(f'Error during security check: {str(e)}')
        
        return results
    
    @staticmethod
    def check_domain_risk(domain):
        """Check domain-specific risks"""
        risk = {'score': 0, 'warnings': []}
        
        # Very new or suspicious domains
        if len(domain) < 4:
            risk['score'] += 20
            risk['warnings'].append('Very short domain name')
        
        # Check for homograph attacks (mixed scripts)
        if SecurityScanner.has_suspicious_characters(domain):
            risk['score'] += 30
            risk['warnings'].append('Domain contains suspicious characters')
        
        # Check for typosquatting patterns
        if SecurityScanner.is_typosquatting_attempt(domain):
            risk['score'] += 25
            risk['warnings'].append('Possible typosquatting attempt')
        
        return risk
    
    @staticmethod
    def analyze_url_structure(url):
        """Analyze URL structure for suspicious patterns"""
        risk = {'score': 0, 'warnings': []}
        
        # Very long URLs are suspicious
        if len(url) > 200:
            risk['score'] += 15
            risk['warnings'].append('Unusually long URL')
        
        # Too many subdomains
        parsed = urlparse(url)
        subdomain_count = len(parsed.netloc.split('.')) - 2
        if subdomain_count > 3:
            risk['score'] += 20
            risk['warnings'].append('Too many subdomains')
        
        # Suspicious parameters
        if parsed.query:
            if len(parsed.query) > 100:
                risk['score'] += 10
                risk['warnings'].append('Long query parameters')
            
            # Check for suspicious parameter patterns
            suspicious_params = ['redirect', 'goto', 'url', 'link', 'next', 'target']
            if any(param in parsed.query.lower() for param in suspicious_params):
                risk['score'] += 15
                risk['warnings'].append('Suspicious redirect parameters')
        
        return risk
    
    @staticmethod
    def has_suspicious_characters(domain):
        """Check for suspicious characters in domain (homograph attacks)"""
        # Basic check for non-ASCII characters that could be homograph attacks
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True
    
    @staticmethod
    def is_typosquatting_attempt(domain):
        """Check if domain might be typosquatting popular sites"""
        popular_domains = [
            'google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix',
            'paypal', 'ebay', 'twitter', 'instagram', 'linkedin', 'github',
            'dropbox', 'spotify', 'reddit', 'yahoo', 'youtube'
        ]
        
        domain_base = domain.split('.')[0].lower()
        
        for popular in popular_domains:
            # Check for slight variations
            if (len(domain_base) == len(popular) and 
                sum(a != b for a, b in zip(domain_base, popular)) == 1):
                return True
            
            # Check for character substitutions
            if (domain_base.replace('0', 'o').replace('1', 'i').replace('3', 'e') == popular or
                domain_base.replace('o', '0').replace('i', '1').replace('e', '3') == popular):
                return True
        
        return False
    
    @staticmethod
    def can_resolve_domain(domain):
        """Check if domain can be resolved"""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.gaierror, socket.herror):
            return False
    
    @staticmethod
    def scan_url_with_virustotal(url):
        """Enhanced VirusTotal scanning"""
        if not hasattr(settings, 'VIRUSTOTAL_API_KEY') or not settings.VIRUSTOTAL_API_KEY:
            return {'status': 'error', 'message': 'VirusTotal API key not configured'}
        
        api_key = settings.VIRUSTOTAL_API_KEY
        
        # First, submit URL for scanning
        submit_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        submit_params = {'apikey': api_key, 'url': url}
        
        try:
            # Submit for scanning
            submit_response = requests.post(submit_url, data=submit_params, timeout=10)
            
            # Check existing report
            report_url = "https://www.virustotal.com/vtapi/v2/url/report"
            report_params = {'apikey': api_key, 'resource': url, 'allinfo': True}
            
            report_response = requests.get(report_url, params=report_params, timeout=10)
            result = report_response.json()
            
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                
                if positives > 2:  # More than 2 engines flagged it
                    return {
                        'status': 'malicious',
                        'positives': positives,
                        'total': total,
                        'details': result
                    }
                elif positives > 0:
                    return {
                        'status': 'suspicious',
                        'positives': positives,
                        'total': total,
                        'details': result
                    }
                else:
                    return {'status': 'safe', 'details': result}
            else:
                return {'status': 'unknown', 'message': 'URL not found in VirusTotal database'}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @staticmethod
    def check_domain_reputation(domain):
        """Enhanced domain reputation check"""
        # Use comprehensive check instead
        fake_url = f"https://{domain}/"
        return SecurityScanner.comprehensive_url_check(fake_url)
    
    @staticmethod
    def is_nested_shortener(url):
        """Check if URL is from a competing URL shortener - updated logic"""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()
        
        # First check if it's an allowed service
        if any(allowed in domain for allowed in SecurityScanner.ALLOWED_SERVICES):
            return False
        
        # Only block major competing shorteners
        return any(shortener in domain for shortener in SecurityScanner.BLOCKED_SHORTENERS)
    
    @staticmethod
    def check_url_safety_with_google(url):
        """Check URL with Google Safe Browsing API (if configured)"""
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY'):
            return {'status': 'unknown', 'message': 'Google Safe Browsing API not configured'}
        
        api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "your-app-name",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(api_url, json=payload, timeout=10)
            result = response.json()
            
            if result.get('matches'):
                return {'status': 'malicious', 'details': result}
            else:
                return {'status': 'safe', 'details': result}
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

# Keep the existing RateLimiter class and other functions...
class RateLimiter:
    """Rate limiting utilities"""
    
    @staticmethod
    def is_rate_limited(request, action='url_create'):
        """Check if user/IP is rate limited"""
        settings_obj = SecuritySettings.objects.first()
        if not settings_obj or not settings_obj.enable_rate_limiting:
            return False
        
        ip = get_client_ip(request)
        user = request.user if request.user.is_authenticated else None
        
        # Check hourly limit
        hour_key = f"rate_limit:{action}:{ip}:hour"
        hour_count = cache.get(hour_key, 0)
        
        if hour_count >= settings_obj.max_urls_per_hour:
            RateLimitLog.objects.create(
                ip_address=ip,
                user=user,
                action=action,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                blocked=True
            )
            return True
        
        # Check daily limit
        day_key = f"rate_limit:{action}:{ip}:day"
        day_count = cache.get(day_key, 0)
        
        if day_count >= settings_obj.max_urls_per_day:
            RateLimitLog.objects.create(
                ip_address=ip,
                user=user,
                action=action,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                blocked=True
            )
            return True
        
        # Increment counters
        cache.set(hour_key, hour_count + 1, 3600)  # 1 hour
        cache.set(day_key, day_count + 1, 86400)   # 24 hours
        
        # Log the action
        RateLimitLog.objects.create(
            ip_address=ip,
            user=user,
            action=action,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            blocked=False
        )
        
        return False
    
    @staticmethod
    def check_suspicious_behavior(request):
        """Check for suspicious behavior patterns"""
        ip = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Check for bot-like user agents
        bot_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python'
        ]
        
        if any(pattern in user_agent.lower() for pattern in bot_patterns):
            SuspiciousActivity.objects.create(
                ip_address=ip,
                user=request.user if request.user.is_authenticated else None,
                activity_type='bot_behavior',
                description=f'Bot-like user agent: {user_agent}',
                severity=5,
                metadata={'user_agent': user_agent}
            )
            return True
        
        # Check rapid requests
        recent_requests = RateLimitLog.objects.filter(
            ip_address=ip,
            timestamp__gte=timezone.now() - timedelta(minutes=1)
        ).count()
        
        if recent_requests > 20:  # More than 20 requests per minute
            SuspiciousActivity.objects.create(
                ip_address=ip,
                user=request.user if request.user.is_authenticated else None,
                activity_type='rapid_creation',
                description=f'Rapid requests: {recent_requests} in 1 minute',
                severity=7,
                metadata={'requests_per_minute': recent_requests}
            )
            return True
        
        return False

def get_client_ip(request):
    """Get real client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip