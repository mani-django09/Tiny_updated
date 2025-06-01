from functools import wraps
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from urllib.parse import urlparse

# Import the required functions and models
from .utils import get_client_ip, SecurityScanner
from ..models import SuspiciousActivity

def require_captcha(view_func):
    """Decorator to require captcha for suspicious users"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        ip = get_client_ip(request)
        
        # Check if IP has recent suspicious activity
        recent_suspicious = SuspiciousActivity.objects.filter(
            ip_address=ip,
            timestamp__gte=timezone.now() - timedelta(hours=24),
            severity__gte=5
        ).exists()
        
        if recent_suspicious:
            if request.method == 'POST':
                # In a real implementation, you'd integrate with reCAPTCHA
                captcha_response = request.POST.get('captcha_response')
                if not captcha_response:
                    return render(request, 'shortener/captcha_required.html')
        
        return view_func(request, *args, **kwargs)
    return wrapper

def security_scan_required(view_func):
    """Decorator to require security scan before URL creation"""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method == 'POST':
            original_url = request.POST.get('original_url')
            if original_url:
                # Perform security scan
                domain = urlparse(original_url).netloc
                reputation = SecurityScanner.check_domain_reputation(domain)
                
                if reputation['status'] == 'blocked':
                    return render(request, 'shortener/url_blocked.html', {
                        'reason': reputation['reason']
                    })
        
        return view_func(request, *args, **kwargs)
    return wrapper