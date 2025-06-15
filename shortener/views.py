from django.shortcuts import render, redirect, get_object_or_404, HttpResponseRedirect
from django.http import Http404, JsonResponse, HttpResponse
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.contrib import messages
from django.views.decorators.http import require_POST
import qrcode
import io
from django.db.models import Sum, Count 
import base64
from PIL import Image
from django.views.decorators.csrf import csrf_protect
from .models import URL, ClickAnalytics
from .forms import URLForm
from .models import (
    URL, ClickAnalytics, SecurityScan, SuspiciousActivity, 
    LinkReport, BlockedDomain, WhitelistedDomain, SecuritySettings
)
from .forms import URLForm
# Import security utilities if they exist
try:
    from .security.utils import SecurityScanner, RateLimiter, get_client_ip
    from .security.decorators import require_captcha, security_scan_required
except ImportError:
    # If security modules don't exist, create dummy functions
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def require_captcha(func):
        return func
    
    def security_scan_required(func):
        return func

import json
import csv
from django.contrib.admin.views.decorators import staff_member_required
from urllib.parse import urlparse
from django.core.cache import cache
from django.db import models
import logging
import requests

# HELPER FUNCTIONS FOR DOMAIN HANDLING
def get_site_url():
    """Get the correct site URL based on DEBUG mode"""
    return settings.SITE_URL

def build_short_url(short_code):
    """Build complete short URL with correct domain"""
    return f"{get_site_url()}{short_code}"

def get_domain_and_scheme():
    """Get domain and scheme separately"""
    return settings.SITE_DOMAIN, settings.SITE_SCHEME

def get_client_ip(request):
    """Get real client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def check_url_with_google_safebrowsing(url):
    """Check URL with Google Safe Browsing API"""
    if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
        return {'status': 'unknown', 'message': 'Google Safe Browsing API not configured'}
    
    api_key = settings.GOOGLE_SAFEBROWSING_API_KEY
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "url-shortener-app",
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
        response = requests.post(api_url, json=payload, timeout=10)
        
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

def check_url_with_virustotal(url):
    """Check URL with VirusTotal API"""
    if not hasattr(settings, 'VIRUSTOTAL_API_KEY') or not settings.VIRUSTOTAL_API_KEY:
        return {'status': 'unknown', 'message': 'VirusTotal API key not configured'}
    
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

def perform_security_scan(url_obj, url_string):
    """Perform comprehensive security scan including Google Safe Browsing and VirusTotal"""
    scan_details = {}
    threat_found = False
    highest_risk_score = 0
    block_reasons = []
    
    # 1. Check with Google Safe Browsing
    google_result = check_url_with_google_safebrowsing(url_string)
    scan_details['google_safebrowsing'] = google_result
    
    if google_result['status'] == 'malicious':
        threat_found = True
        highest_risk_score = max(highest_risk_score, 100)
        threats = google_result.get('threats', [])
        threat_types = [t.get('threatType', 'Unknown') for t in threats]
        block_reasons.append(f"Google Safe Browsing: {', '.join(threat_types)}")
    
    # 2. Check with VirusTotal
    vt_result = check_url_with_virustotal(url_string)
    scan_details['virustotal'] = vt_result
    
    if vt_result['status'] == 'malicious':
        threat_found = True
        highest_risk_score = max(highest_risk_score, 95)
        positives = vt_result.get('positives', 0)
        total = vt_result.get('total', 0)
        block_reasons.append(f"VirusTotal: {positives}/{total} engines detected threats")
    elif vt_result['status'] == 'suspicious':
        highest_risk_score = max(highest_risk_score, 60)
        positives = vt_result.get('positives', 0)
        total = vt_result.get('total', 0)
        block_reasons.append(f"VirusTotal: {positives}/{total} engines flagged as suspicious")
    
    # 3. Use existing SecurityScanner if available
    try:
        if hasattr(SecurityScanner, 'comprehensive_url_check'):
            local_scan = SecurityScanner.comprehensive_url_check(url_string)
            scan_details['local_scan'] = local_scan
            
            if local_scan['status'] == 'blocked':
                threat_found = True
                highest_risk_score = max(highest_risk_score, 90)
                block_reasons.extend(local_scan.get('blocked_reasons', []))
            elif local_scan['status'] == 'suspicious':
                highest_risk_score = max(highest_risk_score, local_scan.get('risk_score', 50))
    except (ImportError, AttributeError):
        # SecurityScanner not available, rely on external APIs
        pass
    
    # Determine final result
    if threat_found or highest_risk_score >= 80:
        scan_result = 'malicious'
        url_obj.is_safe = False
        url_obj.security_score = 0
        url_obj.temporarily_blocked = True
        url_obj.block_reason = '; '.join(block_reasons)
    elif highest_risk_score >= 40:
        scan_result = 'suspicious'
        url_obj.security_score = max(30, 100 - highest_risk_score)
    else:
        scan_result = 'safe'
        url_obj.security_score = 100
    
    # Create SecurityScan records for each service
    services_used = []
    
    if google_result['status'] != 'unknown':
        services_used.append('google_safebrowsing')
        try:
            SecurityScan.objects.create(
                url=url_obj,
                scan_type='reputation',
                result=google_result['status'],
                details={'google_safebrowsing': google_result},
                scanner_service='google_safebrowsing'
            )
        except Exception as e:
            logging.error(f"Failed to create Google Safe Browsing SecurityScan record: {e}")
    
    if vt_result['status'] != 'unknown':
        services_used.append('virustotal')
        try:
            SecurityScan.objects.create(
                url=url_obj,
                scan_type='malware',
                result=vt_result['status'],
                details={'virustotal': vt_result},
                scanner_service='virustotal'
            )
        except Exception as e:
            logging.error(f"Failed to create VirusTotal SecurityScan record: {e}")
    
    if 'local_scan' in scan_details:
        services_used.append('internal')
        try:
            SecurityScan.objects.create(
                url=url_obj,
                scan_type='reputation',
                result=scan_details['local_scan'].get('status', 'safe'),
                details={'local_scan': scan_details['local_scan']},
                scanner_service='internal'
            )
        except Exception as e:
            logging.error(f"Failed to create internal SecurityScan record: {e}")
    
    # Update last security scan timestamp
    url_obj.last_security_scan = timezone.now()
    url_obj.save()
    
    # Log security scan results
    logging.info(f"Security scan completed for {url_obj.short_code}: {scan_result} (services: {', '.join(services_used)})")
    
    return scan_result, scan_details

def index(request):
    """Homepage view with form to create short URL"""
    form = URLForm()
    # Get statistics for the homepage
    total_urls = URL.objects.count()
    total_clicks = URL.objects.filter(is_active=True).aggregate(Sum('clicks'))['clicks__sum'] or 0
    
    # Get recently created URLs from session
    recent_urls = []
    if 'recent_urls' in request.session:
        url_ids = request.session['recent_urls']
        recent_urls = URL.objects.filter(id__in=url_ids).order_by('-created_at')
    
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.save(commit=False)
            original_url = form.cleaned_data['original_url']
            
            # Handle custom short code
            custom_short_code = form.cleaned_data.get('custom_short_code')
            if custom_short_code:
                url.short_code = custom_short_code
                url.custom_code = True
            else:
                url.short_code = URL.create_short_code()
            
            # Save URL first to get an ID
            url.save()
            
            # Perform security scan with Google Safe Browsing
            scan_result, scan_details = perform_security_scan(url, original_url)
            
            # Check if URL was blocked during security scan
            if scan_result == 'malicious':
                # Delete the URL object and show error
                url.delete()
                messages.error(request, 'This URL has been identified as potentially harmful and cannot be shortened.')
                return render(request, 'shortener/index.html', {
                    'form': URLForm(),  # Reset form
                    'total_urls': total_urls,
                    'total_clicks': total_clicks,
                    'recent_urls': recent_urls
                })
            
            # If suspicious, show warning but allow creation
            if scan_result == 'suspicious':
                messages.warning(request, 'This URL has been flagged as potentially suspicious. Please verify the link before sharing.')
            
            # Store URL id in session for "recently created URLs"
            if 'recent_urls' not in request.session:
                request.session['recent_urls'] = []
            
            # Add the current URL to the start of the list and limit to 5 items
            recent_urls = request.session['recent_urls']
            if url.id not in recent_urls:
                recent_urls.insert(0, url.id)
                recent_urls = recent_urls[:5]  # Keep only the 5 most recent
                request.session['recent_urls'] = recent_urls
                request.session.modified = True
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            short_url = build_short_url(url.short_code)
            qr.add_data(short_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code image to base64 string
            buffer = io.BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return render(request, 'shortener/success.html', {
                'short_url': short_url,
                'original_url': url.original_url,
                'qr_code': qr_code_base64,
                'url': url,
                'is_custom': url.custom_code,
                'security_status': scan_result
            })
    
    return render(request, 'shortener/index.html', {
        'form': form, 
        'total_urls': total_urls,
        'total_clicks': total_clicks,
        'recent_urls': recent_urls
    })

def redirect_to_original(request, short_code):
    try:
        # Print debug info
        print(f"Redirect request: short_code={short_code}, host={request.get_host()}")
        
        # Find URL by short code
        url = URL.objects.get(short_code=short_code)
        
        # Print found URL for debugging
        print(f"Found URL: {url.short_code} -> {url.original_url}")
        
        # Check if URL is active
        if not url.is_active:
            return render(request, 'shortener/inactive.html', {'url': url})
        
        # Check if URL is temporarily blocked
        if url.temporarily_blocked:
            return render(request, 'shortener/blocked.html', {'url': url, 'reason': url.block_reason})
        
        # Additional security check before redirect (if URL hasn't been scanned recently)
        if not url.last_security_scan or (timezone.now() - url.last_security_scan).days > 7:
            # Re-scan URL if it's been more than 7 days
            scan_result, scan_details = perform_security_scan(url, url.original_url)
            
            # Refresh URL object from database to get updated values
            url.refresh_from_db()
            
            # Check again if URL is now blocked
            if url.temporarily_blocked:
                return render(request, 'shortener/blocked.html', {'url': url, 'reason': url.block_reason})
        
        # Track the click and redirect directly
        track_click(request, url)
        return HttpResponseRedirect(url.original_url)
        
    except URL.DoesNotExist:
        print(f"URL not found: {short_code}")
        raise Http404(f"The shortened URL '{short_code}' was not found.")

def track_click(request, url):
    """Enhanced click tracking with security monitoring"""
    host = request.get_host().split(':')[0]
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Increment the click counter
    url.increment_clicks()
    
    # Create analytics entry with enhanced security data
    ClickAnalytics.objects.create(
        url=url,
        ip_address=ip,
        referrer=request.META.get('HTTP_REFERER', ''),
        user_agent=user_agent,
        domain_used=host
    )
    
    # Security monitoring: Check for unusual click patterns
    recent_clicks = ClickAnalytics.objects.filter(
        url=url,
        clicked_at__gte=timezone.now() - timedelta(minutes=1)
    ).count()
    
    if recent_clicks > 50:  # More than 50 clicks per minute
        try:
            SuspiciousActivity.objects.create(
                ip_address=ip,
                activity_type='suspicious_pattern',
                description=f'Unusual click pattern for {url.short_code}: {recent_clicks} clicks in 1 minute',
                severity=7,
                metadata={
                    'short_code': url.short_code,
                    'clicks_per_minute': recent_clicks,
                    'user_agent': user_agent
                }
            )
            
            # Temporarily increase security monitoring for this URL
            url.security_score = max(0, url.security_score - 10)
            url.save()
        except Exception as e:
            print(f"Error creating suspicious activity log: {e}")

def stats(request, short_code):
    """Show statistics for a given URL"""
    url = get_object_or_404(URL, short_code=short_code)
    
    # Generate QR code with correct domain
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    short_url = build_short_url(url.short_code)
    qr.add_data(short_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code image to base64 string
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    # Get analytics data
    clicks_by_day = ClickAnalytics.objects.filter(url=url).extra({
        'day': "date(clicked_at)"
    }).values('day').annotate(count=models.Count('id')).order_by('day')
    
    # Prepare data for charts
    days = [item['day'].strftime('%Y-%m-%d') for item in clicks_by_day]
    counts = [item['count'] for item in clicks_by_day]
    
    # Get referrers
    referrers = ClickAnalytics.objects.filter(url=url).exclude(
        referrer=''
    ).values('referrer').annotate(
        count=models.Count('id')
    ).order_by('-count')[:5]
    
    # Get user agents (browsers)
    browsers = ClickAnalytics.objects.filter(url=url).exclude(
        user_agent=''
    ).values('user_agent').annotate(
        count=models.Count('id')
    ).order_by('-count')[:5]
    
    # Get security scan results
    security_scans = SecurityScan.objects.filter(url=url).order_by('-scanned_at')[:5]
    
    return render(request, 'shortener/stats.html', {
        'url': url,
        'short_url': short_url,
        'qr_code': qr_code_base64,
        'days': days,
        'counts': counts,
        'referrers': referrers,
        'browsers': browsers,
        'security_scans': security_scans
    })

def custom_url(request):
    """Custom URL page for creating URLs with custom short codes"""
    form = URLForm()
    error_message = None
    
    # Get statistics for the page
    total_urls = URL.objects.count()
    total_custom_urls = URL.objects.filter(custom_code=True).count()
    
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.save(commit=False)
            original_url = form.cleaned_data['original_url']
            
            # Get the custom short code (required for this page)
            custom_short_code = form.cleaned_data.get('custom_short_code', '').strip()
            if not custom_short_code:
                error_message = "Custom short code is required."
                return render(request, 'shortener/custom_url.html', {
                    'form': form,
                    'total_urls': total_urls,
                    'total_custom_urls': total_custom_urls,
                    'error_message': error_message
                })
            
            # Set the custom short code
            url.short_code = custom_short_code
            url.custom_code = True
            
            # Save the URL first to get an ID
            url.save()
            
            # Perform security scan with Google Safe Browsing
            scan_result, scan_details = perform_security_scan(url, original_url)
            
            # Check if URL was blocked during security scan
            if scan_result == 'malicious':
                # Delete the URL object and show error
                url.delete()
                error_message = "This URL has been identified as potentially harmful and cannot be shortened."
                return render(request, 'shortener/custom_url.html', {
                    'form': URLForm(),  # Reset form
                    'total_urls': total_urls,
                    'total_custom_urls': total_custom_urls,
                    'error_message': error_message
                })
            
            # If suspicious, show warning but allow creation
            if scan_result == 'suspicious':
                messages.warning(request, 'This URL has been flagged as potentially suspicious. Please verify the link before sharing.')
            
            # Store URL id in session for "recently created URLs"
            if 'recent_urls' not in request.session:
                request.session['recent_urls'] = []
            
            # Add the current URL to the start of the list and limit to 5 items
            recent_urls = request.session['recent_urls']
            if url.id not in recent_urls:
                recent_urls.insert(0, url.id)
                recent_urls = recent_urls[:5]  # Keep only the 5 most recent
                request.session['recent_urls'] = recent_urls
                request.session.modified = True
            
            # Generate QR code with correct domain
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            
            short_url = build_short_url(url.short_code)
            qr.add_data(short_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code image to base64 string
            buffer = io.BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return render(request, 'shortener/success.html', {
                'short_url': short_url,
                'original_url': url.original_url,
                'qr_code': qr_code_base64,
                'url': url,
                'is_custom': True,
                'security_status': scan_result
            })
    
    return render(request, 'shortener/custom_url.html', {
        'form': form,
        'total_urls': total_urls,
        'total_custom_urls': total_custom_urls,
        'error_message': error_message
    })

def faq(request):
    """FAQ page"""
    return render(request, 'shortener/faq.html')

def about(request):
    """About page"""
    return render(request, 'shortener/about.html')

@require_POST
def generate_qr(request):
    """Generate QR code for a URL"""
    url = request.POST.get('url', '')
    if not url:
        return JsonResponse({'success': False, 'error': 'URL is required'})
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code image to base64 string
    buffer = io.BytesIO()
    qr_img.save(buffer, format="PNG")
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    
    return JsonResponse({
        'success': True, 
        'qr_code': qr_code_base64
    })

def qr_code_generator(request):
    """QR Code Generator page"""
    return render(request, 'shortener/qr_code_generator.html')

def terms_view(request):
    """Terms of Service page"""
    return render(request, 'shortener/terms.html')

def privacy_view(request):
    """Privacy Policy page"""
    return render(request, 'shortener/privacy.html')

def contact_view(request):
    """Contact page with form processing"""
    form_success = False
    
    if request.method == 'POST':
        # Process the form data
        name = request.POST.get('name', '')
        email = request.POST.get('email', '')
        subject = request.POST.get('subject', '')
        message = request.POST.get('message', '')
        
        # Send email with the form data
        from django.core.mail import send_mail, BadHeaderError
        from django.conf import settings
        
        # Construct the email message
        email_subject = f"Contact Form: {subject}"
        email_message = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
        
        try:
            send_mail(
                email_subject,
                email_message,
                settings.DEFAULT_FROM_EMAIL,  # From email (use your configured default)
                [settings.CONTACT_EMAIL],  # To email(s)
                fail_silently=False,
            )
            
            # Mark the form as successful
            form_success = True
            
            # Add a success message
            messages.success(request, 'Your message has been sent! We will get back to you soon.')
            
        except BadHeaderError:
            messages.error(request, 'Invalid header found. Please check your input and try again.')
        except Exception as e:
            messages.error(request, f'An error occurred while sending your message. Please try again later.')
            print(f"Email sending error: {e}")  # For debugging
    
    return render(request, 'shortener/contact.html', {'form_success': form_success})

def report_link(request, short_code):
    """Allow users to report malicious links"""
    url = get_object_or_404(URL, short_code=short_code)
    
    if request.method == 'POST':
        report_type = request.POST.get('report_type')
        description = request.POST.get('description', '')
        reporter_email = request.POST.get('email', '')
        
        try:
            LinkReport.objects.create(
                url=url,
                reporter_ip=get_client_ip(request),
                reporter_email=reporter_email,
                report_type=report_type,
                description=description
            )
            
            # Increment flagged counter
            url.flagged_by_users += 1
            
            # Auto-block if too many reports
            if url.flagged_by_users >= 5:
                url.temporarily_blocked = True
                url.block_reason = 'Multiple user reports'
            
            url.save()
            
            # Trigger re-scan when URL is reported
            try:
                scan_result, scan_details = perform_security_scan(url, url.original_url)
                if scan_result == 'malicious':
                    messages.info(request, 'This link has been automatically blocked due to security concerns.')
                else:
                    messages.success(request, 'Thank you for your report. We will investigate this link.')
            except Exception as e:
                messages.success(request, 'Thank you for your report. We will investigate this link.')
                logging.error(f"Error during report-triggered scan: {e}")
        except Exception as e:
            messages.error(request, 'An error occurred while submitting your report. Please try again.')
            print(f"Error creating report: {e}")
        
        return redirect('index')
    
    return render(request, 'shortener/report_link.html', {'url': url})

@staff_member_required
def security_dashboard(request):
    """Security dashboard for admins"""
    try:
        recent_reports = LinkReport.objects.filter(investigated=False)[:10]
        suspicious_activities = SuspiciousActivity.objects.filter(resolved=False)[:10]
        blocked_domains = BlockedDomain.objects.filter(is_active=True)[:10]
        recent_scans = SecurityScan.objects.filter(result='malicious')[:10]
        
        # Get Google Safe Browsing statistics
        google_scans = SecurityScan.objects.filter(scanner_service='google_safebrowsing')
        google_stats = {
            'total_scans': google_scans.count(),
            'malicious_found': google_scans.filter(result='malicious').count(),
            'errors': google_scans.filter(result='error').count(),
        }
        
        context = {
            'recent_reports': recent_reports,
            'suspicious_activities': suspicious_activities,
            'blocked_domains': blocked_domains,
            'recent_scans': recent_scans,
            'google_stats': google_stats,
        }
        
        return render(request, 'shortener/security_dashboard.html', context)
    except Exception as e:
        messages.error(request, f'Error loading security dashboard: {str(e)}')
        return redirect('admin:index')

@staff_member_required
def rescan_url(request, url_id):
    """Manually trigger security rescan for a URL"""
    if request.method == 'POST':
        try:
            url = get_object_or_404(URL, id=url_id)
            scan_result, scan_details = perform_security_scan(url, url.original_url)
            
            return JsonResponse({
                'success': True,
                'scan_result': scan_result,
                'message': f'Scan completed. Result: {scan_result}'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@staff_member_required
def block_domain(request):
    """Block a domain"""
    if request.method == 'POST':
        domain = request.POST.get('domain')
        reason = request.POST.get('reason')
        
        try:
            BlockedDomain.objects.create(
                domain=domain,
                reason=reason,
                blocked_by=request.user
            )
            
            messages.success(request, f'Domain {domain} has been blocked.')
        except Exception as e:
            messages.error(request, f'Error blocking domain: {str(e)}')
        
        return redirect('security_dashboard')
    
    return redirect('security_dashboard')

@staff_member_required
def remove_blocked_domain(request, domain_id):
    """Remove a domain from blocklist"""
    if request.method == 'POST':
        try:
            domain = get_object_or_404(BlockedDomain, id=domain_id)
            domain.is_active = False
            domain.save()
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@staff_member_required
def security_settings_view(request):
    """View and update security settings"""
    settings_obj, created = SecuritySettings.objects.get_or_create(pk=1)
    
    if request.method == 'POST':
        # Update security settings
        settings_obj.enable_malware_scanning = request.POST.get('enable_malware_scanning') == 'on'
        settings_obj.enable_rate_limiting = request.POST.get('enable_rate_limiting') == 'on'
        settings_obj.enable_captcha = request.POST.get('enable_captcha') == 'on'
        
        try:
            settings_obj.max_urls_per_hour = int(request.POST.get('max_urls_per_hour', 50))
            settings_obj.max_urls_per_day = int(request.POST.get('max_urls_per_day', 500))
            settings_obj.suspicious_click_threshold = int(request.POST.get('suspicious_click_threshold', 100))
        except ValueError:
            messages.error(request, 'Please enter valid numbers for the limits.')
            return render(request, 'shortener/security_settings.html', {'settings': settings_obj})
        
        settings_obj.save()
        messages.success(request, 'Security settings updated successfully.')
    
    # Get API configuration status
    api_status = {
        'google_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY),
        'virustotal_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY),
        'redis_configured': 'redis' in str(settings.CACHES.get('default', {}).get('BACKEND', '')).lower()
    }
    
    # Get scanning statistics
    scan_stats = {
        'google_scans': SecurityScan.objects.filter(scanner_service='google_safebrowsing').count(),
        'google_malicious': SecurityScan.objects.filter(scanner_service='google_safebrowsing', result='malicious').count(),
        'vt_scans': SecurityScan.objects.filter(scanner_service='virustotal').count(),
        'vt_malicious': SecurityScan.objects.filter(scanner_service='virustotal', result='malicious').count(),
        'internal_scans': SecurityScan.objects.filter(scanner_service='internal').count(),
        'total_blocked': URL.objects.filter(temporarily_blocked=True).count(),
        'total_flagged': URL.objects.filter(flagged_by_users__gt=0).count()
    }
    
    context = {
        'settings': settings_obj,
        'api_status': api_status,
        'scan_stats': scan_stats
    }
    
    return render(request, 'shortener/security_settings.html', context)

@staff_member_required
def security_api_status(request):
    """Get real-time API status for dashboard"""
    try:
        # Test Google Safe Browsing API
        google_status = 'unknown'
        if hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and settings.GOOGLE_SAFEBROWSING_API_KEY:
            try:
                test_result = check_url_with_google_safebrowsing('https://google.com')
                google_status = 'working' if test_result['status'] in ['safe', 'malicious'] else 'error'
            except:
                google_status = 'error'
        else:
            google_status = 'not_configured'
        
        # Test VirusTotal API
        vt_status = 'unknown'
        if hasattr(settings, 'VIRUSTOTAL_API_KEY') and settings.VIRUSTOTAL_API_KEY:
            try:
                test_result = check_url_with_virustotal('https://google.com')
                vt_status = 'working' if test_result['status'] in ['safe', 'malicious', 'suspicious'] else 'error'
            except:
                vt_status = 'error'
        else:
            vt_status = 'not_configured'
        
        # Check Redis connection
        redis_status = 'unknown'
        try:
            from django.core.cache import cache
            cache.set('test_key', 'test_value', 10)
            test_value = cache.get('test_key')
            redis_status = 'working' if test_value == 'test_value' else 'error'
        except:
            redis_status = 'error'
        
        return JsonResponse({
            'success': True,
            'api_status': {
                'google_safebrowsing': google_status,
                'virustotal': vt_status,
                'redis_cache': redis_status
            },
            'last_check': timezone.now().isoformat()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@staff_member_required
def export_security_report_detailed(request):
    """Export detailed security report with API scan results"""
    try:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="detailed_security_report.csv"'
        
        writer = csv.writer(response)
        
        # Write header
        writer.writerow([
            'Date', 'URL Short Code', 'Original URL', 'Scan Type', 'Scanner Service', 
            'Result', 'Google Safe Browsing', 'VirusTotal', 'Local Scan', 'Details'
        ])
        
        # Get all security scans from the last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        scans = SecurityScan.objects.filter(
            scanned_at__gte=thirty_days_ago
        ).select_related('url').order_by('-scanned_at')[:1000]
        
        for scan in scans:
            # Extract details for each service
            google_result = ''
            vt_result = ''
            local_result = ''
            
            if 'google_safebrowsing' in scan.details:
                google_data = scan.details['google_safebrowsing']
                if google_data.get('threats'):
                    threats = [t.get('threatType', 'Unknown') for t in google_data['threats']]
                    google_result = f"Threats: {', '.join(threats)}"
                else:
                    google_result = google_data.get('status', 'Unknown')
            
            if 'virustotal' in scan.details:
                vt_data = scan.details['virustotal']
                if vt_data.get('positives'):
                    vt_result = f"{vt_data['positives']}/{vt_data.get('total', 0)} engines"
                else:
                    vt_result = vt_data.get('status', 'Unknown')
            
            if 'local_scan' in scan.details:
                local_data = scan.details['local_scan']
                if local_data.get('blocked_reasons'):
                    local_result = '; '.join(local_data['blocked_reasons'])
                else:
                    local_result = f"Risk Score: {local_data.get('risk_score', 0)}"
            
            writer.writerow([
                scan.scanned_at.strftime('%Y-%m-%d %H:%M:%S'),
                scan.url.short_code,
                scan.url.original_url,
                scan.scan_type,
                scan.scanner_service,
                scan.result,
                google_result,
                vt_result,
                local_result,
                str(scan.details)[:100] + '...' if len(str(scan.details)) > 100 else str(scan.details)
            ])
        
        return response
        
    except Exception as e:
        messages.error(request, f'Error generating detailed report: {str(e)}')
        return redirect('security_dashboard')

@staff_member_required
def security_analytics_view(request):
    """Security analytics dashboard with charts and statistics"""
    try:
        # Get date range (last 30 days)
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=30)
        
        # Daily scan statistics
        daily_scans = SecurityScan.objects.filter(
            scanned_at__date__gte=start_date
        ).extra({
            'day': 'date(scanned_at)'
        }).values('day', 'scanner_service', 'result').annotate(
            count=Count('id')
        ).order_by('day')
        
        # Threat type distribution from Google Safe Browsing
        google_threats = SecurityScan.objects.filter(
            scanner_service='google_safebrowsing',
            result='malicious',
            scanned_at__date__gte=start_date
        )
        
        threat_distribution = {}
        for scan in google_threats:
            google_data = scan.details.get('google_safebrowsing', {})
            threats = google_data.get('threats', [])
            for threat in threats:
                threat_type = threat.get('threatType', 'Unknown')
                threat_distribution[threat_type] = threat_distribution.get(threat_type, 0) + 1
        
        # VirusTotal detection rates
        vt_scans = SecurityScan.objects.filter(
            scanner_service='virustotal',
            scanned_at__date__gte=start_date
        )
        
        vt_stats = {
            'total_scans': vt_scans.count(),
            'malicious': vt_scans.filter(result='malicious').count(),
            'suspicious': vt_scans.filter(result='suspicious').count(),
            'safe': vt_scans.filter(result='safe').count(),
            'errors': vt_scans.filter(result='error').count()
        }
        
        # Top blocked domains
        blocked_urls = URL.objects.filter(
            temporarily_blocked=True,
            created_at__date__gte=start_date
        )
        
        domain_blocks = {}
        for url in blocked_urls:
            try:
                domain = urlparse(url.original_url).netloc
                domain_blocks[domain] = domain_blocks.get(domain, 0) + 1
            except:
                pass
        
        top_blocked_domains = sorted(domain_blocks.items(), key=lambda x: x[1], reverse=True)[:10]
        
        context = {
            'daily_scans': list(daily_scans),
            'threat_distribution': threat_distribution,
            'vt_stats': vt_stats,
            'top_blocked_domains': top_blocked_domains,
            'date_range': {
                'start': start_date.isoformat(),
                'end': end_date.isoformat()
            }
        }
        
        return render(request, 'shortener/security_analytics.html', context)
        
    except Exception as e:
        messages.error(request, f'Error loading security analytics: {str(e)}')
        return redirect('security_dashboard')

@staff_member_required
def whitelist_domain(request):
    """Add a domain to the whitelist"""
    if request.method == 'POST':
        domain = request.POST.get('domain', '').strip().lower()
        
        if not domain:
            messages.error(request, 'Domain is required.')
            return redirect('security_dashboard')
        
        try:
            # Remove http/https if present
            if domain.startswith(('http://', 'https://')):
                domain = urlparse(domain).netloc
            
            whitelist_obj, created = WhitelistedDomain.objects.get_or_create(
                domain=domain,
                defaults={'added_by': request.user}
            )
            
            if created:
                messages.success(request, f'Domain {domain} has been whitelisted.')
                
                # Unblock any URLs from this domain
                blocked_urls = URL.objects.filter(
                    temporarily_blocked=True,
                    original_url__icontains=domain
                )
                
                unblocked_count = 0
                for url in blocked_urls:
                    if urlparse(url.original_url).netloc.lower() == domain:
                        url.temporarily_blocked = False
                        url.is_safe = True
                        url.security_score = 100
                        url.block_reason = ''
                        url.save()
                        unblocked_count += 1
                
                if unblocked_count > 0:
                    messages.info(request, f'Unblocked {unblocked_count} URLs from {domain}.')
            else:
                messages.info(request, f'Domain {domain} is already whitelisted.')
                
        except Exception as e:
            messages.error(request, f'Error whitelisting domain: {str(e)}')
    
    return redirect('security_dashboard')

@staff_member_required
def remove_whitelist_domain(request, domain_id):
    """Remove a domain from the whitelist"""
    if request.method == 'POST':
        try:
            domain = get_object_or_404(WhitelistedDomain, id=domain_id)
            domain_name = domain.domain
            domain.delete()
            
            messages.success(request, f'Domain {domain_name} has been removed from whitelist.')
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@staff_member_required
def manual_url_scan(request):
    """Manually scan a specific URL"""
    if request.method == 'POST':
        url_to_scan = request.POST.get('url', '').strip()
        scan_services = request.POST.getlist('services')  # ['google', 'virustotal', 'local']
        
        if not url_to_scan:
            return JsonResponse({'success': False, 'error': 'URL is required'})
        
        try:
            # Create a temporary URL object for scanning
            temp_url = URL(original_url=url_to_scan, short_code='temp_scan')
            
            scan_results = {}
            overall_status = 'safe'
            
            # Scan with selected services
            if 'google' in scan_services:
                google_result = check_url_with_google_safebrowsing(url_to_scan)
                scan_results['google_safebrowsing'] = google_result
                if google_result['status'] == 'malicious':
                    overall_status = 'malicious'
            
            if 'virustotal' in scan_services:
                vt_result = check_url_with_virustotal(url_to_scan)
                scan_results['virustotal'] = vt_result
                if vt_result['status'] == 'malicious':
                    overall_status = 'malicious'
                elif vt_result['status'] == 'suspicious' and overall_status == 'safe':
                    overall_status = 'suspicious'
            
            if 'local' in scan_services:
                try:
                    if hasattr(SecurityScanner, 'comprehensive_url_check'):
                        local_result = SecurityScanner.comprehensive_url_check(url_to_scan)
                        scan_results['local_scan'] = local_result
                        if local_result['status'] == 'blocked':
                            overall_status = 'malicious'
                        elif local_result['status'] == 'suspicious' and overall_status == 'safe':
                            overall_status = 'suspicious'
                except Exception as e:
                    scan_results['local_scan'] = {'status': 'error', 'message': str(e)}
            
            return JsonResponse({
                'success': True,
                'url': url_to_scan,
                'overall_status': overall_status,
                'scan_results': scan_results,
                'scanned_at': timezone.now().isoformat()
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return render(request, 'shortener/manual_scan.html')


@staff_member_required 
def test_google_safebrowsing(request):
    """Test Google Safe Browsing API configuration"""
    if request.method == 'POST':
        test_url = request.POST.get('test_url', 'http://malware.testing.google.test/testing/malware/')
        
        try:
            result = check_url_with_google_safebrowsing(test_url)
            
            return JsonResponse({
                'success': True,
                'test_url': test_url,
                'result': result,
                'api_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY)
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
                'api_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY)
            })
    
    return render(request, 'shortener/test_safebrowsing.html')

@staff_member_required 
def test_virustotal(request):
    """Test VirusTotal API configuration"""
    if request.method == 'POST':
        test_url = request.POST.get('test_url', 'http://malware.testing.google.test/testing/malware/')
        
        try:
            result = check_url_with_virustotal(test_url)
            
            return JsonResponse({
                'success': True,
                'test_url': test_url,
                'result': result,
                'api_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY)
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
                'api_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY)
            })
    
    return render(request, 'shortener/test_virustotal.html')

@staff_member_required
def test_all_security_apis(request):
    """Test both Google Safe Browsing and VirusTotal APIs"""
    if request.method == 'POST':
        test_url = request.POST.get('test_url', 'http://malware.testing.google.test/testing/malware/')
        
        try:
            # Test Google Safe Browsing
            google_result = check_url_with_google_safebrowsing(test_url)
            
            # Test VirusTotal
            vt_result = check_url_with_virustotal(test_url)
            
            # Test local scanner if available
            local_result = None
            try:
                if hasattr(SecurityScanner, 'comprehensive_url_check'):
                    local_result = SecurityScanner.comprehensive_url_check(test_url)
            except Exception as e:
                local_result = {'status': 'error', 'message': str(e)}
            
            return JsonResponse({
                'success': True,
                'test_url': test_url,
                'results': {
                    'google_safebrowsing': google_result,
                    'virustotal': vt_result,
                    'local_scan': local_result
                },
                'api_status': {
                    'google_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY),
                    'virustotal_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY),
                    'local_scanner_available': hasattr(SecurityScanner, 'comprehensive_url_check')
                },
                'recommendations': get_api_recommendations(google_result, vt_result, local_result)
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e),
                'api_status': {
                    'google_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY),
                    'virustotal_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY),
                    'local_scanner_available': hasattr(SecurityScanner, 'comprehensive_url_check')
                }
            })
    
    # GET request - show the test form
    context = {
        'google_configured': hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') and bool(settings.GOOGLE_SAFEBROWSING_API_KEY),
        'virustotal_configured': hasattr(settings, 'VIRUSTOTAL_API_KEY') and bool(settings.VIRUSTOTAL_API_KEY),
        'test_urls': [
            'http://malware.testing.google.test/testing/malware/',
            'https://secure-bank-login.suspicious-domain.com',
            'https://www.google.com',
            'https://github.com',
            'https://example.com'
        ]
    }
    
    return render(request, 'shortener/test_all_apis.html', context)

# Error handlers
def handler404(request, exception):
    """Custom 404 error handler"""
    return render(request, 'shortener/404.html', status=404)

def handler500(request):
    """Custom 500 error handler"""
    return render(request, 'shortener/500.html', status=500)

# API Views (if needed)
def api_shorten_url(request):
    """API endpoint to shorten URLs with Google Safe Browsing integration"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            original_url = data.get('url')
            custom_code = data.get('custom_code', '')
            
            if not original_url:
                return JsonResponse({'error': 'URL is required'}, status=400)
            
            # Create URL object
            url = URL(original_url=original_url)
            
            if custom_code:
                if URL.objects.filter(short_code=custom_code).exists():
                    return JsonResponse({'error': 'Custom code already exists'}, status=400)
                url.short_code = custom_code
                url.custom_code = True
            else:
                url.short_code = URL.create_short_code()
            
            # Save URL first to get an ID
            url.save()
            
            # Perform security scan with Google Safe Browsing
            scan_result, scan_details = perform_security_scan(url, original_url)
            
            # Check if URL was blocked during security scan
            if scan_result == 'malicious':
                # Delete the URL object and return error
                url.delete()
                return JsonResponse({
                    'error': 'This URL has been identified as potentially harmful and cannot be shortened.',
                    'scan_details': scan_details
                }, status=400)
            
            response_data = {
                'success': True,
                'short_url': build_short_url(url.short_code),
                'short_code': url.short_code,
                'original_url': url.original_url,
                'security_status': scan_result
            }
            
            # Add warning for suspicious URLs
            if scan_result == 'suspicious':
                response_data['warning'] = 'This URL has been flagged as potentially suspicious.'
            
            return JsonResponse(response_data)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def api_url_stats(request, short_code):
    """API endpoint to get URL statistics with security information"""
    try:
        url = get_object_or_404(URL, short_code=short_code)
        
        # Get click count by day for the last 30 days
        from datetime import date, timedelta
        thirty_days_ago = date.today() - timedelta(days=30)
        
        daily_clicks = ClickAnalytics.objects.filter(
            url=url,
            clicked_at__date__gte=thirty_days_ago
        ).extra({'day': 'date(clicked_at)'}).values('day').annotate(
            clicks=Count('id')
        ).order_by('day')
        
        # Get security scan information
        latest_scan = SecurityScan.objects.filter(url=url).order_by('-scanned_at').first()
        security_info = None
        if latest_scan:
            security_info = {
                'last_scan': latest_scan.scanned_at.isoformat(),
                'result': latest_scan.result,
                'scanner_service': latest_scan.scanner_service
            }
        
        return JsonResponse({
            'success': True,
            'short_code': url.short_code,
            'original_url': url.original_url,
            'total_clicks': url.clicks,
            'created_at': url.created_at.isoformat(),
            'is_active': url.is_active,
            'is_safe': url.is_safe,
            'security_score': url.security_score,
            'temporarily_blocked': url.temporarily_blocked,
            'block_reason': url.block_reason,
            'flagged_by_users': url.flagged_by_users,
            'daily_clicks': list(daily_clicks),
            'security_info': security_info
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@staff_member_required
def api_security_stats(request):
    """API endpoint for security statistics"""
    try:
        # Get overall security statistics
        total_urls = URL.objects.count()
        safe_urls = URL.objects.filter(is_safe=True).count()
        blocked_urls = URL.objects.filter(temporarily_blocked=True).count()
        flagged_urls = URL.objects.filter(flagged_by_users__gt=0).count()
        
        # Google Safe Browsing statistics
        google_scans = SecurityScan.objects.filter(scanner_service='google_safebrowsing')
        google_malicious = google_scans.filter(result='malicious').count()
        google_errors = google_scans.filter(result='error').count()
        
        # Recent threat activity
        recent_threats = SecurityScan.objects.filter(
            result='malicious',
            scanned_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        # Suspicious activity in last 24 hours
        recent_suspicious = SuspiciousActivity.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24),
            resolved=False
        ).count()
        
        return JsonResponse({
            'success': True,
            'statistics': {
                'total_urls': total_urls,
                'safe_urls': safe_urls,
                'blocked_urls': blocked_urls,
                'flagged_urls': flagged_urls,
                'safety_percentage': round((safe_urls / total_urls * 100) if total_urls > 0 else 100, 2),
                'google_safebrowsing': {
                    'total_scans': google_scans.count(),
                    'malicious_found': google_malicious,
                    'errors': google_errors
                },
                'recent_threats': recent_threats,
                'recent_suspicious_activity': recent_suspicious
            }
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@staff_member_required
def bulk_rescan_urls(request):
    """Bulk rescan URLs for security threats"""
    if request.method == 'POST':
        try:
            # Get URLs that haven't been scanned in the last 24 hours or have low security scores
            urls_to_scan = URL.objects.filter(
                models.Q(last_security_scan__isnull=True) |
                models.Q(last_security_scan__lt=timezone.now() - timedelta(hours=24)) |
                models.Q(security_score__lt=70)
            ).filter(is_active=True)[:50]  # Limit to 50 URLs to avoid API limits
            
            scanned_count = 0
            blocked_count = 0
            errors = []
            
            for url in urls_to_scan:
                try:
                    scan_result, scan_details = perform_security_scan(url, url.original_url)
                    scanned_count += 1
                    
                    if scan_result == 'malicious':
                        blocked_count += 1
                        
                except Exception as e:
                    errors.append(f"Error scanning {url.short_code}: {str(e)}")
                    continue
            
            return JsonResponse({
                'success': True,
                'scanned_count': scanned_count,
                'blocked_count': blocked_count,
                'errors': errors,
                'message': f'Scanned {scanned_count} URLs, blocked {blocked_count} malicious URLs'
            })
            
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def check_url_security_status(request):
    """Public endpoint to check security status of a URL"""
    if request.method == 'GET':
        short_code = request.GET.get('code')
        if not short_code:
            return JsonResponse({'error': 'Short code is required'}, status=400)
        
        try:
            url = get_object_or_404(URL, short_code=short_code)
            
            # Get latest security scan
            latest_scan = SecurityScan.objects.filter(url=url).order_by('-scanned_at').first()
            
            return JsonResponse({
                'success': True,
                'short_code': url.short_code,
                'is_safe': url.is_safe,
                'security_score': url.security_score,
                'temporarily_blocked': url.temporarily_blocked,
                'block_reason': url.block_reason if url.temporarily_blocked else None,
                'flagged_by_users': url.flagged_by_users,
                'last_security_scan': url.last_security_scan.isoformat() if url.last_security_scan else None,
                'latest_scan_result': latest_scan.result if latest_scan else None
            })
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)



# Add this function to your views.py file

def get_api_recommendations(google_result, vt_result, local_result):
    """Generate recommendations based on API test results"""
    recommendations = []
    
    # Google Safe Browsing recommendations
    if google_result['status'] == 'error':
        if 'API key' in google_result.get('message', ''):
            recommendations.append({
                'type': 'error',
                'service': 'Google Safe Browsing',
                'message': 'API key not configured or invalid. Please check your GOOGLE_SAFEBROWSING_API_KEY setting.'
            })
        elif 'quota' in google_result.get('message', '').lower():
            recommendations.append({
                'type': 'warning',
                'service': 'Google Safe Browsing',
                'message': 'API quota exceeded. Consider upgrading your Google Cloud plan.'
            })
        else:
            recommendations.append({
                'type': 'error',
                'service': 'Google Safe Browsing',
                'message': f'API error: {google_result.get("message", "Unknown error")}'
            })
    elif google_result['status'] == 'safe':
        recommendations.append({
            'type': 'success',
            'service': 'Google Safe Browsing',
            'message': 'API is working correctly and can detect safe URLs.'
        })
    elif google_result['status'] == 'malicious':
        recommendations.append({
            'type': 'success',
            'service': 'Google Safe Browsing',
            'message': 'API is working correctly and successfully detected the test malicious URL.'
        })
    
    # VirusTotal recommendations
    if vt_result['status'] == 'error':
        if 'API key' in vt_result.get('message', ''):
            recommendations.append({
                'type': 'error',
                'service': 'VirusTotal',
                'message': 'API key not configured or invalid. Please check your VIRUSTOTAL_API_KEY setting.'
            })
        elif 'quota' in vt_result.get('message', '').lower():
            recommendations.append({
                'type': 'warning',
                'service': 'VirusTotal',
                'message': 'API quota exceeded. Consider upgrading to VirusTotal Premium.'
            })
        else:
            recommendations.append({
                'type': 'error',
                'service': 'VirusTotal',
                'message': f'API error: {vt_result.get("message", "Unknown error")}'
            })
    elif vt_result['status'] in ['safe', 'unknown']:
        recommendations.append({
            'type': 'success',
            'service': 'VirusTotal',
            'message': 'API is working correctly. Note: VirusTotal may not have data for all test URLs.'
        })
    elif vt_result['status'] == 'malicious':
        recommendations.append({
            'type': 'success',
            'service': 'VirusTotal',
            'message': f'API working correctly. Detected threats: {vt_result.get("positives", 0)}/{vt_result.get("total", 0)} engines.'
        })
    elif vt_result['status'] == 'suspicious':
        recommendations.append({
            'type': 'info',
            'service': 'VirusTotal',
            'message': f'API working correctly. Some engines flagged as suspicious: {vt_result.get("positives", 0)}/{vt_result.get("total", 0)}.'
        })
    
    # Local scanner recommendations
    if local_result:
        if local_result['status'] == 'error':
            recommendations.append({
                'type': 'warning',
                'service': 'Local Scanner',
                'message': 'Local security scanner encountered an error. This is optional but provides additional protection.'
            })
        else:
            recommendations.append({
                'type': 'success',
                'service': 'Local Scanner',
                'message': 'Local security scanner is working correctly.'
            })
    else:
        recommendations.append({
            'type': 'info',
            'service': 'Local Scanner',
            'message': 'Local security scanner not available. This is optional but recommended for enhanced protection.'
        })
    
    # Overall recommendations
    working_apis = sum(1 for result in [google_result, vt_result] if result['status'] not in ['error', 'unknown'])
    
    if working_apis == 0:
        recommendations.append({
            'type': 'error',
            'service': 'Overall',
            'message': 'No security APIs are working. Your URL shortener has no malware protection!'
        })
    elif working_apis == 1:
        recommendations.append({
            'type': 'warning',
            'service': 'Overall',
            'message': 'Only one security API is working. Consider fixing the other API for better protection.'
        })
    else:
        recommendations.append({
            'type': 'success',
            'service': 'Overall',
            'message': 'Multiple security APIs are working. Your URL shortener has robust malware protection!'
        })
    
    return recommendations

# Also add this missing function to your views.py if it doesn't exist:

@staff_member_required
def export_security_report(request):
    """Export basic security report as CSV"""
    try:
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="security_report.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Date', 'Type', 'Details', 'Severity', 'Status'])
        
        # Add reports
        for report in LinkReport.objects.all()[:100]:
            writer.writerow([
                report.reported_at.strftime('%Y-%m-%d %H:%M'),
                f'Report: {report.report_type}',
                f'{report.url.short_code} - {report.description[:50]}',
                'High' if not report.investigated else 'Resolved',
                'Pending' if not report.investigated else 'Investigated'
            ])
        
        # Add suspicious activities
        for activity in SuspiciousActivity.objects.all()[:100]:
            writer.writerow([
                activity.timestamp.strftime('%Y-%m-%d %H:%M'),
                f'Activity: {activity.activity_type}',
                f'{activity.ip_address} - {activity.description[:50]}',
                f'Level {activity.severity}',
                'Resolved' if activity.resolved else 'Active'
            ])
        
        return response
    except Exception as e:
        messages.error(request, f'Error generating report: {str(e)}')
        return redirect('security_dashboard')


@csrf_protect
@require_POST
def check_short_code_availability(request):
    """
    AJAX endpoint to check if a custom short code is available
    """
    try:
        data = json.loads(request.body)
        short_code = data.get('short_code', '').strip()
        
        if not short_code:
            return JsonResponse({
                'available': False,
                'error': 'Short code is required'
            })
        
        # Validate format first
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', short_code):
            return JsonResponse({
                'available': False,
                'error': 'Invalid characters'
            })
        
        # Check length
        if len(short_code) < 3 or len(short_code) > 10:
            return JsonResponse({
                'available': False,
                'error': 'Invalid length'
            })
        
        # Check if exists (case-insensitive)
        exists = URL.objects.filter(short_code__iexact=short_code).exists()
        
        # Check reserved words
        reserved_words = [
            'admin', 'api', 'www', 'mail', 'ftp', 'localhost', 'stats', 'analytics',
            'dashboard', 'login', 'logout', 'register', 'signup', 'signin', 'user',
            'users', 'profile', 'settings', 'config', 'help', 'support', 'contact',
            'about', 'terms', 'privacy', 'policy', 'legal', 'dmca', 'abuse',
            'security', 'qr', 'qrcode', 'short', 'url', 'link', 'redirect',
            'goto', 'go', 'click', 'visit', 'view', 'show', 'display', 'index',
            'home', 'test', 'demo', 'example', 'sample'
        ]
        
        is_reserved = short_code.lower() in reserved_words
        
        return JsonResponse({
            'available': not exists and not is_reserved,
            'exists': exists,
            'reserved': is_reserved
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'available': False,
            'error': 'Invalid JSON'
        })
    except Exception as e:
        return JsonResponse({
            'available': False,
            'error': 'Server error'
        })
