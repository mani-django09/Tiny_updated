from django.shortcuts import render, redirect, get_object_or_404,HttpResponseRedirect
from django.http import Http404, JsonResponse
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
from .models import URL, ClickAnalytics
from .forms import URLForm
from .models import URL, ClickAnalytics, SecurityScan, SuspiciousActivity, LinkReport, BlockedDomain
from .forms import URLForm
from .security.utils import SecurityScanner, RateLimiter, get_client_ip
from .security.decorators import require_captcha, security_scan_required
import json
import csv
from django.contrib.admin.views.decorators import staff_member_required  # Add this import
from urllib.parse import urlparse

from .models import (
    URL, ClickAnalytics, SecurityScan, SuspiciousActivity, 
    LinkReport, BlockedDomain, WhitelistedDomain, SecuritySettings
)
from .forms import URLForm

# Import security utilities
from .security.utils import SecurityScanner, RateLimiter, get_client_ip
from .security.decorators import require_captcha, security_scan_required


@require_captcha
@security_scan_required
def index(request):
    """Enhanced homepage view with comprehensive security features"""
    form = URLForm()
    
    # Get statistics for the homepage (only count safe URLs)
    total_urls = URL.objects.filter(is_safe=True, temporarily_blocked=False).count()
    total_clicks = URL.objects.filter(
        is_active=True, 
        is_safe=True, 
        temporarily_blocked=False
    ).aggregate(total=Sum('clicks'))['total'] or 0
    
    # Get recently created URLs from session (only safe ones)
    recent_urls = []
    if 'recent_urls' in request.session:
        url_ids = request.session['recent_urls']
        recent_urls = URL.objects.filter(
            id__in=url_ids, 
            is_safe=True, 
            temporarily_blocked=False
        ).order_by('-created_at')
    
    if request.method == 'POST':
        # Check rate limiting first
        if RateLimiter.is_rate_limited(request, 'url_create'):
            return render(request, 'shortener/rate_limited.html', status=429)
        
        form = URLForm(request.POST)
        if form.is_valid():
            original_url = form.cleaned_data['original_url']
            
            # ENHANCED SECURITY CHECKS
            
            # 1. Comprehensive security scan
            security_result = SecurityScanner.comprehensive_url_check(original_url)
            
            if security_result['status'] == 'blocked':
                reasons = ', '.join(security_result['blocked_reasons'])
                messages.error(request, f'This URL is blocked for security reasons: {reasons}')
                return render(request, 'shortener/index.html', {
                    'form': form, 
                    'total_urls': total_urls,
                    'total_clicks': total_clicks,
                    'recent_urls': recent_urls
                })
            
            # 2. Handle suspicious URLs with warning
            if security_result['status'] == 'suspicious':
                warnings = ', '.join(security_result['warnings'])
                messages.warning(request, f'This URL has been flagged as potentially suspicious: {warnings}')
                # Continue but mark as lower security score
            
            # Create URL object
            url = form.save(commit=False)
            
            # Handle custom short code
            custom_short_code = form.cleaned_data.get('custom_short_code')
            if custom_short_code:
                # Additional validation for custom codes
                if len(custom_short_code) < 3:
                    messages.error(request, 'Custom short code must be at least 3 characters long.')
                    return render(request, 'shortener/index.html', {
                        'form': form,
                        'total_urls': total_urls,
                        'total_clicks': total_clicks,
                        'recent_urls': recent_urls
                    })
                
                # Check for malicious patterns in custom code
                if any(char in custom_short_code.lower() for char in ['<', '>', '"', "'", '&']):
                    messages.error(request, 'Custom short code contains invalid characters.')
                    return render(request, 'shortener/index.html', {
                        'form': form,
                        'total_urls': total_urls,
                        'total_clicks': total_clicks,
                        'recent_urls': recent_urls
                    })
                
                url.short_code = custom_short_code
                url.custom_code = True
            else:
                url.short_code = URL.create_short_code()
            
            # Handle expiration
            expiry_option = form.cleaned_data.get('expiry_options', 'never')
            if expiry_option == 'custom':
                url.expiry_date = form.cleaned_data.get('custom_expiry_date')
            elif expiry_option == '1d':
                url.expiry_date = timezone.now() + timedelta(days=1)
            elif expiry_option == '7d':
                url.expiry_date = timezone.now() + timedelta(days=7)
            elif expiry_option == '30d':
                url.expiry_date = timezone.now() + timedelta(days=30)
            
            # Set security defaults based on scan results
            url.is_safe = security_result['status'] in ['safe', 'suspicious']
            url.security_score = max(0, 100 - security_result['risk_score'])
            url.last_security_scan = timezone.now()
            
            # Mark suspicious URLs
            if security_result['status'] == 'suspicious':
                url.security_score = 50  # Lower score for suspicious URLs
            
            # Associate with user if authenticated
            if request.user.is_authenticated:
                url.user = request.user
            
            url.save()
            
            # Perform additional security scans asynchronously
            try:
                # VirusTotal scan
                vt_result = SecurityScanner.scan_url_with_virustotal(original_url)
                
                # Create security scan record
                SecurityScan.objects.create(
                    url=url,
                    scan_type='malware',
                    result=vt_result.get('status', 'error'),
                    details=vt_result,
                    scanner_service='virustotal'
                )
                
                # Update URL based on VirusTotal results
                if vt_result.get('status') == 'malicious':
                    url.is_safe = False
                    url.temporarily_blocked = True
                    url.block_reason = 'Flagged by VirusTotal security scanner'
                    url.security_score = 0
                    url.save()
                    
                    messages.error(request, 'This URL has been flagged as malicious by our security scanner and has been blocked.')
                    return render(request, 'shortener/index.html', {
                        'form': form,
                        'total_urls': total_urls,
                        'total_clicks': total_clicks,
                        'recent_urls': recent_urls
                    })
                
                # Google Safe Browsing check (if available)
                google_result = SecurityScanner.check_url_safety_with_google(original_url)
                if google_result.get('status') == 'malicious':
                    SecurityScan.objects.create(
                        url=url,
                        scan_type='malware',
                        result='malicious',
                        details=google_result,
                        scanner_service='google_safebrowsing'
                    )
                    
                    url.is_safe = False
                    url.temporarily_blocked = True
                    url.block_reason = 'Flagged by Google Safe Browsing'
                    url.security_score = 0
                    url.save()
                    
                    messages.error(request, 'This URL has been flagged as malicious and has been blocked.')
                    return render(request, 'shortener/index.html', {
                        'form': form,
                        'total_urls': total_urls,
                        'total_clicks': total_clicks,
                        'recent_urls': recent_urls
                    })
                
            except Exception as e:
                # If scanning fails, log it but don't block the URL
                import logging
                logger = logging.getLogger('security')
                logger.warning(f'Security scan failed for {original_url}: {str(e)}')
            
            # Store URL id in session for "recently created URLs"
            if 'recent_urls' not in request.session:
                request.session['recent_urls'] = []
            
            recent_urls_session = request.session['recent_urls']
            if url.id not in recent_urls_session:
                recent_urls_session.insert(0, url.id)
                recent_urls_session = recent_urls_session[:5]
                request.session['recent_urls'] = recent_urls_session
                request.session.modified = True
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(f"{settings.SITE_URL}{url.short_code}")
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code image to base64 string
            buffer = io.BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            # Show additional security info for suspicious URLs
            security_info = None
            if security_result['warnings']:
                security_info = {
                    'risk_score': security_result['risk_score'],
                    'warnings': security_result['warnings']
                }
            
            return render(request, 'shortener/success.html', {
                'short_url': f"{settings.SITE_URL}{url.short_code}",
                'original_url': url.original_url,
                'qr_code': qr_code_base64,
                'url': url,
                'security_info': security_info
            })
    
    return render(request, 'shortener/index.html', {
        'form': form, 
        'total_urls': total_urls,
        'total_clicks': total_clicks,
        'recent_urls': recent_urls
    })

def redirect_to_original(request, short_code):
    """Enhanced redirect view with security checks"""
    try:
        print(f"Redirect request: short_code={short_code}, host={request.get_host()}")
        
        # Find URL by short code
        url = URL.objects.get(short_code=short_code)
        print(f"Found URL: {url.short_code} -> {url.original_url}")
        
        # Security checks before redirect
        
        # 1. Check if URL is temporarily blocked
        if url.temporarily_blocked:
            return render(request, 'shortener/blocked.html', {
                'url': url,
                'reason': url.block_reason
            })
        
        # 2. Check if URL is marked as unsafe
        if not url.is_safe:
            return render(request, 'shortener/unsafe_warning.html', {
                'url': url,
                'proceed_url': request.build_absolute_uri()
            })
        
        # 3. Check if URL is expired
        if url.is_expired():
            return render(request, 'shortener/expired.html', {'url': url})
        
        # 4. Rate limiting for redirects (prevent click bombing)
        ip = get_client_ip(request)
        redirect_key = f"redirect_limit:{ip}:{short_code}"
        redirect_count = cache.get(redirect_key, 0)
        
        if redirect_count > 10:  # Max 10 redirects per minute per IP per URL
            SuspiciousActivity.objects.create(
                ip_address=ip,
                activity_type='rapid_creation',
                description=f'Rapid redirects to {short_code}: {redirect_count} in 1 minute',
                severity=6,
                metadata={'short_code': short_code, 'redirects_per_minute': redirect_count}
            )
            messages.warning(request, 'Too many requests. Please wait before accessing this link again.')
            return render(request, 'shortener/rate_limited.html')
        
        cache.set(redirect_key, redirect_count + 1, 60)  # 1 minute
        
        # All checks passed, track click and redirect
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

def get_client_ip(request):
    """Get real client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def stats(request, short_code):
    """Show statistics for a given URL"""
    url = get_object_or_404(URL, short_code=short_code)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(f"{settings.SITE_URL}{url.short_code}")
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
    
    return render(request, 'shortener/stats.html', {
        'url': url,
        'short_url': f"{settings.SITE_URL}{url.short_code}",
        'qr_code': qr_code_base64,
        'days': days,
        'counts': counts,
        'referrers': referrers,
        'browsers': browsers
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

def custom_url(request):
    """Custom URL page for creating URLs with custom domains and short codes"""
    form = URLForm()
    error_message = None
    
    # Get statistics for the page
    total_urls = URL.objects.count()
    total_custom_urls = URL.objects.filter(custom_code=True).count()
    
    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.save(commit=False)
            
            # Get the domain
            domain = request.POST.get('domain', 'tinyurl.run')
            
            # If custom domain was selected, use the provided custom domain
            if domain == 'custom':
                custom_domain = request.POST.get('custom_domain', '').strip()
                if custom_domain:
                    # Remove any http:// or https:// if the user entered it
                    if custom_domain.startswith('http://'):
                        custom_domain = custom_domain[7:]
                    elif custom_domain.startswith('https://'):
                        custom_domain = custom_domain[8:]
                    
                    # Remove any trailing slashes
                    custom_domain = custom_domain.rstrip('/')
                    
                    domain = custom_domain
                else:
                    # If no custom domain was provided, default back to tinyurl.run
                    domain = 'tinyurl.run'
            
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
            
            # Only allow letters, numbers, and hyphens in short code
            if not all(c.isalnum() or c == '-' for c in custom_short_code):
                error_message = "Custom short code can only contain letters, numbers, and hyphens."
                return render(request, 'shortener/custom_url.html', {
                    'form': form,
                    'total_urls': total_urls,
                    'total_custom_urls': total_custom_urls,
                    'error_message': error_message
                })
            
            # Check if custom code already exists
            if URL.objects.filter(short_code=custom_short_code).exists():
                error_message = "This short code is already in use. Please try another one."
                return render(request, 'shortener/custom_url.html', {
                    'form': form,
                    'total_urls': total_urls,
                    'total_custom_urls': total_custom_urls,
                    'error_message': error_message
                })
            
            # Set the custom short code
            url.short_code = custom_short_code
            url.custom_code = True
            
            # Store the domain information with the URL
            url.domain = domain
            
            # Handle expiration if provided
            expiry_option = form.cleaned_data.get('expiry_options', 'never')
            if expiry_option == 'custom':
                url.expiry_date = form.cleaned_data.get('custom_expiry_date')
            elif expiry_option == '1d':
                url.expiry_date = timezone.now() + timedelta(days=1)
            elif expiry_option == '7d':
                url.expiry_date = timezone.now() + timedelta(days=7)
            elif expiry_option == '30d':
                url.expiry_date = timezone.now() + timedelta(days=30)
            
            # Save the URL
            url.save()
            
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
            
            # Format the URL based on the selected domain
            short_url = f"https://{domain}/{url.short_code}"
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
                'domain': domain
            })
    
    return render(request, 'shortener/custom_url.html', {
        'form': form,
        'total_urls': total_urls,
        'total_custom_urls': total_custom_urls,
        'error_message': error_message
    })
def qr_code_generator(request):
    """QR Code Generator page"""
    return render(request, 'shortener/qr_code_generator.html')

def terms_view(request):
    return render(request, 'shortener/terms.html')

def privacy_view(request):
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
        
        messages.success(request, 'Thank you for your report. We will investigate this link.')
        return redirect('index')
    
    return render(request, 'shortener/report_link.html', {'url': url})

@staff_member_required
def security_dashboard(request):
    """Security dashboard for admins"""
    recent_reports = LinkReport.objects.filter(investigated=False)[:10]
    suspicious_activities = SuspiciousActivity.objects.filter(resolved=False)[:10]
    blocked_domains = BlockedDomain.objects.filter(is_active=True)[:10]
    recent_scans = SecurityScan.objects.filter(result='malicious')[:10]
    
    context = {
        'recent_reports': recent_reports,
        'suspicious_activities': suspicious_activities,
        'blocked_domains': blocked_domains,
        'recent_scans': recent_scans,
    }
    
    return render(request, 'shortener/security_dashboard.html', context)

@staff_member_required
def block_domain(request):
    """Block a domain"""
    if request.method == 'POST':
        domain = request.POST.get('domain')
        reason = request.POST.get('reason')
        
        BlockedDomain.objects.create(
            domain=domain,
            reason=reason,
            blocked_by=request.user
        )
        
        messages.success(request, f'Domain {domain} has been blocked.')
        return redirect('security_dashboard')
    
    return redirect('security_dashboard')

@staff_member_required
def remove_blocked_domain(request, domain_id):
    """Remove a domain from blocklist"""
    if request.method == 'POST':
        domain = get_object_or_404(BlockedDomain, id=domain_id)
        domain.is_active = False
        domain.save()
        
        return JsonResponse({'success': True})
    
    return JsonResponse({'success': False})

@staff_member_required
def export_security_report(request):
    """Export security report as CSV"""
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

# ===== EXISTING VIEWS (Keep your existing ones) =====

def stats(request, short_code):
    """Show statistics for a given URL"""
    url = get_object_or_404(URL, short_code=short_code)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(f"{settings.SITE_URL}{url.short_code}")
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
    
    return render(request, 'shortener/stats.html', {
        'url': url,
        'short_url': f"{settings.SITE_URL}{url.short_code}",
        'qr_code': qr_code_base64,
        'days': days,
        'counts': counts,
        'referrers': referrers,
        'browsers': browsers
    })
