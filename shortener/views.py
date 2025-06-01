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
            
            # Handle custom short code
            custom_short_code = form.cleaned_data.get('custom_short_code')
            if custom_short_code:
                url.short_code = custom_short_code
                url.custom_code = True
            else:
                url.short_code = URL.create_short_code()
            
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
                'is_custom': url.custom_code
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
    
    return render(request, 'shortener/stats.html', {
        'url': url,
        'short_url': short_url,
        'qr_code': qr_code_base64,
        'days': days,
        'counts': counts,
        'referrers': referrers,
        'browsers': browsers
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
                'is_custom': True
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
            
            messages.success(request, 'Thank you for your report. We will investigate this link.')
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
        
        context = {
            'recent_reports': recent_reports,
            'suspicious_activities': suspicious_activities,
            'blocked_domains': blocked_domains,
            'recent_scans': recent_scans,
        }
        
        return render(request, 'shortener/security_dashboard.html', context)
    except Exception as e:
        messages.error(request, f'Error loading security dashboard: {str(e)}')
        return redirect('admin:index')

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
def export_security_report(request):
    """Export security report as CSV"""
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

# Error handlers
def handler404(request, exception):
    """Custom 404 error handler"""
    return render(request, 'shortener/404.html', status=404)

def handler500(request):
    """Custom 500 error handler"""
    return render(request, 'shortener/500.html', status=500)

# API Views (if needed)
def api_shorten_url(request):
    """API endpoint to shorten URLs"""
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
            
            url.save()
            
            return JsonResponse({
                'success': True,
                'short_url': build_short_url(url.short_code),
                'short_code': url.short_code,
                'original_url': url.original_url
            })
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def api_url_stats(request, short_code):
    """API endpoint to get URL statistics"""
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
        
        return JsonResponse({
            'success': True,
            'short_code': url.short_code,
            'original_url': url.original_url,
            'total_clicks': url.clicks,
            'created_at': url.created_at.isoformat(),
            'is_active': url.is_active,
            'daily_clicks': list(daily_clicks)
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)