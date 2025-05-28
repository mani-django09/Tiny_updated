from django.shortcuts import render, redirect, get_object_or_404,HttpResponseRedirect
from django.http import Http404, JsonResponse
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.contrib import messages
from django.views.decorators.http import require_POST
import qrcode
import io
import base64
from PIL import Image

from .models import URL, ClickAnalytics
from .forms import URLForm

def index(request):
    """Homepage view with form to create short URL"""
    form = URLForm()
    # Get statistics for the homepage
    total_urls = URL.objects.count()
    total_clicks = URL.objects.filter(is_active=True).count()
    
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
            
            # Handle password protection
            if form.cleaned_data.get('password_protect'):
                url.password = form.cleaned_data.get('password')
            
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
            qr.add_data(f"{settings.SITE_URL}{url.short_code}")
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code image to base64 string
            buffer = io.BytesIO()
            qr_img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return render(request, 'shortener/success.html', {
                'short_url': f"{settings.SITE_URL}{url.short_code}",
                'original_url': url.original_url,
                'qr_code': qr_code_base64,
                'url': url
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
        
        # Check if URL is expired
        if url.is_expired():
            return render(request, 'shortener/expired.html', {'url': url})
        
        # Check if URL is password protected
        if url.password:
            if request.method == 'POST':
                provided_password = request.POST.get('password', '')
                if provided_password == url.password:
                    # Create analytics entry and redirect
                    track_click(request, url)
                    return HttpResponseRedirect(url.original_url)
                else:
                    return render(request, 'shortener/password.html', {
                        'url': url,
                        'error': 'Incorrect password. Please try again.',
                        'custom_domain': request.get_host()
                    })
            else:
                return render(request, 'shortener/password.html', {
                    'url': url,
                    'custom_domain': request.get_host()
                })
        
        # No password, track the click and redirect
        track_click(request, url)
        return HttpResponseRedirect(url.original_url)
    except URL.DoesNotExist:
        print(f"URL not found: {short_code}")
        raise Http404(f"The shortened URL '{short_code}' was not found.")

def track_click(request, url):
    """Track click analytics with domain information"""
    # Get the host domain used for this click
    host = request.get_host().split(':')[0]  # Remove port if present
    
    # Increment the click counter
    url.increment_clicks()
    
    # Create analytics entry with domain information
    ClickAnalytics.objects.create(
        url=url,
        ip_address=get_client_ip(request),
        referrer=request.META.get('HTTP_REFERER', ''),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        domain_used=host  # Track which domain was used for the click
    )

def get_client_ip(request):
    """Get client IP address"""
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
            
            # Handle password protection
            if form.cleaned_data.get('password_protect'):
                url.password = form.cleaned_data.get('password')
            
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