from django import forms
from django.core.exceptions import ValidationError
from .models import URL
import re

class URLForm(forms.ModelForm):
    custom_short_code = forms.CharField(
        max_length=10,
        min_length=3,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'my-brand-name',
            'pattern': '[a-zA-Z0-9_-]+',
            'title': 'Only letters, numbers, hyphens, and underscores are allowed',
            'maxlength': '10',
            'minlength': '3',
            'id': 'id_custom_short_code',  # Ensure consistent ID
            'autocomplete': 'off'
        }),
        help_text='3-10 characters: letters, numbers, hyphens, and underscores only',
        label='Customize your link (optional)'
    )
    
    class Meta:
        model = URL
        fields = ['original_url']
        widgets = {
            'original_url': forms.URLInput(attrs={
                'class': 'form-control form-control-lg',
                'placeholder': 'https://example.com/your-long-url',
                'required': True,
                'id': 'id_original_url'  # Ensure consistent ID
            })
        }
        labels = {
            'original_url': 'Enter your long URL'
        }
    
    def clean_custom_short_code(self):
        custom_short_code = self.cleaned_data.get('custom_short_code')
        
        if custom_short_code:
            # Remove any whitespace
            custom_short_code = custom_short_code.strip()
            
            # If empty after stripping, return None
            if not custom_short_code:
                return None
            
            # Check length constraints with specific error messages
            if len(custom_short_code) < 3:
                raise ValidationError(
                    "Custom short code must be at least 3 characters long.",
                    code='min_length'
                )
            
            if len(custom_short_code) > 10:
                raise ValidationError(
                    "Custom short code cannot be more than 10 characters long.",
                    code='max_length'
                )
            
            # Check for valid characters (letters, numbers, hyphens, underscores)
            if not re.match(r'^[a-zA-Z0-9_-]+$', custom_short_code):
                raise ValidationError(
                    "Custom short code can only contain letters, numbers, hyphens, and underscores.",
                    code='invalid_characters'
                )
            
            # Check if the short code already exists (case-insensitive)
            if URL.objects.filter(short_code__iexact=custom_short_code).exists():
                raise ValidationError(
                    f"The short code '{custom_short_code}' is not available. Please choose a different one.",
                    code='duplicate'
                )
            
            # Check against reserved words to prevent conflicts
            reserved_words = [
                'admin', 'api', 'www', 'mail', 'ftp', 'localhost', 'stats', 'analytics',
                'dashboard', 'login', 'logout', 'register', 'signup', 'signin', 'user',
                'users', 'profile', 'settings', 'config', 'help', 'support', 'contact',
                'about', 'terms', 'privacy', 'policy', 'legal', 'dmca', 'abuse',
                'security', 'qr', 'qrcode', 'short', 'url', 'link', 'redirect',
                'goto', 'go', 'click', 'visit', 'view', 'show', 'display', 'index',
                'home', 'test', 'demo', 'example', 'sample'
            ]
            
            if custom_short_code.lower() in reserved_words:
                raise ValidationError(
                    f"The short code '{custom_short_code}' is reserved. Please choose a different one.",
                    code='reserved'
                )
        
        return custom_short_code
    
    def clean_original_url(self):
        original_url = self.cleaned_data.get('original_url')
        
        if not original_url:
            raise ValidationError("Please enter a valid URL.")
        
        # Ensure URL has a scheme
        if not original_url.startswith(('http://', 'https://')):
            original_url = 'https://' + original_url
        
        # Additional URL validation - check for valid format
        try:
            from urllib.parse import urlparse
            parsed = urlparse(original_url)
            if not parsed.netloc:
                raise ValidationError("Please enter a valid URL with a domain name.")
        except Exception:
            raise ValidationError("Please enter a valid URL.")
        
        return original_url