from django import forms
from .models import URL
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class URLForm(forms.ModelForm):
    original_url = forms.URLField(
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your long URL here',
            'aria-label': 'URL to shorten'
        }),
        label='URL to Shorten',
        help_text='Enter the URL you want to shorten (include http:// or https://)'
    )
    
    custom_short_code = forms.CharField(
        max_length=10,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Optional: Create a custom short code',
            'aria-label': 'Custom short code'
        }),
        label='Custom Short Code',
        help_text='Leave blank for an auto-generated code'
    )
    
    expiry_options = forms.ChoiceField(
        choices=[
            ('never', 'Never'),
            ('1d', '1 Day'),
            ('7d', '7 Days'),
            ('30d', '30 Days'),
            ('custom', 'Custom')
        ],
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False,
        label='Expiration'
    )
    
    custom_expiry_date = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control',
            'type': 'datetime-local'
        }),
        label='Custom Expiry Date and Time'
    )
    
    password_protect = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='Password Protect'
    )
    
    password = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter password'
        }),
        label='Password'
    )
    
    class Meta:
        model = URL
        fields = ['original_url']
        
    def clean_custom_short_code(self):
        custom_short_code = self.cleaned_data.get('custom_short_code')
        
        if custom_short_code:
            # Check if custom short code already exists
            if URL.objects.filter(short_code=custom_short_code).exists():
                raise ValidationError('This short code is already in use. Please try another one.')
            
            # Check if custom short code only contains letters and numbers
            if not all(c.isalnum() or c == '_' or c == '-' for c in custom_short_code):
                raise ValidationError('Short code can only contain letters, numbers, underscores, and hyphens.')
        
        return custom_short_code
        
    def clean(self):
        cleaned_data = super().clean()
        password_protect = cleaned_data.get('password_protect')
        password = cleaned_data.get('password')
        
        if password_protect and not password:
            self.add_error('password', 'Password is required when password protection is enabled.')
            
        return cleaned_data