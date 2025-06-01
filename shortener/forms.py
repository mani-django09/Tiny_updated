from django import forms
from .models import URL
from django.core.exceptions import ValidationError
import re

class URLForm(forms.ModelForm):
    custom_short_code = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'my-custom-link'
        }),
        help_text='Use letters, numbers, and hyphens only'
    )
    
    class Meta:
        model = URL
        fields = ['original_url']
        widgets = {
            'original_url': forms.URLInput(attrs={
                'class': 'form-control form-control-lg',
                'placeholder': 'https://example.com/your-long-url',
                'required': True
            })
        }
    
    def clean_custom_short_code(self):
        custom_short_code = self.cleaned_data.get('custom_short_code')
        
        if custom_short_code:
            # Check if it contains only allowed characters
            if not re.match(r'^[a-zA-Z0-9\-_]+$', custom_short_code):
                raise ValidationError("Custom short code can only contain letters, numbers, hyphens, and underscores.")
            
            # Check if it's not too short
            if len(custom_short_code) < 3:
                raise ValidationError("Custom short code must be at least 3 characters long.")
            
            # Check if it already exists
            if URL.objects.filter(short_code=custom_short_code).exists():
                raise ValidationError("This short code is already taken. Please try another one.")
            
            # Check if it's not a reserved word
            reserved_words = ['api', 'admin', 'www', 'mail', 'ftp', 'stats', 'about', 'contact', 'help', 'support']
            if custom_short_code.lower() in reserved_words:
                raise ValidationError("This short code is reserved. Please choose another one.")
        
        return custom_short_code