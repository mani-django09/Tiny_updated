from django.db import models
import string
import random
from django.utils import timezone
import datetime

class URL(models.Model):
    original_url = models.URLField(max_length=2000)
    short_code = models.CharField(max_length=10, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    clicks = models.IntegerField(default=0)
    domain = models.CharField(max_length=255, blank=True, null=True)

    # New fields
    custom_code = models.BooleanField(default=False)
    expiry_date = models.DateTimeField(null=True, blank=True)
    password = models.CharField(max_length=50, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"{self.original_url} to {self.short_code}"
    
    @classmethod
    def create_short_code(cls, length=6):
        """Generate a random short code"""
        chars = string.ascii_letters + string.digits
        while True:
            short_code = ''.join(random.choice(chars) for _ in range(length))
            if not cls.objects.filter(short_code=short_code).exists():
                return short_code
    
    def is_expired(self):
        """Check if URL is expired"""
        if self.expiry_date and timezone.now() > self.expiry_date:
            self.is_active = False
            self.save()
            return True
        return False
    
    def increment_clicks(self):
        """Increment click count"""
        self.clicks += 1
        self.save()
    
    class Meta:
        ordering = ['-created_at']

class ClickAnalytics(models.Model):
    """Model to track click analytics"""
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='analytics')
    clicked_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    referrer = models.CharField(max_length=500, null=True, blank=True)
    user_agent = models.CharField(max_length=500, null=True, blank=True)
    domain_used = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"Click on {self.url.short_code} at {self.clicked_at}"

from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('shortener', '0002_previous_migration'),  # Replace with your previous migration
    ]

    operations = [
        migrations.AddField(
            model_name='url',
            name='domain',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='clickanalytics',
            name='domain_used',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]