from django.db import models
import string
import random
from django.utils import timezone
import datetime
from django.contrib.auth.models import User
import hashlib
import requests
from datetime import timedelta

class URL(models.Model):
    original_url = models.URLField(max_length=2000)
    short_code = models.CharField(max_length=10, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    clicks = models.IntegerField(default=0)
    domain = models.CharField(max_length=255, blank=True, null=True)

    # Existing fields
    custom_code = models.BooleanField(default=False)
    expiry_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # NEW SECURITY FIELDS
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    is_safe = models.BooleanField(default=True)
    last_security_scan = models.DateTimeField(null=True, blank=True)
    security_score = models.IntegerField(default=100)  # 0-100 scale
    flagged_by_users = models.IntegerField(default=0)
    temporarily_blocked = models.BooleanField(default=False)
    block_reason = models.CharField(max_length=500, blank=True)
    
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

class SecuritySettings(models.Model):
    """Global security settings"""
    enable_malware_scanning = models.BooleanField(default=True)
    enable_rate_limiting = models.BooleanField(default=True)
    enable_captcha = models.BooleanField(default=True)
    max_urls_per_hour = models.IntegerField(default=50)
    max_urls_per_day = models.IntegerField(default=500)
    suspicious_click_threshold = models.IntegerField(default=100)  # clicks per minute
    
    class Meta:
        verbose_name_plural = "Security Settings"

class BlockedDomain(models.Model):
    """Domains that are blocked from being shortened"""
    domain = models.CharField(max_length=255, unique=True)
    reason = models.CharField(max_length=500)
    blocked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return f"Blocked: {self.domain}"

class WhitelistedDomain(models.Model):
    """Domains that are always allowed (bypass security checks)"""
    domain = models.CharField(max_length=255, unique=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Whitelisted: {self.domain}"

class SecurityScan(models.Model):
    """Records of security scans performed on URLs"""
    SCAN_TYPES = [
        ('malware', 'Malware Scan'),
        ('phishing', 'Phishing Scan'),
        ('reputation', 'Reputation Check'),
    ]
    
    SCAN_RESULTS = [
        ('safe', 'Safe'),
        ('suspicious', 'Suspicious'),
        ('malicious', 'Malicious'),
        ('error', 'Scan Error'),
    ]
    
    url = models.ForeignKey('URL', on_delete=models.CASCADE, related_name='security_scans')
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    result = models.CharField(max_length=20, choices=SCAN_RESULTS)
    details = models.JSONField(default=dict)
    scanned_at = models.DateTimeField(auto_now_add=True)
    scanner_service = models.CharField(max_length=100, default='internal')
    
    def __str__(self):
        return f"{self.url.short_code} - {self.scan_type}: {self.result}"

class RateLimitLog(models.Model):
    """Track rate limiting events"""
    ip_address = models.GenericIPAddressField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50)  # 'url_create', 'url_access', etc.
    timestamp = models.DateTimeField(auto_now_add=True)
    user_agent = models.CharField(max_length=500, blank=True)
    blocked = models.BooleanField(default=False)
    
    class Meta:
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
        ]

class SuspiciousActivity(models.Model):
    """Log suspicious activities"""
    ACTIVITY_TYPES = [
        ('rapid_creation', 'Rapid URL Creation'),
        ('suspicious_pattern', 'Suspicious Pattern'),
        ('malicious_url', 'Malicious URL Attempt'),
        ('bot_behavior', 'Bot-like Behavior'),
        ('captcha_failure', 'Repeated Captcha Failures'),
    ]
    
    ip_address = models.GenericIPAddressField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    activity_type = models.CharField(max_length=30, choices=ACTIVITY_TYPES)
    description = models.TextField()
    severity = models.IntegerField(default=1)  # 1-10 scale
    timestamp = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    metadata = models.JSONField(default=dict)
    
    def __str__(self):
        return f"{self.activity_type} - {self.ip_address} at {self.timestamp}"

class LinkReport(models.Model):
    """User reports for malicious or inappropriate links"""
    REPORT_TYPES = [
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('spam', 'Spam'),
        ('inappropriate', 'Inappropriate Content'),
        ('scam', 'Scam'),
        ('other', 'Other'),
    ]
    
    url = models.ForeignKey('URL', on_delete=models.CASCADE, related_name='reports')
    reporter_ip = models.GenericIPAddressField()
    reporter_email = models.EmailField(blank=True)
    report_type = models.CharField(max_length=20, choices=REPORT_TYPES)
    description = models.TextField()
    reported_at = models.DateTimeField(auto_now_add=True)
    investigated = models.BooleanField(default=False)
    action_taken = models.CharField(max_length=200, blank=True)
    
    def __str__(self):
        return f"Report for {self.url.short_code}: {self.report_type}"