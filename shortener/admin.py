from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import timedelta
import json
from django.shortcuts import render
from django.urls import path

from .models import (
    URL, ClickAnalytics, SecurityScan, SuspiciousActivity, 
    LinkReport, BlockedDomain, WhitelistedDomain, SecuritySettings,
    RateLimitLog
)

# Customize Admin Site
admin.site.site_header = "TinyURL.run Administration"
admin.site.site_title = "TinyURL Admin"
admin.site.index_title = "Welcome to TinyURL.run Admin Dashboard"

@admin.register(URL)
class URLAdmin(admin.ModelAdmin):
    list_display = [
        'short_code', 'original_url_display', 'clicks', 'is_safe', 
        'is_active', 'created_at', 'user', 'security_score', 'view_stats'
    ]
    # FIXED: Removed 'expiry_date' from list_filter
    list_filter = [
        'is_safe', 'is_active', 'custom_code', 'temporarily_blocked',
        'created_at'
    ]
    search_fields = ['short_code', 'original_url', 'user__username']
    readonly_fields = [
        'created_at', 'clicks', 'last_security_scan', 'flagged_by_users'
    ]
    ordering = ['-created_at']
    list_per_page = 50
    
    # FIXED: Removed 'expiry_date' from fieldsets
    fieldsets = (
        ('Basic Information', {
            'fields': ('short_code', 'original_url', 'user', 'created_at')
        }),
        ('Settings', {
            'fields': ('is_active', 'custom_code', 'domain')
        }),
        ('Analytics', {
            'fields': ('clicks',)
        }),
        ('Security', {
            'fields': (
                'is_safe', 'security_score', 'last_security_scan',
                'temporarily_blocked', 'block_reason', 'flagged_by_users'
            )
        })
    )
    
    def original_url_display(self, obj):
        if len(obj.original_url) > 50:
            return f"{obj.original_url[:50]}..."
        return obj.original_url
    original_url_display.short_description = "Original URL"
    
    def view_stats(self, obj):
        url = reverse('admin:shortener_clickanalytics_changelist')
        return format_html(
            '<a href="{}?url__id__exact={}" class="button">View Stats</a>',
            url, obj.id
        )
    view_stats.short_description = "Analytics"
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')

@admin.register(ClickAnalytics)
class ClickAnalyticsAdmin(admin.ModelAdmin):
    list_display = [
        'url', 'clicked_at', 'ip_address', 'referrer_display', 
        'user_agent_display', 'domain_used'
    ]
    list_filter = ['clicked_at', 'domain_used']
    search_fields = ['url__short_code', 'ip_address', 'referrer']
    readonly_fields = ['clicked_at']
    ordering = ['-clicked_at']
    list_per_page = 100
    
    def referrer_display(self, obj):
        if obj.referrer and len(obj.referrer) > 30:
            return f"{obj.referrer[:30]}..."
        return obj.referrer or "Direct"
    referrer_display.short_description = "Referrer"
    
    def user_agent_display(self, obj):
        if obj.user_agent and len(obj.user_agent) > 40:
            return f"{obj.user_agent[:40]}..."
        return obj.user_agent or "Unknown"
    user_agent_display.short_description = "User Agent"

@admin.register(SecurityScan)
class SecurityScanAdmin(admin.ModelAdmin):
    list_display = [
        'url', 'scan_type', 'result', 'scanner_service', 'scanned_at'
    ]
    list_filter = ['scan_type', 'result', 'scanner_service', 'scanned_at']
    search_fields = ['url__short_code']
    readonly_fields = ['scanned_at', 'details']
    ordering = ['-scanned_at']
    
    def get_readonly_fields(self, request, obj=None):
        if obj:  # editing an existing object
            return self.readonly_fields + ['url', 'scan_type']
        return self.readonly_fields

@admin.register(SuspiciousActivity)
class SuspiciousActivityAdmin(admin.ModelAdmin):
    list_display = [
        'activity_type', 'ip_address', 'user', 'severity', 
        'timestamp', 'resolved', 'view_details'
    ]
    list_filter = [
        'activity_type', 'severity', 'resolved', 'timestamp'
    ]
    search_fields = ['ip_address', 'user__username', 'description']
    readonly_fields = ['timestamp', 'metadata']
    ordering = ['-timestamp']
    actions = ['mark_resolved', 'mark_unresolved']
    
    def view_details(self, obj):
        return format_html(
            '<button onclick="alert(\'{}\')">View</button>',
            obj.description.replace("'", "\\'")
        )
    view_details.short_description = "Details"
    
    def mark_resolved(self, request, queryset):
        queryset.update(resolved=True)
        self.message_user(request, f"{queryset.count()} activities marked as resolved.")
    mark_resolved.short_description = "Mark selected activities as resolved"
    
    def mark_unresolved(self, request, queryset):
        queryset.update(resolved=False)
        self.message_user(request, f"{queryset.count()} activities marked as unresolved.")
    mark_unresolved.short_description = "Mark selected activities as unresolved"

@admin.register(LinkReport)
class LinkReportAdmin(admin.ModelAdmin):
    list_display = [
        'url', 'report_type', 'reporter_email', 'reported_at', 
        'investigated', 'action_taken'
    ]
    list_filter = ['report_type', 'investigated', 'reported_at']
    search_fields = ['url__short_code', 'reporter_email', 'description']
    readonly_fields = ['reported_at', 'reporter_ip']
    ordering = ['-reported_at']
    actions = ['mark_investigated']
    
    def mark_investigated(self, request, queryset):
        queryset.update(investigated=True)
        self.message_user(request, f"{queryset.count()} reports marked as investigated.")
    mark_investigated.short_description = "Mark selected reports as investigated"

@admin.register(BlockedDomain)
class BlockedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'reason', 'blocked_by', 'created_at', 'is_active']
    list_filter = ['is_active', 'created_at']
    search_fields = ['domain', 'reason']
    readonly_fields = ['created_at']
    actions = ['activate_domains', 'deactivate_domains']
    
    def activate_domains(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, f"{queryset.count()} domains activated.")
    activate_domains.short_description = "Activate selected domains"
    
    def deactivate_domains(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, f"{queryset.count()} domains deactivated.")
    deactivate_domains.short_description = "Deactivate selected domains"

@admin.register(WhitelistedDomain)
class WhitelistedDomainAdmin(admin.ModelAdmin):
    list_display = ['domain', 'added_by', 'created_at']
    list_filter = ['created_at']
    search_fields = ['domain']
    readonly_fields = ['created_at']

@admin.register(SecuritySettings)
class SecuritySettingsAdmin(admin.ModelAdmin):
    list_display = [
        'enable_malware_scanning', 'enable_rate_limiting', 'enable_captcha',
        'max_urls_per_hour', 'max_urls_per_day'
    ]
    
    def has_add_permission(self, request):
        # Only allow one SecuritySettings instance
        return not SecuritySettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        # Don't allow deletion of security settings
        return False

@admin.register(RateLimitLog)
class RateLimitLogAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address', 'user', 'action', 'timestamp', 'blocked', 'user_agent_short'
    ]
    list_filter = ['action', 'blocked', 'timestamp']
    search_fields = ['ip_address', 'user__username']
    readonly_fields = ['timestamp']
    ordering = ['-timestamp']
    list_per_page = 100
    
    def user_agent_short(self, obj):
        if obj.user_agent and len(obj.user_agent) > 50:
            return f"{obj.user_agent[:50]}..."
        return obj.user_agent or "Unknown"
    user_agent_short.short_description = "User Agent"
    
    def has_add_permission(self, request):
        return False  # These are auto-generated

class CustomAdminSite(admin.AdminSite):
    site_header = 'TinyURL.run Administration'
    site_title = 'TinyURL Admin'
    index_title = 'Welcome to TinyURL.run Admin Dashboard'
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('dashboard/', self.admin_view(self.dashboard_view), name='admin_dashboard'),
            path('system-health/', self.admin_view(self.system_health_view), name='system_health'),
        ]
        return custom_urls + urls
    
    def dashboard_view(self, request):
        """Custom dashboard view"""
        from .models import URL, ClickAnalytics, SuspiciousActivity, LinkReport
        
        today = timezone.now().date()
        
        stats = {
            'total_urls': URL.objects.count(),
            'active_urls': URL.objects.filter(is_active=True).count(),
            'total_clicks': URL.objects.aggregate(Sum('clicks'))['clicks__sum'] or 0,
            'today_urls': URL.objects.filter(created_at__date=today).count(),
        }
        
        security_stats = {
            'unsafe_urls': URL.objects.filter(is_safe=False).count(),
            'blocked_urls': URL.objects.filter(temporarily_blocked=True).count(),
            'pending_reports': LinkReport.objects.filter(investigated=False).count(),
            'suspicious_activities': SuspiciousActivity.objects.filter(resolved=False).count(),
        }
        
        recent_urls = URL.objects.order_by('-created_at')[:10]
        
        context = {
            **self.each_context(request),
            'stats': stats,
            'security_stats': security_stats,
            'recent_urls': recent_urls,
        }
        
        return render(request, 'admin/dashboard.html', context)
    
    def system_health_view(self, request):
        """System health check"""
        from django.http import JsonResponse
        
        try:
            from .models import URL, SuspiciousActivity
            
            db_check = URL.objects.count() >= 0
            security_issues = SuspiciousActivity.objects.filter(resolved=False, severity__gte=7).count()
            
            health_status = {
                'database': 'healthy' if db_check else 'error',
                'security': 'warning' if security_issues > 0 else 'healthy',
                'security_issues_count': security_issues,
                'timestamp': timezone.now().isoformat()
            }
            
            return JsonResponse(health_status)
            
        except Exception as e:
            return JsonResponse({
                'database': 'error',
                'security': 'error',
                'error': str(e),
                'timestamp': timezone.now().isoformat()
            }, status=500)

# Create custom admin site instance
admin_site = CustomAdminSite(name='custom_admin')

# Re-register all your models with the custom admin site
from .models import (
    URL, ClickAnalytics, SecurityScan, SuspiciousActivity, 
    LinkReport, BlockedDomain, WhitelistedDomain, SecuritySettings, RateLimitLog
)

admin_site.register(URL, URLAdmin)
admin_site.register(ClickAnalytics, ClickAnalyticsAdmin)
admin_site.register(SecurityScan, SecurityScanAdmin)
admin_site.register(SuspiciousActivity, SuspiciousActivityAdmin)
admin_site.register(LinkReport, LinkReportAdmin)
admin_site.register(BlockedDomain, BlockedDomainAdmin)
admin_site.register(WhitelistedDomain, WhitelistedDomainAdmin)
admin_site.register(SecuritySettings, SecuritySettingsAdmin)
admin_site.register(RateLimitLog, RateLimitLogAdmin)