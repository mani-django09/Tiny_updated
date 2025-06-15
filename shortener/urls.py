from django.urls import path
from . import views
from .admin_dashboard import admin_dashboard, system_health
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    # Standard app URLs (must come BEFORE the catch-all)
    path('', views.index, name='index'),
    path('custom-url/', views.custom_url, name='custom_url'),
    path('stats/<str:short_code>/', views.stats, name='stats'),
    path('about/', views.about, name='about'),
    path('faq/', views.faq, name='faq'),
    path('qr-code-generator/', views.qr_code_generator, name='qr_code_generator'),
    path('terms/', views.terms_view, name='terms'),
    path('privacy/', views.privacy_view, name='privacy'),
    path('contact/', views.contact_view, name='contact'),
    
    # Security URLs
    path('report/<str:short_code>/', views.report_link, name='report_link'),
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('security/dashboard/', views.security_dashboard, name='security_dashboard_alt'),
    path('security/analytics/', views.security_analytics_view, name='security_analytics'),
    path('security/manual-scan/', views.manual_url_scan, name='manual_scan'),
    path('security/settings/', views.security_settings_view, name='security_settings'),
    
    # Domain Management
    path('security/block-domain/', views.block_domain, name='block_domain'),
    path('security/domains/<int:domain_id>/remove/', views.remove_blocked_domain, name='remove_blocked_domain'),
    path('security/whitelist-domain/', views.whitelist_domain, name='whitelist_domain'),
    path('security/remove-whitelist/<int:domain_id>/', views.remove_whitelist_domain, name='remove_whitelist_domain'),
    
    # URL Management
    path('security/rescan/<int:url_id>/', views.rescan_url, name='rescan_url'),
    path('security/bulk-rescan/', views.bulk_rescan_urls, name='bulk_rescan_urls'),
    path('check-availability/', views.check_short_code_availability, name='check_availability'),

    # API Testing
    path('security/test-safebrowsing/', views.test_google_safebrowsing, name='test_safebrowsing'),
    path('security/test-virustotal/', views.test_virustotal, name='test_virustotal'),
    path('security/test-all-apis/', views.test_all_security_apis, name='test_all_apis'),
    path('security/api-status/', views.security_api_status, name='security_api_status'),
    
    # Reports and Export
    path('security/export-report/', views.export_security_report_detailed, name='export_security_report'),
    path('security/export-detailed/', views.export_security_report_detailed, name='export_detailed_report'),
    
    # Public API Endpoints
    path('api/shorten/', views.api_shorten_url, name='api_shorten'),
    path('api/stats/<str:short_code>/', views.api_url_stats, name='api_url_stats'),
    path('api/security-check/', views.check_url_security_status, name='security_check'),
    
    # Staff API Endpoints
    path('api/security/stats/', views.api_security_stats, name='api_security_stats'),
    
    # Admin Dashboard
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/system-health/', system_health, name='system_health'),
    
    
    # This catch-all pattern MUST be LAST in the list
    path('<str:short_code>/', views.redirect_to_original, name='redirect'),
]