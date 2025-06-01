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
    path('contact/', views.contact_view, name='contact'),  # MOVE THIS BEFORE the catch-all
     # Security URLs
    path('report/<str:short_code>/', views.report_link, name='report_link'),
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('security/block-domain/', views.block_domain, name='block_domain'),
    path('security/domains/<int:domain_id>/remove/', views.remove_blocked_domain, name='remove_blocked_domain'),
    path('security/export-report/', views.export_security_report, name='export_security_report'),


    # This catch-all pattern MUST be LAST in the list
    path('<str:short_code>/', views.redirect_to_original, name='redirect'),
]

