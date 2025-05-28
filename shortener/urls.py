from django.urls import path
from . import views

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
    
    # This catch-all pattern MUST be LAST in the list
    path('<str:short_code>/', views.redirect_to_original, name='redirect'),
]