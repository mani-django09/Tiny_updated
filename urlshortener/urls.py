from django.contrib import admin
from django.urls import path,include
from django.contrib.sitemaps.views import sitemap
from django.http import HttpResponse
from shortener.sitemaps import StaticViewsSitemap
from shortener.admin_dashboard import admin_dashboard, system_health
from shortener.admin import admin_site


sitemaps = {
    'static': StaticViewsSitemap,
}


def ads_txt_view(request):
    """Serve ads.txt file"""
    content = "google.com, pub-6913093595582462, DIRECT, f08c47fec0942fa0"
    return HttpResponse(content, content_type='text/plain')

def robots_txt(request):
    content = """User-agent: *
Allow: /
Disallow: /admin/

Sitemap: https://tinyurl.run/sitemap.xml
"""
    return HttpResponse(content, content_type='text/plain')


urlpatterns = [
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('admin-dashboard/system-health/', system_health, name='system_health'),
    path('admin/', admin_site.urls),
    path('ads.txt', ads_txt_view, name='ads_txt'),
    path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='sitemap'),
    path('robots.txt', robots_txt, name='robots'),
    path('', include('shortener.urls')),

]

