# shortener/sitemaps.py
from django.contrib.sitemaps import Sitemap
from django.urls import reverse

class StaticViewsSitemap(Sitemap):
    priority = 0.8
    changefreq = 'weekly'

    def items(self):
        return ['index', 'custom_url', 'qr_code_generator', 'about', 'faq', 'terms', 'privacy', 'contact']

    def location(self, item):
        return reverse(item)