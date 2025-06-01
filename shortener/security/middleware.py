from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

class SecurityMiddleware(MiddlewareMixin):
    """Security middleware for URL shortener"""
    
    def process_request(self, request):
        """Process incoming requests for security threats"""
        
        # Skip security checks for admin and static files
        if request.path.startswith('/admin/') or request.path.startswith('/static/'):
            return None
        
        # For now, just return None (disable security features temporarily)
        return None