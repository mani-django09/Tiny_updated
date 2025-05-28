# middleware.py
# Place this file in your shortener app directory

class CustomDomainMiddleware:
    """
    Middleware to intercept requests from custom domains and route them
    to the correct view for URL redirection.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        # List of your app domains that should be handled normally
        self.app_domains = [
            'tinyurl.run',
            'www.tinyurl.run',
            'tiny.one',
            'shrt.link',
            'localhost',
            '127.0.0.1',
        ]
        print("CustomDomainMiddleware initialized")
    
    def __call__(self, request):
        # Get the host (domain) from the request
        host = request.get_host().split(':')[0]  # Remove port if present
        path = request.path.strip('/')
        
        print(f"Processing request: {host}{request.path}")
        
        # Check if this is a custom domain (not one of our app domains)
        if host not in self.app_domains:
            # Skip processing for static files and admin
            if not path.startswith('static/') and not path.startswith('admin/'):
                # If there's a path component and it doesn't contain another slash,
                # it's likely a short code we should handle
                if path and '/' not in path:
                    print(f"Custom domain detected: {host}, Path: {path}")
                    
                    # Rewrite the path to match our redirect URL pattern
                    # This makes Django treat the request as if it were for /<path>/
                    request.path_info = f'/{path}/'
                    
                    print(f"Rewritten path: {request.path_info}")
        
        # Continue with the regular request processing
        response = self.get_response(request)
        return response