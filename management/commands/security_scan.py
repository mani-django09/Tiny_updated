from django.core.management.base import BaseCommand
from myapp.models import URL
from myapp.security.utils import SecurityScanner

class Command(BaseCommand):
    help = 'Run security scans on all URLs'
    
    def handle(self, *args, **options):
        urls_to_scan = URL.objects.filter(
            last_security_scan__lt=timezone.now() - timedelta(days=7)
        ) | URL.objects.filter(last_security_scan__isnull=True)
        
        for url in urls_to_scan:
            self.stdout.write(f'Scanning {url.original_url}...')
            
            scan_result = SecurityScanner.scan_url_with_virustotal(url.original_url)
            
            SecurityScan.objects.create(
                url=url,
                scan_type='malware',
                result=scan_result.get('status', 'error'),
                details=scan_result,
                scanner_service='virustotal'
            )
            
            url.last_security_scan = timezone.now()
            
            if scan_result.get('status') == 'malicious':
                url.is_safe = False
                url.temporarily_blocked = True
                url.block_reason = 'Flagged by scheduled security scan'
            
            url.save()
            
            self.stdout.write(
                self.style.SUCCESS(f'Scanned {url.short_code}: {scan_result.get("status")}')
            )