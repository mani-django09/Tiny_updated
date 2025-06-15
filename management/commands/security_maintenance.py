from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Count, Q
from shortener.models import (
    URL, SecurityScan, SuspiciousActivity, LinkReport, 
    ClickAnalytics, RateLimitLog
)
from datetime import timedelta
import logging

class Command(BaseCommand):
    help = 'Perform security maintenance tasks and generate security reports'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--cleanup-age',
            type=int,
            default=90,
            help='Age in days for cleaning up old records (default: 90)',
        )
        parser.add_argument(
            '--generate-report',
            action='store_true',
            help='Generate security summary report',
        )
        parser.add_argument(
            '--check-anomalies',
            action='store_true',
            help='Check for security anomalies and suspicious patterns',
        )
    
    def handle(self, *args, **options):
        self.stdout.write('🔧 Starting security maintenance...')
        
        if options['cleanup_age']:
            self.cleanup_old_records(options['cleanup_age'])
        
        if options['generate_report']:
            self.generate_security_report()
        
        if options['check_anomalies']:
            self.check_security_anomalies()
        
        self.update_security_metrics()
        
        self.stdout.write(self.style.SUCCESS('✅ Security maintenance completed!'))
    
    def cleanup_old_records(self, age_days):
        """Clean up old security records"""
        self.stdout.write(f'🧹 Cleaning records older than {age_days} days...')
        
        cutoff_date = timezone.now() - timedelta(days=age_days)
        
        # Clean up old scan records
        old_scans = SecurityScan.objects.filter(scanned_at__lt=cutoff_date)
        scan_count = old_scans.count()
        old_scans.delete()
        self.stdout.write(f'   Deleted {scan_count} old scan records')
        
        # Clean up resolved suspicious activities
        old_activities = SuspiciousActivity.objects.filter(
            timestamp__lt=cutoff_date,
            resolved=True
        )
        activity_count = old_activities.count()
        old_activities.delete()
        self.stdout.write(f'   Deleted {activity_count} resolved suspicious activities')
        
        # Clean up old rate limit logs
        old_rate_logs = RateLimitLog.objects.filter(
            timestamp__lt=cutoff_date
        )
        rate_log_count = old_rate_logs.count()
        old_rate_logs.delete()
        self.stdout.write(f'   Deleted {rate_log_count} old rate limit logs')
        
        # Clean up old click analytics (keep recent for statistics)
        very_old_date = timezone.now() - timedelta(days=age_days * 2)  # Keep longer for analytics
        old_clicks = ClickAnalytics.objects.filter(clicked_at__lt=very_old_date)
        click_count = old_clicks.count()
        old_clicks.delete()
        self.stdout.write(f'   Deleted {click_count} very old click records')
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        self.stdout.write('📊 Generating security report...')
        
        # Date ranges
        today = timezone.now().date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)
        
        # URL Security Statistics
        total_urls = URL.objects.count()
        active_urls = URL.objects.filter(is_active=True).count()
        blocked_urls = URL.objects.filter(temporarily_blocked=True).count()
        flagged_urls = URL.objects.filter(flagged_by_users__gt=0).count()
        
        # Scan Statistics
        total_scans = SecurityScan.objects.count()
        recent_scans = SecurityScan.objects.filter(scanned_at__date__gte=week_ago).count()
        malicious_found = SecurityScan.objects.filter(result='malicious').count()
        
        # API Performance
        google_scans = SecurityScan.objects.filter(scanner_service='google_safebrowsing')
        vt_scans = SecurityScan.objects.filter(scanner_service='virustotal')
        internal_scans = SecurityScan.objects.filter(scanner_service='internal')
        
        # Threat Analysis
        recent_threats = SecurityScan.objects.filter(
            result='malicious',
            scanned_at__date__gte=week_ago
        )
        
        # Generate report
        report = f"""
🔒 SECURITY REPORT - {today}
{'='*50}

📈 URL STATISTICS:
   Total URLs: {total_urls:,}
   Active URLs: {active_urls:,}
   Blocked URLs: {blocked_urls:,} ({blocked_urls/max(total_urls,1)*100:.1f}%)
   Flagged by Users: {flagged_urls:,}

🔍 SCANNING STATISTICS:
   Total Scans Performed: {total_scans:,}
   Scans This Week: {recent_scans:,}
   Malicious URLs Found: {malicious_found:,}
   Detection Rate: {malicious_found/max(total_scans,1)*100:.2f}%

🛡️ API PERFORMANCE:
   Google Safe Browsing: {google_scans.count():,} scans
   VirusTotal: {vt_scans.count():,} scans
   Internal Scanner: {internal_scans.count():,} scans

⚠️ RECENT THREATS:
   Threats Found This Week: {recent_threats.count():,}
"""
        
        # Add threat breakdown
        if recent_threats.exists():
            threat_types = {}
            for scan in recent_threats:
                if scan.scanner_service == 'google_safebrowsing':
                    google_data = scan.details.get('google_safebrowsing', {})
                    threats = google_data.get('threats', [])
                    for threat in threats:
                        threat_type = threat.get('threatType', 'Unknown')
                        threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            if threat_types:
                report += "\n📊 THREAT BREAKDOWN:\n"
                for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                    report += f"   {threat_type}: {count:,}\n"
        
        # Suspicious Activity
        unresolved_activities = SuspiciousActivity.objects.filter(resolved=False).count()
        recent_activities = SuspiciousActivity.objects.filter(
            timestamp__date__gte=week_ago
        ).count()
        
        report += f"""
🚨 SUSPICIOUS ACTIVITY:
   Unresolved Activities: {unresolved_activities:,}
   New Activities This Week: {recent_activities:,}

🎯 RECOMMENDATIONS:
"""
        
        # Add recommendations based on data
        if blocked_urls / max(total_urls, 1) > 0.05:  # More than 5% blocked
            report += "   • High block rate detected - review scanning sensitivity\n"
        
        if unresolved_activities > 50:
            report += "   • Many unresolved suspicious activities - review and resolve\n"
        
        if recent_scans == 0:
            report += "   • No recent scans - ensure periodic scanning is active\n"
        
        # Print report
        self.stdout.write(report)
        
        # Log report
        logging.info(f"Security report generated: {total_urls} URLs, {blocked_urls} blocked, {malicious_found} threats found")
    
    def check_security_anomalies(self):
        """Check for security anomalies and suspicious patterns"""
        self.stdout.write('🔍 Checking for security anomalies...')
        
        anomalies_found = 0
        
        # Check for URLs with unusual click patterns
        suspicious_urls = URL.objects.annotate(
            recent_clicks=Count(
                'analytics',
                filter=Q(analytics__clicked_at__gte=timezone.now() - timedelta(hours=1))
            )
        ).filter(recent_clicks__gt=100)  # More than 100 clicks in 1 hour
        
        if suspicious_urls.exists():
            anomalies_found += suspicious_urls.count()
            self.stdout.write(f'   ⚠️  {suspicious_urls.count()} URLs with unusual click patterns')
            
            for url in suspicious_urls[:5]:  # Show top 5
                self.stdout.write(f'      • {url.short_code}: {url.recent_clicks} clicks in 1 hour')
        
        # Check for mass URL creation from same IP
        recent_rate_logs = RateLimitLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=1),
            action='url_create'
        ).values('ip_address').annotate(
            count=Count('id')
        ).filter(count__gt=20)  # More than 20 URLs in 1 hour
        
        if recent_rate_logs.exists():
            anomalies_found += recent_rate_logs.count()
            self.stdout.write(f'   ⚠️  {recent_rate_logs.count()} IPs with mass URL creation')
            
            for log in recent_rate_logs[:5]:
                self.stdout.write(f'      • IP {log["ip_address"]}: {log["count"]} URLs created')
        
        # Check for sudden spike in malicious detections
        recent_malicious = SecurityScan.objects.filter(
            result='malicious',
            scanned_at__gte=timezone.now() - timedelta(hours=6)
        ).count()
        
        normal_rate = SecurityScan.objects.filter(
            result='malicious',
            scanned_at__gte=timezone.now() - timedelta(days=7),
            scanned_at__lt=timezone.now() - timedelta(hours=6)
        ).count() / (7 * 4)  # Average per 6-hour period over last week
        
        if recent_malicious > normal_rate * 3:  # 3x normal rate
            anomalies_found += 1
            self.stdout.write(f'   ⚠️  Spike in malicious detections: {recent_malicious} (normal: {normal_rate:.1f})')
        
        if anomalies_found == 0:
            self.stdout.write('   ✅ No security anomalies detected')
        else:
            self.stdout.write(f'   🚨 {anomalies_found} anomalies detected - review recommended')
    
    def update_security_metrics(self):
        """Update security metrics and scores"""
        self.stdout.write('📊 Updating security metrics...')
        
        # Update URLs that haven't been scored recently
        urls_to_update = URL.objects.filter(
            Q(last_security_scan__lt=timezone.now() - timedelta(days=30)) |
            Q(last_security_scan__isnull=True)
        )[:100]  # Limit to avoid long processing
        
        updated_count = 0
        for url in urls_to_update:
            # Recalculate security score based on various factors
            base_score = 100
            
            # Reduce score for user flags
            base_score -= min(url.flagged_by_users * 10, 50)
            
            # Reduce score for recent malicious scans
            recent_malicious_scans = SecurityScan.objects.filter(
                url=url,
                result='malicious',
                scanned_at__gte=timezone.now() - timedelta(days=30)
            ).count()
            base_score -= min(recent_malicious_scans * 20, 60)
            
            # Reduce score for suspicious patterns
            if url.clicks > 10000:  # Very high traffic
                recent_clicks = ClickAnalytics.objects.filter(
                    url=url,
                    clicked_at__gte=timezone.now() - timedelta(hours=24)
                ).count()
                if recent_clicks > url.clicks * 0.1:  # More than 10% of total clicks in 24h
                    base_score -= 15
            
            # Update score
            url.security_score = max(0, min(100, base_score))
            url.save(update_fields=['security_score'])
            updated_count += 1
        
        self.stdout.write(f'   Updated security scores for {updated_count} URLs')


# Save this as: shortener/management/commands/test_security_apis.py

from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Test security API configurations and connectivity'
    
    def handle(self, *args, **options):
        self.stdout.write('🧪 Testing security API configurations...')
        
        # Test Google Safe Browsing
        self.test_google_safebrowsing()
        
        # Test VirusTotal
        self.test_virustotal()
        
        # Test Redis Cache
        self.test_redis_cache()
        
        self.stdout.write(self.style.SUCCESS('✅ API testing completed!'))
    
    def test_google_safebrowsing(self):
        """Test Google Safe Browsing API"""
        self.stdout.write('🛡️ Testing Google Safe Browsing API...')
        
        if not hasattr(settings, 'GOOGLE_SAFEBROWSING_API_KEY') or not settings.GOOGLE_SAFEBROWSING_API_KEY:
            self.stdout.write(self.style.ERROR('   ❌ Google Safe Browsing API key not configured'))
            return
        
        try:
            from shortener.views import check_url_with_google_safebrowsing
            
            # Test with known safe URL
            result = check_url_with_google_safebrowsing('https://www.google.com')
            if result['status'] == 'safe':
                self.stdout.write(self.style.SUCCESS('   ✅ Google Safe Browsing API working'))
            else:
                self.stdout.write(self.style.WARNING(f'   ⚠️  Unexpected result: {result}'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'   ❌ Google Safe Browsing API error: {e}'))
    
    def test_virustotal(self):
        """Test VirusTotal API"""
        self.stdout.write('🦠 Testing VirusTotal API...')
        
        if not hasattr(settings, 'VIRUSTOTAL_API_KEY') or not settings.VIRUSTOTAL_API_KEY:
            self.stdout.write(self.style.ERROR('   ❌ VirusTotal API key not configured'))
            return
        
        try:
            from shortener.views import check_url_with_virustotal
            
            # Test with known safe URL
            result = check_url_with_virustotal('https://www.google.com')
            if result['status'] in ['safe', 'unknown']:  # VirusTotal might not have data
                self.stdout.write(self.style.SUCCESS('   ✅ VirusTotal API working'))
            else:
                self.stdout.write(self.style.WARNING(f'   ⚠️  Unexpected result: {result}'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'   ❌ VirusTotal API error: {e}'))
    
    def test_redis_cache(self):
        """Test Redis cache connectivity"""
        self.stdout.write('🔴 Testing Redis cache...')
        
        try:
            from django.core.cache import cache
            
            # Test cache operations
            test_key = 'security_test_key'
            test_value = 'security_test_value'
            
            cache.set(test_key, test_value, 30)
            retrieved_value = cache.get(test_key)
            
            if retrieved_value == test_value:
                self.stdout.write(self.style.SUCCESS('   ✅ Redis cache working'))
                cache.delete(test_key)  # Cleanup
            else:
                self.stdout.write(self.style.ERROR('   ❌ Redis cache not working properly'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'   ❌ Redis cache error: {e}'))
