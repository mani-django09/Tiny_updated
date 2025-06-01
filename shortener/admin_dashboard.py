from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render
from django.db.models import Count, Sum, Q
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse

from .models import URL, ClickAnalytics, SuspiciousActivity, LinkReport, SecurityScan

@staff_member_required
def admin_dashboard(request):
    """Custom admin dashboard with analytics"""
    
    # Time ranges
    today = timezone.now().date()
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)
    
    # Basic stats
    stats = {
        'total_urls': URL.objects.count(),
        'active_urls': URL.objects.filter(is_active=True).count(),
        'total_clicks': URL.objects.aggregate(Sum('clicks'))['clicks__sum'] or 0,
        'today_urls': URL.objects.filter(created_at__date=today).count(),
        'today_clicks': ClickAnalytics.objects.filter(clicked_at__date=today).count(),
    }
    
    # Security stats
    security_stats = {
        'unsafe_urls': URL.objects.filter(is_safe=False).count(),
        'blocked_urls': URL.objects.filter(temporarily_blocked=True).count(),
        'pending_reports': LinkReport.objects.filter(investigated=False).count(),
        'suspicious_activities': SuspiciousActivity.objects.filter(resolved=False).count(),
    }
    
    # Recent activity
    recent_urls = URL.objects.order_by('-created_at')[:10]
    recent_clicks = ClickAnalytics.objects.order_by('-clicked_at')[:20]
    recent_reports = LinkReport.objects.order_by('-reported_at')[:10]
    recent_suspicious = SuspiciousActivity.objects.filter(resolved=False).order_by('-timestamp')[:10]
    
    # Chart data for last 7 days
    chart_data = []
    for i in range(7):
        date = today - timedelta(days=i)
        urls_created = URL.objects.filter(created_at__date=date).count()
        clicks_count = ClickAnalytics.objects.filter(clicked_at__date=date).count()
        chart_data.append({
            'date': date.strftime('%Y-%m-%d'),
            'urls': urls_created,
            'clicks': clicks_count
        })
    
    chart_data.reverse()  # Show oldest to newest
    
    # Top URLs by clicks
    top_urls = URL.objects.filter(clicks__gt=0).order_by('-clicks')[:10]
    
    context = {
        'stats': stats,
        'security_stats': security_stats,
        'recent_urls': recent_urls,
        'recent_clicks': recent_clicks,
        'recent_reports': recent_reports,
        'recent_suspicious': recent_suspicious,
        'chart_data': chart_data,
        'top_urls': top_urls,
    }
    
    return render(request, 'admin/dashboard.html', context)

@staff_member_required
def system_health(request):
    """System health check endpoint"""
    
    try:
        # Database check
        db_check = URL.objects.count() >= 0
        
        # Security check
        security_issues = SuspiciousActivity.objects.filter(
            resolved=False, 
            severity__gte=7
        ).count()
        
        # Recent activity check
        recent_activity = ClickAnalytics.objects.filter(
            clicked_at__gte=timezone.now() - timedelta(hours=1)
        ).count()
        
        health_status = {
            'database': 'healthy' if db_check else 'error',
            'security': 'warning' if security_issues > 0 else 'healthy',
            'activity': 'healthy' if recent_activity >= 0 else 'warning',
            'security_issues_count': security_issues,
            'recent_activity_count': recent_activity,
            'timestamp': timezone.now().isoformat()
        }
        
        return JsonResponse(health_status)
        
    except Exception as e:
        return JsonResponse({
            'database': 'error',
            'security': 'error', 
            'activity': 'error',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }, status=500)