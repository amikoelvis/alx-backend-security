from celery import shared_task
from django.utils.timezone import now, timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/api/login/", "/login"]

@shared_task
def detect_anomalies():
    one_hour_ago = now() - timedelta(hours=1)
    logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    # Count requests per IP
    ip_counts = {}
    for log in logs:
        ip_counts[log.ip_address] = ip_counts.get(log.ip_address, 0) + 1

        # Check sensitive paths
        if any(log.path.startswith(p) for p in SENSITIVE_PATHS):
            SuspiciousIP.objects.get_or_create(
                ip_address=log.ip_address,
                defaults={"reason": f"Accessed sensitive path {log.path}"},
            )

    # Flag IPs exceeding threshold
    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                defaults={"reason": f"Excessive requests: {count} in last hour"},
            )
