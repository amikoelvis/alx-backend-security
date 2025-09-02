from .models import RequestLog
from django.utils.timezone import now

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get('REMOTE_ADDR')
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded:
            ip = forwarded.split(',')[0]

        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path
        )
        return self.get_response(request)
