from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.core.cache import cache
from ipgeolocation import IpGeoLocation
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeoLocation()

    def __call__(self, request):
        # Extract IP
        ip = request.META.get('REMOTE_ADDR')
        forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if forwarded:
            ip = forwarded.split(',')[0]

        # Block check
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Get cached geolocation (24h = 86400s)
        geo_data = cache.get(f"geo_{ip}")
        if not geo_data:
            try:
                location = self.geo.get_location(ip)
                geo_data = {
                    "country": location.get("country_name"),
                    "city": location.get("city"),
                }
            except Exception:
                geo_data = {"country": None, "city": None}

            cache.set(f"geo_{ip}", geo_data, timeout=86400)  # 24h

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            timestamp=now(),
            path=request.path,
            country=geo_data["country"],
            city=geo_data["city"],
        )

        return self.get_response(request)
