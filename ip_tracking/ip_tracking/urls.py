from django.contrib import admin
from django.urls import path
from ip_tracking.views import login_view, RequestLogListView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/logs/', RequestLogListView.as_view(), name='request-logs'),
    path('api/login/', login_view, name='login'),
]
