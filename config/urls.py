from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('apps.api_urls')),
    # Legacy routes — will be removed after Phase 1
    path('', include('main.urls')),
    path('admins/', include('admins.urls')),
]
