from django.contrib import admin
from django.urls import path, include
from drf_yasg.views import get_schema_view
from django.conf import settings
from drf_yasg import openapi
from rest_framework import permissions
from django.conf.urls.static import static

schema_view = get_schema_view(
   openapi.Info(
      title=settings.PROJECT_NAME_,
      default_version='v1',
      description= f"This is the backend APIs for {settings.PROJECT_NAME_}",
      contact=openapi.Contact(email="akinolasamson1234@gmail.com"),
      license=openapi.License(name=settings.PROJECT_NAME_),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api/v1/auth/', include('authentication.urls')),
    path('api/v1/admin/', include('administration.urls')),
    path('api/v1/user/', include('user.urls')),
    path('api/v1/notification/', include('notification.urls')),
]

if settings.ENVIROMENT != 'prod':
    urlpatterns += path('admin/', admin.site.urls),
    urlpatterns += static(settings.STATIC_URL,
                        document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)