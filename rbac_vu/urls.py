from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from task.views import (
    RegisterView, AdminApprovalView, LoginView,
    ChangePasswordView, PasswordResetRequestView, PasswordResetConfirmView, PendingRequests
)
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
urlpatterns = [
     # JWT auth endpoints
     path("auth/register/", RegisterView.as_view(), name="auth-register"),
    path("auth/approve/", AdminApprovalView.as_view(), name="auth-approve"),
    path("auth/login/", LoginView.as_view(), name="token_obtain_pair"),
    path("auth/pending-requests/", PendingRequests.as_view(), name="pending-requests"),
    path("auth/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("auth/password-reset/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("auth/password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),   # returns access + refresh
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # rotates refresh if enabled
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # drf-spectacular OpenAPI schema + UIs
    path('', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    path('tasks/', include('task.urls')),
    path('admin/', admin.site.urls),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)