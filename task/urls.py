# urls.py (app)
from django.urls import path
from .views import (
    RegisterView, AdminApprovalView, LoginView,
    ChangePasswordView, PasswordResetRequestView, PasswordResetConfirmView, PendingRequests
)


urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="auth-register"),

    path("auth/approve/", AdminApprovalView.as_view(), name="auth-approve"),
    path("auth/login/", LoginView.as_view(), name="token_obtain_pair"),
    path("auth/pending-requests/", PendingRequests.as_view(), name="pending-requests"),
    path("auth/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("auth/password-reset/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("auth/password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
]
