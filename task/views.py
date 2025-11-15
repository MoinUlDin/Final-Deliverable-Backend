# views.py
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from .permissions import  RolePermission
from rest_framework_simplejwt.views import TokenObtainPairView
from .permissions import IsAdminOrReadOnly
from .serializers import (
    RegistrationSerializer,
    LoginSerializer,
    ChangePasswordSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserSerializer, AdminApprovalSerializer
)

User = get_user_model()
token_generator = PasswordResetTokenGenerator()


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = RegistrationSerializer

    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            print("❌ Serializer errors:", serializer.errors)  # <-- print in console
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        admins = User.objects.filter(role=User.Roles.ADMIN)
        admin_emails = [a.email for a in admins if a.email]
        if admin_emails:
            subject = "New user registration awaiting approval"
            body = (
                f"A new user has registered:\n\n"
                f"Username: {user.username}\n"
                f"Name: {user.get_full_name()}\n"
                f"Employee #: {user.employee_number}\n\n"
                f"Approve or reject via admin API."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)

        return Response({"detail": "Registration successful. Awaiting admin approval."}, status=status.HTTP_201_CREATED)


class AdminApprovalView(APIView):
    """
    Admin-only: approve or reject a pending registration.

    POST payload examples:
    { "user_id": 5, "action": "approve" }   # or "reject"
    """
    permission_classes = [IsAuthenticated] 
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = AdminApprovalSerializer
    def post(self, request):
        if getattr(request.user, "role", None) != User.Roles.ADMIN:
            return Response({"detail": "Admin only."}, status=status.HTTP_403_FORBIDDEN)

        user_id = request.data.get("user_id")
        action = request.data.get("action", "approve").lower()
        if not user_id:
            return Response({"detail": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)

        if action == "approve":
            user.is_approved = True
            user.is_rejected = False
            user.save()
            subject = "Your account has been approved"
            body = (
                f"Hello {user.get_full_name()},\n\n"
                "Your account has been approved by the administrator. You can now log in."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
            return Response({"detail": "User approved and notified."})
        elif action == "reject":
            user.is_rejected = True
            user.is_approved = False
            user.save()
            subject = "Your account registration was not approved"
            body = (
                f"Hello {user.get_full_name()},\n\n"
                "Your registration was not approved by the administrator. If you think this is a mistake, contact support."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
            return Response({"detail": "User rejected and notified."})
        else:
            return Response({"detail": "Unknown action. Use 'approve' or 'reject'."}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
    authentication_classes = []
    permission_classes = [AllowAny]


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class=ChangePasswordSerializer

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        np = serializer.validated_data["new_password"]
        op = serializer.validated_data["old_password"]

        if not user.check_password(op):
            return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(np)
        user.save()
        return Response({"detail": "Password changed successfully."})


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        givenEmail = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=givenEmail)
        except User.DoesNotExist:
            return Response({"detail": "If an account with that email exists, a reset link has been sent."})

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        frontend_url = getattr(settings, "FRONTEND_URL", None)
        if frontend_url:
            reset_link = f"{frontend_url}/reset-password/?uid={uid}&token={token}"
        else:
            reset_link = f"uid={uid}&token={token}"

        subject = "Password reset request"
        body = (
            f"Hello {user.get_full_name()},\n\n"
            f"Hello {user.first_name} {user.last_name},\n\n"
            f"We received a request to reset your password. Use the given link to set a new password:\n\n"
            f"{reset_link}\n\n"
            "If you did not request this, you can ignore this email."
        )
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        return Response({"detail": "If an account with that email exists, a reset link has been sent."})


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uidb64 = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"detail": "Invalid uid"}, status=status.HTTP_400_BAD_REQUEST)

        if not token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password has been reset successfully."})

class PendingRequests(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = UserSerializer
    def get(self, request):
        users = User.objects.all().exclude(role=User.Roles.ADMIN)
        pending_users = users.filter(is_approved=False, is_rejected=False)
        rejected_users = users.filter(is_rejected=True)
        active_users = users.filter(is_approved=True, is_active=True)
        pending_serializer = UserSerializer(pending_users, many=True, context={"request": request})
        rejected = UserSerializer(rejected_users, many=True, context={"request": request})
        active = UserSerializer(active_users, many=True, context={"request": request})

        manager_count = users.filter(role=User.Roles.MANAGER).count()
        member_count = users.filter(role=User.Roles.MEMBER).count()
        data = {
            'count': {
                "total": users.count(),
                "pending": pending_users.count(),
                "active": active_users.count(),
                "rejected": rejected_users.count(),
                'manager': manager_count,
                "member": member_count,
                },
            "pending": pending_serializer.data,
            "rejected": rejected.data,
            'active': active.data,
        }
        return Response(data)



