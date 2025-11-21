# views.py
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets, status, mixins
from rest_framework.decorators import action
from django.db.models import Avg, F, Count, Q
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from rest_framework.exceptions import ValidationError, PermissionDenied
from .serializers import (
    RegistrationSerializer, CompactTaskSerializer,
    LoginSerializer, TaskSerializer, ProfileSerializer,
    ChangePasswordSerializer, NotificationSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    UserSerializer, AdminApprovalSerializer,
)
from .models import (
    Task, Notification, NotificationState, Comment, 
    TaskFile, Assignment
    )
from .permissions import RolePermission, IsAdminOrReadOnly,TaskPermission


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

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProfileSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    
    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = ProfileSerializer(user, context={'request': request})
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def patch(self, request, *args, **kwargs):
        """
        Partial update for profile fields and picture.
        Allowed to update: first_name, last_name, picture.
        Disallowed (will be ignored if provided): username, email, employee_number, department, role, is_approved, is_rejected
        """
        user = request.user

        # copy incoming data and remove disallowed keys (defensive)
        incoming = request.data.copy() if hasattr(request, "data") else {}
        forbidden = {"username", "email", "employee_number", "department", "role", "is_approved", "is_rejected"}
        for k in list(incoming.keys()):
            if k in forbidden:
                incoming.pop(k, None)

        # Use serializer for validation/save (partial update)
        serializer = ProfileSerializer(user, data=incoming, partial=True, context={"request": request})
        serializer.is_valid(raise_exception=True)

        # Save inside a transaction to be safe (especially with file uploads)
        with transaction.atomic():
            serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)
    
class AdminApprovalView(APIView):
    """
    Admin-only: approve or reject a pending registration.

    POST payload examples:
    { "user_id": 5, "action": "approve" }   # or "reject"
    """
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
            return Response({"old_password": ["Old password is not correct."]}, status=status.HTTP_400_BAD_REQUEST)

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


# ===========================================================================
# ============================= Task View ===================================
# ===========================================================================

class TaskViewSet(viewsets.ModelViewSet):
    """
    Admin/Manager: create, update, delete tasks; assign users; upload files.
    Member: list/retrieve tasks they are assigned to, and update progress (update_progress action).
    """
    queryset = Task.objects.all().order_by('-created_at')
    serializer_class = TaskSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    permission_classes = [IsAuthenticated, TaskPermission]

    def get_queryset(self):
        user = self.request.user
        if getattr(user, "role", None) == user.Roles.MEMBER:
            # Members only see tasks assigned to them
            return Task.objects.filter(assignments__user=user).distinct().order_by('-created_at')
        # Managers and Admins see all
        return super().get_queryset()
    
    def perform_create(self, serializer):
        """
        Handle assignees (list of IDs) and files in a single create call.
        Expect assignees as either JSON array in body (assignees: [1,2]) or form data with multiple assignees.
        Files are in request.FILES.getlist('files').
        """
        user = self.request.user
        if getattr(user, "role", None) not in (user.Roles.MANAGER, user.Roles.ADMIN):
            raise PermissionDenied("Only Managers or Admins can create tasks.")

        assignees = self.request.data.getlist('assignees') if hasattr(self.request.data, "getlist") else self.request.data.get("assignees", [])
        # when assignees come as JSON list from serializer validated_data, they will be present in serializer.validated_data
        try:
            data_assignees = serializer.validated_data.get("assignees", None)
        except Exception:
            data_assignees = None

        if not assignees and data_assignees:
            assignees = data_assignees

        files = self.request.FILES.getlist('files')
        
        with transaction.atomic():
            task = serializer.save(created_by=user)

            # handle assignees
            if assignees:
                for uid in assignees:
                    try:
                        uid_int = int(uid)
                    except Exception:
                        raise ValidationError({"assignees": f"Invalid user id: {uid}"})
                    try:
                        target = User.objects.get(pk=uid_int)
                    except User.DoesNotExist:
                        raise ValidationError({"assignees": f"User id {uid_int} not found."})

                    # Only allow assigning to Members (as requested)
                    if target.role != User.Roles.MEMBER:
                        raise ValidationError({"assignees": f"User {target.username} is not a Member and cannot be assigned."})

                    # create assignment if not exists
                    Assignment.objects.get_or_create(task=task, user=target, defaults={"assigned_by": user})

            # handle files
            for f in files:
                TaskFile.objects.create(
                    task=task,
                    uploaded_by=user,
                    file=f,
                    file_name=getattr(f, 'name', ''),
                    file_size=getattr(f, 'size', None),
                    content_type=getattr(f, 'content_type', None),
                )

    def perform_update(self, serializer):
        """
        Update task and replace assignees if `assignees` is provided.
        - Accepts assignees as repeated form fields (multipart) or JSON array.
        - Does NOT handle files (files are handled on creation and via upload-files endpoint).
        """
        user = self.request.user
        # Only Manager/Admin should update core fields & assignees.
        if getattr(user, "role", None) not in (user.Roles.MANAGER, user.Roles.ADMIN):
            raise PermissionDenied("Only Managers or Admins can update tasks.")

        # Read assignees from request (multipart) or serializer.validated_data (JSON)
        assignees = (
            self.request.data.getlist("assignees")
            if hasattr(self.request.data, "getlist")
            else self.request.data.get("assignees", None)
        )
        try:
            data_assignees = serializer.validated_data.get("assignees", None)
        except Exception:
            data_assignees = None

        # If we didn't find repeated form fields, but serializer has assignees (JSON), use it.
        # Note: assignees may be None (not provided) or [] (explicitly provided empty list)
        if assignees is None and data_assignees is not None:
            assignees = data_assignees

        with transaction.atomic():
            # perform the model update
            task = serializer.save()

            # If assignees is None => client didn't provide assignees -> leave current assignments unchanged.
            # If assignees is provided (could be []), replace assignments with exactly these IDs.
            if assignees is not None:
                new_ids = []
                for uid in assignees:
                    try:
                        uid_int = int(uid)
                    except Exception:
                        raise ValidationError({"assignees": f"Invalid user id: {uid}"})
                    try:
                        target = User.objects.get(pk=uid_int)
                    except User.DoesNotExist:
                        raise ValidationError({"assignees": f"User id {uid_int} not found."})
                    if target.role != User.Roles.MEMBER:
                        raise ValidationError({"assignees": f"User {target.username} is not a Member and cannot be assigned."})
                    new_ids.append(uid_int)

                current_ids = list(Assignment.objects.filter(task=task).values_list("user_id", flat=True))

                to_remove = set(current_ids) - set(new_ids)
                to_add = set(new_ids) - set(current_ids)

                if to_remove:
                    Assignment.objects.filter(task=task, user_id__in=to_remove).delete()

                for uid in to_add:
                    # use get_or_create to avoid duplicates/races
                    Assignment.objects.get_or_create(task=task, user_id=uid, defaults={"assigned_by": user})         
                    
    @action(detail=True, methods=['post'], url_path='assign', url_name='assign')
    def assign(self, request, pk=None):
        """
        Assign members to an existing task (manager/admin action).
        Accepts body: { "assignees": [1,2,3] }
        Behaviour:
          - Add new assignments for ids present in payload but not currently assigned.
          - Remove assignments for ids currently assigned but not present in payload.
          - Return { "detail": "...", "added": [...], "removed": [...] }
        """
        user = request.user
        if getattr(user, "role", None) not in (user.Roles.MANAGER, user.Roles.ADMIN):
            raise PermissionDenied("Only Managers or Admins can assign tasks.")

        task = self.get_object()

        assignees = request.data.get("assignees", [])

        if not isinstance(assignees, (list, tuple)):
            raise ValidationError({"assignees": "assignees must be a list of user ids."})

        # Normalize & validate incoming ids (all must be integers)
        new_ids = set()
        for uid in assignees:
            try:
                new_ids.add(int(uid))
            except Exception:
                raise ValidationError({"assignees": f"Invalid user id: {uid}"})

        # Current assigned user ids for this task
        current_qs = Assignment.objects.filter(task=task).values_list("user_id", flat=True)
        current_ids = set(int(x) for x in current_qs)

        to_add = new_ids - current_ids
        to_remove = current_ids - new_ids

        added = []
        removed = []

        # Validate all user ids in to_add exist and are Members before making DB changes
        if to_add:
            invalid_users = []
            non_members = []
            for uid in list(to_add):
                try:
                    u = User.objects.get(pk=uid)
                except User.DoesNotExist:
                    invalid_users.append(uid)
                    continue
                if u.role != User.Roles.MEMBER:
                    non_members.append(uid)

            if invalid_users:
                raise ValidationError({"assignees": f"User id(s) not found: {invalid_users}"})
            if non_members:
                raise ValidationError({"assignees": f"User id(s) are not members and cannot be assigned: {non_members}"})

        # Now perform DB changes in a transaction
        with transaction.atomic():
            # remove assignments no longer present
            if to_remove:
                removed_qs = Assignment.objects.filter(task=task, user_id__in=list(to_remove))
                # collect removed ids for response
                removed = list(removed_qs.values_list("user_id", flat=True))
                deleted_count, _ = removed_qs.delete()

            # create new assignments (use get_or_create per user so post_save signals fire)
            for uid in to_add:
                target = User.objects.get(pk=uid)  # validated above
                assignment_obj, created_flag = Assignment.objects.get_or_create(
                    task=task, user=target, defaults={"assigned_by": user}
                )
                if created_flag:
                    added.append(target.id)
                

        return Response({"detail": "Assignment update processed.", "added": added, "removed": removed})

    @action(detail=True, methods=['post'], url_path='upload-files', url_name='upload_files', parser_classes=[MultiPartParser, FormParser])
    def upload_files(self, request, pk=None):
        """
        Upload files to an existing task. Managers/Admins (or assigned Member?) can upload.
        Body: multipart with files[].
        """
        task = self.get_object()
        user = request.user

        # who can upload? allow Manager/Admin, or Member if assigned
        if user.role == user.Roles.MEMBER:
            if not Assignment.objects.filter(task=task, user=user).exists():
                raise PermissionDenied("Members can only upload files to tasks they're assigned to.")

        files = request.FILES.getlist('files')
        if not files:
            raise ValidationError({"files": "No files provided."})

        created = []
        for f in files:
            tf = TaskFile.objects.create(
                task=task,
                uploaded_by=user,
                file=f,
                file_name=getattr(f, 'name', ''),
                file_size=getattr(f, 'size', None),
                content_type=getattr(f, 'content_type', None),
            )
            created.append({"id": str(tf.id), "file_name": tf.file_name})

        return Response({"detail": "Files uploaded.", "files": created})

    @action(detail=True, methods=['patch'], url_path='update-progress', url_name='update_progress')
    def update_progress(self, request, pk=None):
        """
        Members can update progress (0-100) on tasks they are assigned to.
        Managers/Admins can also set progress.
        Body: { "progress": 50 }
        """
        task = self.get_object()
        user = request.user

        if user.role == user.Roles.MEMBER:
            # ensure member is assigned to the task
            if not Assignment.objects.filter(task=task, user=user).exists():
                raise PermissionDenied("You are not assigned to this task.")

        progress = request.data.get("progress", None)
        if progress is None:
            raise ValidationError({"progress": "This field is required."})
        try:
            print(f"\n we got progress: {progress} and Type: {type(progress)} \n")
            progress_int = int(progress)
        except Exception:
            raise ValidationError({"progress": "Must be an integer between 0 and 100."})
        if progress_int < 0 or progress_int > 100:
            raise ValidationError({"progress": "Must be between 0 and 100."})

        task.progress = progress_int
        # Optionally update status/completed_at when 100%
        if progress_int < 100 and task.status == Task.Status.COMPLETED:
            return Response ({'detail': 'Task is already Completed, you can update now.'}, status=status.HTTP_400_BAD_REQUEST)
        if progress_int == 100:
            task.status = Task.Status.COMPLETED
            task.completed_at = timezone.now()
        else:
            # If updating from 0 -> >0, set IN_PROGRESS
            if task.status == Task.Status.PENDING and progress_int > 0:
                task.status = Task.Status.IN_PROGRESS

        task.save()
        serializer = self.get_serializer(task)
        return Response(serializer.data)

    @action(detail=False, methods=['get'], url_path='my-tasks', url_name='my_tasks')
    def my_tasks(self, request):
        """
        Convenience endpoint for members to list their assigned tasks.
        """
        user = request.user
        if user.role != user.Roles.MEMBER:
            return Response({"detail": "Only members use this endpoint."}, status=400)
        qs = Task.objects.filter(assignments__user=user).distinct().order_by('-created_at')
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


class RemoveAttachedFile(APIView):
    """
    DELETE /task-files/{pk}/
    Only users in allowed_roles (Admin, Manager) can remove an attached file.
    This removes the DB record and deletes the actual file from storage. ID=File-Id
    """
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER]

    def delete(self, request, pk=None, *args, **kwargs):
        if not pk:
            return Response({"detail": "File id (pk) is required."}, status=status.HTTP_400_BAD_REQUEST)

        task_file = get_object_or_404(TaskFile, pk=pk)

        user = request.user
        if getattr(user, "role", None) not in (User.Roles.ADMIN, User.Roles.MANAGER):
            raise PermissionDenied("Only Admins or Managers may remove attached files.")

        try:
            with transaction.atomic():
                # Delete the actual file from storage if present
                try:
                    if task_file.file and getattr(task_file.file, "name", None):
                        # delete from storage backend; save=False prevents model save
                        task_file.file.delete(save=False)
                except Exception as exc:
                    # If storage deletion fails, we log/continue to let DB record be removed or raise depending on preference.
                    # Keeping it simple: raise to abort transaction and return error.
                    return Response(
                        {"detail": "Failed to delete file from storage.", "error": str(exc)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

                # Delete DB record
                task_file.delete()

        except Exception as exc:
            return Response({"detail": "Failed to remove file.", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"detail": "File deleted."}, status=status.HTTP_200_OK)

class ListMembers(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER]

    def get(self, request, *args, **kwargs):
        member_qs = User.objects.filter(
            role=User.Roles.MEMBER,
            is_active=True,
            is_approved=True
        ).order_by("first_name", "last_name")

        serializer = UserSerializer(member_qs, many=True, context={"request": request})

        return Response(serializer.data, status=status.HTTP_200_OK)

# ===========================================================================
# ============================= Dashboards ==================================
# ===========================================================================
class MemberDashboardView(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER, User.Roles.MEMBER]

    def _compact_user(self, user, request):
        return UserSerializer(user, context={"request": request}).data

    def _compact_task_dict(self, task, member, over_due=False, dead_line=False ):
        # include assignment metadata for this member (assigned_at)
        assignment = Assignment.objects.filter(task=task, user=member).order_by('-assigned_at').first()
        return {
            "id": str(task.id),
            "title": task.title,
            "status": task.status,
            "over_due": over_due,
            "dead_line": dead_line,
            "progress": getattr(task, "progress", 0),
            "due_date": task.due_date.isoformat() if task.due_date else None,
            "assigned_at": assignment.assigned_at.isoformat() if assignment and assignment.assigned_at else None,
        }

    def get(self, request, *args, **kwargs):
        # determine target user (members can only see self)
        query_user_id = request.query_params.get("user_id")
        if request.user.role == User.Roles.MEMBER:
            if query_user_id and str(query_user_id) != str(request.user.id):
                return Response({"detail": "Members can only view their own dashboard."}, status=status.HTTP_403_FORBIDDEN)
            target_user = request.user
        else:
            target_user = get_object_or_404(User, pk=query_user_id) if query_user_id else request.user

        now = timezone.now()
        window = now + timedelta(days=3)   # "next 2 or 3 days" — using 3 days

        base_qs = Task.objects.filter(assignments__user=target_user).distinct()

        total = base_qs.count()
        completed = base_qs.filter(status=Task.Status.COMPLETED).count()
        in_progress = base_qs.filter(status=Task.Status.IN_PROGRESS).count()
        overdue = base_qs.filter(due_date__lt=now).exclude(status=Task.Status.COMPLETED).count()

        # performance
        avg_progress_val = base_qs.aggregate(avg=Avg('progress'))['avg'] or 0
        try:
            average_progress = int(round(avg_progress_val))
        except Exception:
            average_progress = int(avg_progress_val or 0)

        on_time_rate = None
        if completed > 0:
            on_time_count = base_qs.filter(
                status=Task.Status.COMPLETED,
                completed_at__isnull=False,
                due_date__isnull=False,
            ).filter(completed_at__lte=F('due_date')).count()
            on_time_rate = int(round((on_time_count / completed) * 100))

        # Prepare the prioritized 5 tasks
        desired = 10
        selected = []
        selected_ids = set()

        # 1) one overdue (if any) - earliest due first
        overdue_qs = base_qs.filter(due_date__lt=now).exclude(status=Task.Status.COMPLETED).order_by('due_date')
        if overdue_qs.exists():
            for t in overdue_qs:
                selected.append(self._compact_task_dict(t, target_user, over_due=True))
                selected_ids.add(t.id)

        # 2) up to 3 deadline-approaching (next 3 days), excluding already picked
        deadline_qs = base_qs.filter(due_date__gte=now, due_date__lte=window).exclude(status=Task.Status.COMPLETED).exclude(id__in=selected_ids).order_by('due_date')
        for t in deadline_qs[:4]:
            if len(selected) >= desired:
                break
            selected.append(self._compact_task_dict(t, target_user, dead_line=True))
            selected_ids.add(t.id)

        # 3) recent completed tasks to fill remaining slots
        if len(selected) < desired:
            completed_qs = base_qs.filter(status=Task.Status.COMPLETED).exclude(id__in=selected_ids).order_by('-completed_at')
            for t in completed_qs:
                if len(selected) >= desired:
                    break
                selected.append(self._compact_task_dict(t, target_user))
                selected_ids.add(t.id)


        data = {
            "user": self._compact_user(target_user, request),
            "counts": {
                "total": total,
                "in_progress": in_progress,
                "completed": completed,
                "overdue": overdue,
            },
            "performance": {
                "average_progress": average_progress,
                "on_time_completion_rate": on_time_rate,
            },
            "top_tasks": selected,   # up to 5 tasks following your prioritization
        }

        return Response(data, status=status.HTTP_200_OK)

class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.ADMIN]

    def get(self, request, *args, **kwargs):
        # Base sets
        users_qs = User.objects.all()
        total_users = users_qs.count()
        active_count = users_qs.filter(is_active=True).count()
        managers_count = users_qs.filter(role=User.Roles.MANAGER).count()
        members_count = users_qs.filter(role=User.Roles.MEMBER).count()

        tasks_qs = Task.objects.all()
        total_tasks = tasks_qs.count()
        completed_count = tasks_qs.filter(status=Task.Status.COMPLETED).count()

        performance_all = int(round((completed_count / total_tasks) * 100)) if total_tasks > 0 else 0

        # Annotate users with counts: total assigned tasks, completed assigned tasks
        annotated_qs = users_qs.annotate(
            total_assigned=Count("assignments__task", distinct=True),
            completed_assigned=Count(
                "assignments__task",
                filter=Q(assignments__task__status=Task.Status.COMPLETED),
                distinct=True,
            ),
        ).order_by("-total_assigned", "username")

        users_data = []
        for user in annotated_qs:
            # serialize base profile fields
            serializer = ProfileSerializer(user, context={"request": request})
            user_data = serializer.data

            # annotated counts (may be None)
            total_assigned = int(getattr(user, "total_assigned", 0) or 0)
            completed_assigned = int(getattr(user, "completed_assigned", 0) or 0)

            # per-user performance %
            if total_assigned > 0:
                perf = int(round((completed_assigned / total_assigned) * 100))
            else:
                perf = 0

            # Append additional stats
            user_data.update({
                "total_tasks_assigned": total_assigned,
                "completed_tasks_assigned": completed_assigned,
                "performance": perf, 
            })

            users_data.append(user_data)

        payload = {
            "stats": {
                "total_users": total_users,
                "managers": managers_count,
                "members": members_count,
                "active": active_count,
                "total_tasks": total_tasks,
                "completed_count": completed_count,
                "performance": performance_all,
            },
            "users": users_data,
        }

        return Response(payload, status=status.HTTP_200_OK)

# Notifications
class NotificationViewSet(mixins.ListModelMixin,
                          mixins.DestroyModelMixin,
                          viewsets.GenericViewSet):
    """
    Notifications API:
      - list (GET) -> user's notifications
      - destroy (DELETE) -> delete a single notification (recipient only)
      - mark-read (POST detail) -> mark a single notification as read (recipient only)
      - mark-all-read (POST list) -> mark all unread notifications for the current user as read
    Creation / update via API is NOT allowed (notifications are generated by the application).
    """
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Only return notifications that belong to the requesting user
        return Notification.objects.filter(recipient=self.request.user).order_by("-created_at")

    # disable create/update endpoints explicitly to make intent clear
    def create(self, request, *args, **kwargs):
        return Response({"detail": 'Method "POST" not allowed.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def update(self, request, *args, **kwargs):
        return Response({"detail": 'Method "PUT" not allowed.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def partial_update(self, request, *args, **kwargs):
        return Response({"detail": 'Method "PATCH" not allowed.'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    def destroy(self, request, *args, **kwargs):
        notif = self.get_object()
        if notif.recipient != request.user:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        return super().destroy(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, pk=None):
        """
        Mark a single notification as read. Only the recipient may do this.
        """
        notif = self.get_object()
        if notif.recipient != request.user:
            return Response({"detail": "Not allowed."}, status=status.HTTP_403_FORBIDDEN)
        if not notif.read:
            notif.read = True
            notif.save(update_fields=["read"])
        return Response({"status": "ok", "id": str(notif.id), "read": True})

    @action(detail=False, methods=["post"], url_path="mark-all-read")
    def mark_all_read(self, request):
        """
        Mark all unread notifications for the current user as read.
        Returns number of notifications updated.
        """
        qs = Notification.objects.filter(recipient=request.user, read=False)
        updated = qs.update(read=True)
        return Response({"status": "ok", "updated": updated})