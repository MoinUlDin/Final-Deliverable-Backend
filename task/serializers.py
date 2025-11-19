# serializers.py
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils import timezone
from django.db import transaction
from .models import Task, Assignment, TaskFile, Notification

User = get_user_model()

        
class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = [
            "first_name", "last_name", "username", "password",
            "role", 'is_approved','is_rejected',  
            "employee_number", "department", "picture",
            "email",
        ]
        read_only_fields = ['is_approved','is_rejected']

    def validate_role(self, value):
        if value == User.Roles.ADMIN:
            raise serializers.ValidationError("Cannot set role to Admin during registration.")
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data): 
        role = validated_data.pop("role", None)
        if not role:
            raise serializers.ValidationError({"role": "This field is required."})

        user = User(
            username=validated_data["username"],
            email=validated_data.get("email"),
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            employee_number=validated_data.get("employee_number"),
            department=validated_data.get("department"),
            role=role, 
        )
        if validated_data.get("picture"):
            user.picture = validated_data.get("picture")
        user.set_password(validated_data["password"])
        user.save()
        return user


class LoginSerializer(TokenObtainPairSerializer):
    """
    Return the standard access/refresh tokens AND a user_info block.
    Also add small claims to the token (role, username).
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        user = getattr(self, 'user', None)

        if getattr(user, 'picture', None):
            try:
                picture_url = self.context.get('request').build_absolute_uri(user.picture.url)
            except Exception:
                picture_url = user.picture.url
        else:
            picture_url = None


        if user and not user.is_approved:
            raise serializers.ValidationError(
                {'detail': 'Your account is not active. Please wait for admin approval.'}
            )

        user_info = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'department': user.department,
            'employee_number': user.employee_number,
            'profile_picture': picture_url if getattr(user, 'picture', None) else None,
            'is_active': user.is_active,
            'is_approved': bool(user.is_approved, ),
        }
        data['user_info'] = user_info

        return data


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate_new_password(self, value):
        validate_password(value)
        return value

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", 'picture', "email", "first_name", 'employee_number', "last_name", "role", "date_joined"]        
          
class AdminApprovalSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    action = serializers.ChoiceField(choices=["approve", "reject"])

class CompactTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "priority", "status", "progress",
            "due_date", "created_at", "updated_at", "completed_at",
        ]

class TaskSerializer(serializers.ModelSerializer):
    # write-only list of user IDs to assign on create/update
    assignees = serializers.ListField(
        child=serializers.IntegerField(),
        write_only=True,
        required=False,
        help_text="List of user IDs to assign to this task (members only)."
    )
    # files can also be provided in multipart as 'files' (handled in view)
    files = serializers.ListField(child=serializers.FileField(), write_only=True, required=False)

    # read-only compact user info fields
    created_by = serializers.SerializerMethodField(read_only=True)
    assigned_users = serializers.SerializerMethodField(read_only=True)

    # NEW: return attached files metadata & URL
    attached_files = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Task
        fields = [
            "id", "title", "description", "priority", "status", "progress",
            "due_date", "created_at", "updated_at", "completed_at",
            "created_by", "assignees", "files", "assigned_users", "attached_files", "meta",
        ]
        read_only_fields = [
            "id", "created_at", "updated_at", "completed_at",
            "created_by", "assigned_users", "attached_files",
        ]
    def create(self, validated_data):
        # Remove non-model keys so Model.objects.create() won't receive them.
        # We keep a copy if needed, but view already read serializer.validated_data before calling save().
        validated_data.pop("assignees", None)
        validated_data.pop("files", None)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        # Remove non-model keys so Model.objects.update() won't receive them.
        validated_data.pop("assignees", None)
        validated_data.pop("files", None)
        return super().update(instance, validated_data)
    
    def _profile_picture_url(self, user):
        """
        Return absolute URL for user's picture when possible, otherwise None.
        """
        if not user:
            return None
        pic = getattr(user, "picture", None)
        if not pic:
            return None
        try:
            request = self.context.get("request", None)
            if request is not None:
                return request.build_absolute_uri(pic.url)
            return pic.url
        except Exception:
            try:
                return pic.url
            except Exception:
                return None

    def _compact_user(self, user):
        if not user:
            return None
        return {
            "id": user.id,
            "first_name": getattr(user, "first_name", ""),
            "last_name": getattr(user, "last_name", ""),
            "username": getattr(user, "username", ""),
            "employee_number": getattr(user, "employee_number", ""),
            "profile_picture": self._profile_picture_url(user),
            "role": getattr(user, "role", None),
            "email": getattr(user, "email", None),
        }

    def get_created_by(self, obj):
        """
        Return compact user info for created_by.
        """
        return self._compact_user(obj.created_by) if obj.created_by else None

    def get_assigned_users(self, obj):
        """
        Return a list of assignment entries. Each entry contains:
        {
          "assignee": {compact user},
          "assigned_by": {compact user or null},
          "assigned_at": "ISO datetime string" or null
        }
        """
        result = []
        assignments = obj.assignments.select_related("user", "assigned_by").all()
        for a in assignments:
            assigned_by_user = a.assigned_by  # may be None
            assignee_user = getattr(a, "user", None)
            assigned_at = getattr(a, "assigned_at", None)
            assigned_at_iso = assigned_at.isoformat() if assigned_at is not None else None

            result.append({
                "assignee": self._compact_user(assignee_user),
                "assigned_by": self._compact_user(assigned_by_user),
                "assigned_at": assigned_at_iso,
            })
        return result

    def get_attached_files(self, obj):
        """
        Return metadata for TaskFile objects related to this task.
        Each file entry:
        {
          "id": str(uuid),
          "file_name": "...",
          "file_size": 12345,
          "content_type": "application/pdf",
          "uploaded_at": "ISO datetime",
          "uploaded_by": {compact user or null},
          "url": "absolute url to file"
        }
        """
        files_qs = obj.files.select_related("uploaded_by").all()
        request = self.context.get("request", None)
        out = []
        for f in files_qs:
            # file url (absolute when request available)
            file_url = None
            try:
                if getattr(f, "file", None):
                    if request is not None:
                        try:
                            file_url = request.build_absolute_uri(f.file.url)
                        except Exception:
                            file_url = f.file.url
                    else:
                        file_url = f.file.url
            except Exception:
                file_url = None

            uploaded_at_iso = f.uploaded_at.isoformat() if f.uploaded_at is not None else None

            out.append({
                "id": str(getattr(f, "id", None)),
                "file_name": f.file_name or (getattr(f.file, "name", None) if getattr(f, "file", None) else None),
                "file_size": f.file_size,
                "content_type": f.content_type,
                "uploaded_at": uploaded_at_iso,
                "uploaded_by": self._compact_user(getattr(f, "uploaded_by", None)),
                "url": file_url,
            })
        return out

    def validate_progress(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Progress must be between 0 and 100.")
        return value



class NotificationSerializer(serializers.ModelSerializer):
    """
    Notification serializer.
    recipient is required (primary-key). The `read` flag may be toggled by the client.
    """
    recipient = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Notification
        fields = [
            "id",
            "recipient",
            "type",
            "title",
            "message",
            "meta",
            "read",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]



