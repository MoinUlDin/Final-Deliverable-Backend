# serializers.py
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
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
            'picture': picture_url if getattr(user, 'picture', None) else None,
            'is_active': user.is_active,
            'is_approved': bool(user.is_approved, ),
        }
        print(f'\n Senind response with {user_info}')
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

class PendingUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", 'employee_number', "last_name", "role", "date_joined"]        
          

class AdminApprovalSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()
    action = serializers.ChoiceField(choices=["approve", "reject"])


