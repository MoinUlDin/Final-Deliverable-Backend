from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.permissions import BasePermission, SAFE_METHODS
from .models import Assignment

class RolePermission(BasePermission):
    """
    Usage in a view/viewset:
        allowed_roles = ['Manager', 'Member']   # roles allowed for non-admins
        permission_classes = [RolePermission]

    Admin always has full access. If a view doesn't set `allowed_roles`,
    default behavior is: Admin only.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if getattr(user, "role", None) == user.Roles.ADMIN:
            return True

        allowed = getattr(view, 'allowed_roles', None)
        if allowed is None:
            return False

        if request.method in SAFE_METHODS:
            return user.role in allowed

        return user.role in allowed

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)

class TaskPermission(BasePermission):
    """
    Admin: full access.
    Manager: create, update, delete, assign, upload files, list all.
    Member: can list / retrieve only tasks they are assigned to, and can update progress (PATCH update_progress)
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        # Admin always allowed
        if getattr(user, "role", None) == user.Roles.ADMIN:
            return True

        # Manager privileges for management actions
        manager_allowed_actions = {'create', 'update', 'partial_update', 'destroy', 'assign', 'upload_files'}
        if getattr(user, "role", None) == user.Roles.MANAGER:
            # Managers allowed for management actions and reads
            return True

        # Member: allow list/retrieve (but filtered in get_queryset) and allow update_progress action
        if getattr(user, "role", None) == user.Roles.MEMBER:
            # allow safe methods (list/retrieve) — object check will enforce assignment
            if request.method in SAFE_METHODS:
                return True
            # allow progress update action (mapped to a detail POST/PATCH)
            if view.action in ('update_progress',):
                return True

        return False

    def has_object_permission(self, request, view, obj):
        user = request.user
        if getattr(user, "role", None) == user.Roles.ADMIN:
            return True
        if getattr(user, "role", None) == user.Roles.MANAGER:
            return True

        # Member: only if assigned to this task
        if getattr(user, "role", None) == user.Roles.MEMBER:
            # allow only actions related to progress update or read
            if view.action in (None, 'retrieve', 'list', 'update_progress', 'partial_update'):
                return Assignment.objects.filter(task=obj, user=user).exists()
        return False

class IsAdminOrReadOnly(BasePermission):
    """
    Allow safe methods (GET, HEAD, OPTIONS) to any authenticated user.
    Only allow write methods (POST, PUT, PATCH, DELETE) if the user's role is Admin.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if request.method in SAFE_METHODS:
            return True

        return getattr(user, "role", None) == user.Roles.ADMIN