from rest_framework.permissions import BasePermission, SAFE_METHODS

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