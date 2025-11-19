# urls.py (app)
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TaskViewSet,RemoveAttachedFile, ListMembers, NotificationViewSet
)

router = DefaultRouter()
router.register('notifications', NotificationViewSet, basename='notifications')
router.register('', TaskViewSet, basename='task')

urlpatterns = [
    path("list-members/", ListMembers.as_view(), name='list-members'),
    path("remove-file/<uuid:pk>/", RemoveAttachedFile.as_view(), name='remove-file'),
    path("", include(router.urls)),
]
