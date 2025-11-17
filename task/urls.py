# urls.py (app)
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TaskViewSet,RemoveAttachedFile
)

router = DefaultRouter()
router.register('', TaskViewSet, basename='task')

urlpatterns = [
    path("", include(router.urls)),
    path("remove-file/<uuid:pk>", RemoveAttachedFile.as_view(), name='remove-file'),
]
