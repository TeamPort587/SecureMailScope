"""Root URL configuration for SecureMailScope Analysis Engine."""

from django.urls import include, path

urlpatterns = [
    path("", include("analysis.api.urls")),
]
