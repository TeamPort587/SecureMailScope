"""URL routes for internal analysis API."""

from django.urls import path
from analysis.api.views import HealthCheckView, InternalAnalyzeView

urlpatterns = [
    path("internal/analyze", InternalAnalyzeView.as_view(), name="internal-analyze"),
    path("health", HealthCheckView.as_view(), name="health-check"),
]
