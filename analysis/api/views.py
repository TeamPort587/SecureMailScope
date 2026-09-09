"""API Views for SecureMailScope Analysis Engine."""

import logging
import os
import tempfile
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from analysis.integration.pipeline import AnalysisError, analyze_pcap

logger = logging.getLogger(__name__)


class InternalAnalyzeView(APIView):
    """Internal endpoint for Node Gateway to submit a PCAP for offline forensic analysis.

    POST /internal/analyze
    Consumes: multipart/form-data (file=<PCAP>)
    Returns: JSON response strictly conforming to django-analysis-response.json
    """

    def post(self, request, *args, **kwargs):
        uploaded_file = request.FILES.get("file")
        if not uploaded_file:
            return Response(
                {
                    "status": "failed",
                    "error": {
                        "code": "MISSING_FILE",
                        "message": "No capture file provided in 'file' field.",
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        analysis_id = request.data.get("analysis_id")
        filename = request.data.get("filename") or uploaded_file.name

        # Save uploaded file to secure temporary file
        temp_fd, temp_path = tempfile.mkstemp(suffix=".pcap", prefix="sms_capture_")
        try:
            with os.fdopen(temp_fd, "wb") as dest:
                for chunk in uploaded_file.chunks():
                    dest.write(chunk)

            # Execute pipeline
            result = analyze_pcap(
                file_path=temp_path,
                analysis_id=analysis_id,
                filename=filename,
            )
            return Response(result, status=status.HTTP_200_OK)

        except AnalysisError as err:
            logger.warning(f"Analysis error [{err.code}]: {err.message}")
            return Response(
                {
                    "status": "failed",
                    "error": {
                        "code": err.code,
                        "message": err.message,
                    },
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as exc:
            logger.exception("Unexpected failure during PCAP analysis")
            return Response(
                {
                    "status": "failed",
                    "error": {
                        "code": "ANALYSIS_FAILED",
                        "message": "An internal error occurred while processing the capture file.",
                    },
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception as clean_err:
                    logger.warning(f"Failed to remove temp file {temp_path}: {clean_err}")


class HealthCheckView(APIView):
    """Basic health check endpoint for Gateway or monitoring."""

    def get(self, request, *args, **kwargs):
        return Response({"status": "healthy", "service": "sms-analysis-engine"})
