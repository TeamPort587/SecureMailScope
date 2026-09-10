"""WSGI config for SecureMailScope Analysis Engine."""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "analysis.sms_analysis.settings")

application = get_wsgi_application()
