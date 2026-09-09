"""
SecureMailScope ML Module
=========================

Machine learning risk scoring for SMTP, IMAP, and POP3 session security analysis.

This module operates **per session**, consuming structured analysis JSON
produced by the Django analysis service and generating risk predictions
with explainable outputs.
"""

__version__ = "1.0.0"
