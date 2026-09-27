"""Standards profiles package."""

from analysis.standards.profiles.base import BaseStandardsProfile
from analysis.standards.profiles.ietf_tls import IETFModernTLSProfile
from analysis.standards.profiles.email_security import EmailSecurityProfile
from analysis.standards.profiles.nist_guidance import NISTGuidanceProfile

ALL_STANDARDS_PROFILES = [
    IETFModernTLSProfile(),
    EmailSecurityProfile(),
    NISTGuidanceProfile(),
]

__all__ = [
    "BaseStandardsProfile",
    "IETFModernTLSProfile",
    "EmailSecurityProfile",
    "NISTGuidanceProfile",
    "ALL_STANDARDS_PROFILES",
]
