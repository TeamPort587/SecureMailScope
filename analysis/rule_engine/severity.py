"""Severity and Confidence constants for Rule Engine findings."""


class Severity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence:
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
