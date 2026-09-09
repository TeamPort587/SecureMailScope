"""Rule Engine orchestrator for SecureMailScope.

Evaluates SecurityProfile objects against deterministic security rules.
Does not depend on Django ORM or external network state.
"""

from typing import List
from analysis.feature_extraction.models import Finding, SecurityProfile
from analysis.rule_engine.rules import ALL_RULES


def evaluate_profile(
    profile: SecurityProfile,
    start_index: int = 1,
) -> List[Finding]:
    """Evaluate a single SecurityProfile against all active deterministic rules.

    Args:
        profile: The normalized session SecurityProfile.
        start_index: Starting integer for generating sequential finding IDs.

    Returns:
        List of Finding objects generated for this profile.
    """
    findings: List[Finding] = []
    current_idx = start_index

    for rule in ALL_RULES:
        finding_id = f"finding-{current_idx:03d}"
        finding = rule.evaluate(profile, finding_id=finding_id)
        if finding:
            findings.append(finding)
            current_idx += 1

    return findings
