"""
SecureMailScope Security Intelligence

Public entry point for the recommendation and risk intelligence layer.

Input:
    Django analysis + ML result

Output:
    Final security intelligence for Node.js
"""


from .service import build_security_intelligence


def analyze_security_intelligence(
    django_analysis,
    ml_result,
):
    """
    Build final security intelligence from Django and ML results.

    Args:
        django_analysis (dict):
            Complete analysis response from Django.

        ml_result (dict):
            ML prediction returned by Aditi's pipeline.

    Returns:
        dict:
            Final security intelligence object.
    """

    return build_security_intelligence(
        django_analysis=django_analysis,
        ml_result=ml_result,
    )