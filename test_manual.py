"""
Manual test script for SecureMailScope ML Prediction
Run with: python test_manual.py
"""

import json
from ml.inference.predictor import RiskPredictor

def main():
    print("=" * 60)
    print("SecureMailScope - Manual Inference Test")
    print("=" * 60)

    # 1. Load trained production model
    predictor = RiskPredictor("ml/artifacts")
    print("Loaded model from ml/artifacts")

    # 2. Test Session: SMTP with unobserved TLS/cert and plaintext auth finding
    test_session = {
        "session_id": "manual-test-01",
        "protocol": "SMTP",
        "security": {
            "encryption_mode": "STARTTLS",
            "upgrade_advertised": True,
            "upgrade_requested": True,
            "upgrade_succeeded": False,
            "authentication_before_tls": True
        },
        "tls": None,            # Unobserved handshake (partial capture)
        "certificate": None     # Unobserved certificate
    }

    findings = [
        {
            "finding_id": "F001",
            "session_id": "manual-test-01",
            "severity": "CRITICAL",
            "type": "AUTH_BEFORE_TLS",
            "title": "Plaintext credentials exposed"
        }
    ]

    # 3. Predict risk
    result = predictor.predict_session(test_session, findings)

    print("\n--- PREDICTION RESULT ---")
    print(json.dumps(result, indent=2))
    print("=" * 60)

if __name__ == "__main__":
    main()
