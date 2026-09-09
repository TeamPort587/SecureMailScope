import baseMock from './mockAnalysis.json';

export const DEMO_PRESETS = [
  {
    id: 'demo-vulnerable',
    name: 'Demo 2: Vulnerable Capture (High Risk)',
    badge: 'HIGH RISK',
    badgeClass: 'bg-red-500/20 text-red-400 border-red-500/30',
    description: 'Contains plain-text IMAP and SMTP authentication occurring before STARTTLS.',
    data: baseMock,
  },
  {
    id: 'demo-secure',
    name: 'Demo 1: Clean & Modern TLS (Low Risk)',
    badge: 'LOW RISK',
    badgeClass: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    description: 'Fully negotiated TLS 1.3 session with Forward Secrecy and valid certificates.',
    data: {
      analysis_id: "sec-7788-99aa-bbcc-445566778899",
      status: "completed",
      filename: "secure_mail_gateway_traffic.pcap",
      uploaded_at: "2026-09-09T12:00:00Z",
      summary: {
        total_sessions: 2,
        smtp_sessions: 1,
        imap_sessions: 0,
        pop3_sessions: 1,
        plaintext_sessions: 0,
        starttls_sessions: 1,
        implicit_tls_sessions: 1,
        vulnerable_sessions: 0,
        findings_count: 2
      },
      sessions: [
        {
          session_id: "sec-smtp-001",
          protocol: "SMTP",
          service: "submission",
          client_ip: "192.168.1.100",
          server_ip: "198.51.100.10",
          client_port: 52140,
          server_port: 587,
          security: {
            encryption_mode: "STARTTLS",
            upgrade_advertised: "YES",
            upgrade_requested: "YES",
            upgrade_succeeded: "YES",
            authentication_before_tls: "NO",
            capture_completeness: "COMPLETE"
          },
          tls: {
            version: "TLS 1.3",
            cipher_suite: "TLS_AES_256_GCM_SHA384",
            pfs: "YES"
          },
          certificate: {
            subject: "CN=mail.corp-secure.org",
            issuer: "DigiCert Global Root G2",
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: "2027-01-01T00:00:00Z",
            key_type: "EC",
            key_size: 256,
            self_signed: false
          }
        },
        {
          session_id: "sec-pop3-001",
          protocol: "POP3",
          service: "mail-access",
          client_ip: "192.168.1.105",
          server_ip: "198.51.100.10",
          client_port: 52145,
          server_port: 995,
          security: {
            encryption_mode: "IMPLICIT_TLS",
            upgrade_advertised: "UNKNOWN",
            upgrade_requested: "UNKNOWN",
            upgrade_succeeded: "YES",
            authentication_before_tls: "NO",
            capture_completeness: "COMPLETE"
          },
          tls: {
            version: "TLS 1.3",
            cipher_suite: "TLS_CHACHA20_POLY1305_SHA256",
            pfs: "YES"
          },
          certificate: {
            subject: "CN=mail.corp-secure.org",
            issuer: "DigiCert Global Root G2",
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: "2027-01-01T00:00:00Z",
            key_type: "EC",
            key_size: 256,
            self_signed: false
          }
        }
      ],
      findings: [
        {
          finding_id: "finding-sec-001",
          session_id: "sec-smtp-001",
          finding_type: "PFS",
          severity: "INFO",
          title: "Modern TLS 1.3 negotiated with Forward Secrecy",
          description: "Connection used standard modern TLS 1.3 protocol without legacy fallback.",
          confidence: "OBSERVED",
          evidence: {
            tls_version: "TLS 1.3",
            cipher_suite: "TLS_AES_256_GCM_SHA384",
            pfs: "YES"
          }
        },
        {
          finding_id: "finding-sec-002",
          session_id: "sec-pop3-001",
          finding_type: "PFS",
          severity: "INFO",
          title: "Implicit TLS handshake succeeded",
          description: "Implicit TLS wrapper established on port 995 prior to application layer exchange.",
          confidence: "OBSERVED",
          evidence: {
            tls_version: "TLS 1.3",
            cipher_suite: "TLS_CHACHA20_POLY1305_SHA256",
            pfs: "YES"
          }
        }
      ],
      risk: {
        score: 12,
        level: "LOW",
        model_version: "rf-v1",
        method: "RULE_ENGINE_PLUS_ML",
        confidence: 0.98
      },
      recommendations: [
        {
          recommendation_id: "rec-sec-001",
          priority: "INFO",
          title: "Maintain current TLS configuration",
          description: "The existing mail infrastructure adheres to recommended cryptographic standards."
        }
      ]
    }
  },
  {
    id: 'demo-multisession',
    name: 'Demo 3: Multi-Session Mixed Protocols',
    badge: 'CRITICAL',
    badgeClass: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
    description: 'Enterprise capture with 6 concurrent email sessions across SMTP, IMAP & POP3.',
    data: {
      analysis_id: "multi-9900-aabb-ccdd-112233445566",
      status: "completed",
      filename: "enterprise_perimeter_full.pcapng",
      uploaded_at: "2026-09-09T14:15:00Z",
      summary: {
        total_sessions: 6,
        smtp_sessions: 3,
        imap_sessions: 2,
        pop3_sessions: 1,
        plaintext_sessions: 2,
        starttls_sessions: 3,
        implicit_tls_sessions: 1,
        vulnerable_sessions: 3,
        findings_count: 6
      },
      sessions: [
        ...baseMock.sessions,
        {
          session_id: "smtp-003",
          protocol: "SMTP",
          service: "relay",
          client_ip: "10.0.2.55",
          server_ip: "203.0.113.80",
          client_port: 58490,
          server_port: 25,
          security: {
            encryption_mode: "STARTTLS",
            upgrade_advertised: "YES",
            upgrade_requested: "YES",
            upgrade_succeeded: "YES",
            authentication_before_tls: "NO",
            capture_completeness: "COMPLETE"
          },
          tls: {
            version: "TLS 1.2",
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            pfs: "YES"
          },
          certificate: {
            subject: "CN=relay.partner-corp.com",
            issuer: "Sectigo RSA Domain Validation Secure Server CA",
            valid_from: "2025-06-01T00:00:00Z",
            valid_until: "2026-06-01T00:00:00Z",
            key_type: "RSA",
            key_size: 2048,
            self_signed: false
          }
        },
        {
          session_id: "imap-002",
          protocol: "IMAP",
          service: "mail-access",
          client_ip: "10.0.3.12",
          server_ip: "203.0.113.30",
          client_port: 48900,
          server_port: 993,
          security: {
            encryption_mode: "IMPLICIT_TLS",
            upgrade_advertised: "UNKNOWN",
            upgrade_requested: "UNKNOWN",
            upgrade_succeeded: "YES",
            authentication_before_tls: "NO",
            capture_completeness: "PARTIAL"
          },
          tls: {
            version: "TLS 1.2",
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            pfs: "YES"
          },
          certificate: {
            visibility: "NOT_OBSERVABLE"
          }
        }
      ],
      findings: [
        ...baseMock.findings,
        {
          finding_id: "finding-006",
          session_id: "smtp-003",
          finding_type: "WEAK_CIPHER",
          severity: "MEDIUM",
          title: "CBC mode cipher suite observed",
          description: "TLS negotiated CBC-mode cipher which may be vulnerable to padding oracle attacks.",
          confidence: "OBSERVED",
          evidence: {
            cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            protocol: "SMTP",
            server_port: 25
          }
        }
      ],
      risk: {
        score: 84,
        level: "CRITICAL",
        model_version: "rf-v1",
        method: "RULE_ENGINE_PLUS_ML",
        confidence: 0.94
      },
      recommendations: [
        ...baseMock.recommendations,
        {
          recommendation_id: "rec-003",
          priority: "MEDIUM",
          title: "Deprecate CBC cipher suites",
          description: "Configure mail MTA to prioritize AEAD cipher suites (GCM or CHACHA20-POLY1305)."
        }
      ]
    }
  }
];
