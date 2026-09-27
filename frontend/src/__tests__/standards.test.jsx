import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

import StandardsBadge from '../components/standards/StandardsBadge';
import StandardsProvenance from '../components/standards/StandardsProvenance';
import StandardsSpectrum from '../components/standards/StandardsSpectrum';
import CapabilityComparison from '../components/standards/CapabilityComparison';
import StatusAssessment from '../components/standards/StatusAssessment';
import StandardsContextSection from '../components/standards/StandardsContextSection';
import SessionDetails from '../components/SessionDetails';

describe('Standards Context & Configuration Comparison Frontend Tests', () => {
  const sampleTlsResult = {
    field: 'tls_version',
    label: 'TLS Protocol Version',
    observed: 'TLS 1.2',
    status: 'ACCEPTABLE',
    preferred: ['TLS 1.3'],
    visualization: 'ordered_spectrum',
    profile: 'ietf-modern-tls',
    profile_name: 'IETF Modern TLS (RFC 9325)',
    rationale: 'TLS 1.2 is an acceptable baseline when combined with secure AEAD cipher suites and PFS, but TLS 1.3 is preferred.',
    options: [
      { value: 'TLS 1.0', label: 'TLS 1.0', status: 'DEPRECATED', description: 'Formally deprecated by RFC 8996.' },
      { value: 'TLS 1.1', label: 'TLS 1.1', status: 'DEPRECATED', description: 'Formally deprecated by RFC 8996.' },
      { value: 'TLS 1.2', label: 'TLS 1.2', status: 'ACCEPTABLE', description: 'Acceptable baseline under RFC 9325.' },
      { value: 'TLS 1.3', label: 'TLS 1.3', status: 'PREFERRED', description: 'Preferred modern TLS protocol.' },
    ],
    sources: [
      {
        name: 'RFC 9325',
        title: 'Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)',
        section: 'Section 2.1 (Protocol Versions)',
        url: 'https://datatracker.ietf.org/doc/html/rfc9325#section-2.1',
        effective_status: 'CURRENT',
      },
    ],
    metadata: {
      last_reviewed: '2026-01-15',
    },
  };

  const samplePfsResult = {
    field: 'pfs',
    label: 'Forward Secrecy (PFS)',
    observed: 'Ephemeral PFS (PFS Active)',
    status: 'PREFERRED',
    preferred: ['Ephemeral PFS (ECDHE / DHE)'],
    visualization: 'capability_comparison',
    profile: 'ietf-modern-tls',
    profile_name: 'IETF Modern TLS (RFC 9325)',
    rationale: 'Session negotiated ephemeral key exchange (PFS: YES), safeguarding past sessions.',
    options: [
      {
        value: 'NON_PFS',
        label: 'Static / Non-PFS Key Transport',
        status: 'NOT_RECOMMENDED',
        description: 'Compromise of long-term server key compromises all past recorded traffic.',
      },
      {
        value: 'PFS_ACTIVE',
        label: 'Ephemeral PFS (ECDHE / DHE)',
        status: 'PREFERRED',
        description: 'Compromise of server private key cannot decrypt past recorded sessions.',
      },
    ],
    sources: [
      {
        name: 'RFC 9325',
        title: 'Recommendations for Secure Use of Transport Layer Security',
        section: 'Section 4.1',
        url: 'https://datatracker.ietf.org/doc/html/rfc9325#section-4.1',
        effective_status: 'CURRENT',
      },
    ],
  };

  const sampleUnobservableCertResult = {
    field: 'certificate_validity',
    label: 'Certificate Validity & Observability',
    observed: 'Not Observable (TLS 1.3 Encrypted Handshake)',
    status: 'NOT_OBSERVABLE',
    preferred: ['Valid X.509 Certificate'],
    visualization: 'status_assessment',
    profile: 'nist-tls',
    profile_name: 'NIST TLS Guidance (SP 800-52 Rev. 2)',
    rationale: 'Handshake encrypted in flight (TLS 1.3 privacy property). Missing passive evidence is not a defect.',
    options: [],
    sources: [
      {
        name: 'RFC 8446',
        title: 'The Transport Layer Security (TLS) Protocol Version 1.3',
        section: 'Section 1 (Handshake Encryption)',
        url: 'https://datatracker.ietf.org/doc/html/rfc8446',
        effective_status: 'CURRENT',
      },
    ],
  };

  describe('StandardsBadge', () => {
    it('renders PREFERRED status correctly', () => {
      render(<StandardsBadge status="PREFERRED" />);
      expect(screen.getByText('Preferred')).toBeInTheDocument();
    });

    it('renders DEPRECATED status correctly', () => {
      render(<StandardsBadge status="DEPRECATED" />);
      expect(screen.getByText('Deprecated')).toBeInTheDocument();
    });

    it('renders NOT_OBSERVABLE status with privacy framing', () => {
      render(<StandardsBadge status="NOT_OBSERVABLE" />);
      expect(screen.getByText('Not Observable')).toBeInTheDocument();
    });
  });

  describe('StandardsSpectrum (Type A & B)', () => {
    it('renders TLS version spectrum with OBSERVED marker on TLS 1.2 and PREFERRED on TLS 1.3', () => {
      render(<StandardsSpectrum result={sampleTlsResult} />);

      expect(screen.getByText('TLS Protocol Version')).toBeInTheDocument();
      expect(screen.getByText(/Preferred:/i)).toBeInTheDocument();

      // Check all 4 version options are displayed
      expect(screen.getByText('TLS 1.0')).toBeInTheDocument();
      expect(screen.getByText('TLS 1.1')).toBeInTheDocument();
      expect(screen.getAllByText('TLS 1.2').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('TLS 1.3').length).toBeGreaterThanOrEqual(1);

      // Rationale note
      expect(screen.getByText(/TLS 1.2 is an acceptable baseline/i)).toBeInTheDocument();
    });

    it('expands source provenance when clicked', () => {
      render(<StandardsSpectrum result={sampleTlsResult} />);

      const provBtn = screen.getByRole('button', { name: /authoritative guidance/i });
      fireEvent.click(provBtn);

      expect(screen.getAllByText(/RFC 9325/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Section 2.1/i)).toBeInTheDocument();
      expect(screen.getByText(/View Standard/i)).toBeInTheDocument();
    });
  });

  describe('CapabilityComparison (Type C)', () => {
    it('renders binary forward secrecy options and marks observed capability', () => {
      render(<CapabilityComparison result={samplePfsResult} />);

      expect(screen.getByText('Forward Secrecy (PFS)')).toBeInTheDocument();
      expect(screen.getAllByText(/Ephemeral PFS/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('Static / Non-PFS Key Transport')).toBeInTheDocument();
      expect(screen.getByText('Observed in Session')).toBeInTheDocument();
    });
  });

  describe('StatusAssessment (Type D)', () => {
    it('renders NOT_OBSERVABLE for TLS 1.3 with passive epistemology disclaimer', () => {
      render(<StatusAssessment result={sampleUnobservableCertResult} />);

      expect(screen.getByText('Certificate Validity & Observability')).toBeInTheDocument();
      expect(screen.getByText(/PASSIVE EPISTEMOLOGY/i)).toBeInTheDocument();
      expect(screen.getByText(/In TLS 1.3, the certificate payload is encrypted in-flight/i)).toBeInTheDocument();
      expect(screen.queryByText(/vulnerability/i)).not.toBeInTheDocument();
    });
  });

  describe('StandardsContextSection Integration', () => {
    it('renders multiple comparisons and filters them by tabs', () => {
      const items = [sampleTlsResult, samplePfsResult, sampleUnobservableCertResult];
      render(<StandardsContextSection standardsContext={items} />);

      expect(screen.getByText(/Standards Context & Configuration Comparison/i)).toBeInTheDocument();
      expect(screen.getByText('3 PROPERTIES')).toBeInTheDocument();

      // Filter to TLS
      const tlsTab = screen.getByRole('button', { name: /IETF Modern TLS/i });
      fireEvent.click(tlsTab);

      expect(screen.getByText('TLS Protocol Version')).toBeInTheDocument();
      expect(screen.getByText('Forward Secrecy (PFS)')).toBeInTheDocument();
    });
  });

  describe('SessionDetails with Standards Context', () => {
    it('integrates Standards Context seamlessly in session modal', () => {
      const mockSession = {
        session_id: 'sess-001',
        protocol: 'SMTP',
        service: 'submission',
        client_ip: '192.168.1.10',
        server_ip: '192.168.1.25',
        client_port: 54321,
        server_port: 587,
        tcp_stream: 1,
        packet_count: 42,
        security: {
          encryption_mode: 'STARTTLS',
          upgrade_advertised: 'YES',
          upgrade_requested: 'YES',
          upgrade_succeeded: 'YES',
          authentication_before_tls: 'NO',
          capture_completeness: 'COMPLETE',
        },
        tls: {
          version: 'TLS 1.2',
          cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          pfs: 'YES',
        },
        certificate: {
          subject: 'CN=mail.test.local',
          issuer: 'CN=Test CA',
          valid_from: '2025-01-01',
          valid_until: '2027-01-01',
          key_type: 'RSA',
          key_size: 2048,
          self_signed: false,
        },
        standards_context: [sampleTlsResult, samplePfsResult],
      };

      render(<SessionDetails session={mockSession} onClose={vi.fn()} />);

      expect(screen.getByText(/Standards Context & Configuration Comparison/i)).toBeInTheDocument();
      expect(screen.getByText('TLS Protocol Version')).toBeInTheDocument();
      expect(screen.getByText('Observed')).toBeInTheDocument();
    });
  });
});
