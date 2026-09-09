import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';

import UploadForm from '../components/UploadForm';
import RiskSummary from '../components/RiskSummary';
import RiskBadge from '../components/RiskBadge';
import SessionTable from '../components/SessionTable';
import FindingCard from '../components/FindingCard';
import EvidencePanel from '../components/EvidencePanel';
import Recommendations from '../components/Recommendations';
import HistoryTable from '../components/HistoryTable';

import mockAnalysis from '../mock/mockAnalysis.json';

describe('Frontend Component Unit & Integration Tests', () => {
  // --- UploadForm ---
  describe('UploadForm', () => {
    it('renders upload prompt', () => {
      render(<UploadForm onUpload={vi.fn()} />);
      expect(screen.getByText(/click to upload/i)).toBeInTheDocument();
      expect(screen.getByText('.pcap')).toBeInTheDocument();
    });

    it('rejects invalid file extension', () => {
      render(<UploadForm onUpload={vi.fn()} />);
      const input = document.querySelector('input[type="file"]');
      const badFile = new File(['dummy'], 'malware.exe', { type: 'application/octet-stream' });

      fireEvent.change(input, { target: { files: [badFile] } });
      expect(screen.getByText(/invalid file extension/i)).toBeInTheDocument();
    });

    it('accepts valid .pcap file and calls onUpload upon submit', () => {
      const onUpload = vi.fn();
      render(<UploadForm onUpload={onUpload} />);
      const input = document.querySelector('input[type="file"]');
      const goodFile = new File(['valid pcap header content'], 'test_traffic.pcap', {
        type: 'application/vnd.tcpdump.pcap',
      });

      fireEvent.change(input, { target: { files: [goodFile] } });
      expect(screen.getByText('test_traffic.pcap')).toBeInTheDocument();

      const submitBtn = screen.getByRole('button', { name: /launch analysis/i });
      fireEvent.click(submitBtn);
      expect(onUpload).toHaveBeenCalledWith(goodFile);
    });
  });

  // --- RiskBadge ---
  describe('RiskBadge', () => {
    it('renders CRITICAL risk level with text and accessible role', () => {
      render(<RiskBadge level="CRITICAL" />);
      const badge = screen.getByRole('status');
      expect(badge).toHaveTextContent('CRITICAL');
      expect(badge).toHaveAttribute('aria-label', 'Risk level: CRITICAL');
    });

    it('renders LOW risk level with text', () => {
      render(<RiskBadge level="LOW" />);
      expect(screen.getByRole('status')).toHaveTextContent('LOW');
    });
  });

  // --- RiskSummary ---
  describe('RiskSummary', () => {
    it('renders risk score, level, model version and summary counts', () => {
      render(
        <RiskSummary
          risk={mockAnalysis.risk}
          summary={mockAnalysis.summary}
          filename={mockAnalysis.filename}
          uploadedAt={mockAnalysis.uploaded_at}
        />
      );

      expect(screen.getByText(/Overall Security Posture:/i)).toBeInTheDocument();
      expect(screen.getByText('78')).toBeInTheDocument(); // Score
      expect(screen.getByText('rf-v1')).toBeInTheDocument(); // Model
      expect(screen.getByText('91%')).toBeInTheDocument(); // Confidence
      expect(screen.getByText('4')).toBeInTheDocument(); // Total sessions
      expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1); // Vulnerable sessions / counts
    });

    it('does not crash when optional fields are null', () => {
      render(<RiskSummary risk={null} summary={null} />);
      expect(screen.getByText(/Overall Security Posture:/i)).toBeInTheDocument();
    });
  });

  // --- SessionTable & SessionDetails ---
  describe('SessionTable', () => {
    it('displays multiple sessions with protocols and ports', () => {
      render(<SessionTable sessions={mockAnalysis.sessions} findings={mockAnalysis.findings} />);
      expect(screen.getByText('smtp-001')).toBeInTheDocument();
      expect(screen.getByText('smtp-002')).toBeInTheDocument();
      expect(screen.getByText('imap-001')).toBeInTheDocument();
      expect(screen.getByText('pop3-001')).toBeInTheDocument();
    });

    it('opens session inspection modal with tri-state values when clicking inspect', () => {
      render(<SessionTable sessions={mockAnalysis.sessions} findings={mockAnalysis.findings} />);
      const inspectButtons = screen.getAllByRole('button', { name: /inspect/i });
      fireEvent.click(inspectButtons[0]);

      // Verify Session details modal opens
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Protocol Handshake & Upgrade Controls')).toBeInTheDocument();
      expect(screen.getByText('Upgrade Advertised')).toBeInTheDocument();
    });
  });

  // --- FindingCard & EvidencePanel ---
  describe('FindingCard & EvidencePanel', () => {
    it('renders finding severity, type, title, and confidence', () => {
      const finding = mockAnalysis.findings[0];
      render(<FindingCard finding={finding} />);

      expect(screen.getByText(finding.title)).toBeInTheDocument();
      expect(screen.getByText(finding.description)).toBeInTheDocument();
      expect(screen.getByText(`Type: ${finding.finding_type}`)).toBeInTheDocument();
      expect(screen.getByText(`Session: ${finding.session_id}`)).toBeInTheDocument();
    });

    it('toggles evidence panel visibility', () => {
      const finding = mockAnalysis.findings[0];
      render(<FindingCard finding={finding} />);

      const evidenceBtn = screen.getByRole('button', { name: /evidence/i });
      fireEvent.click(evidenceBtn);

      expect(screen.getByText(/packet dissector evidence/i)).toBeInTheDocument();
      expect(screen.getByText(/authentication before tls/i)).toBeInTheDocument();
    });
  });

  // --- Recommendations ---
  describe('Recommendations', () => {
    it('renders recommendations with priority badges and text', () => {
      render(<Recommendations recommendations={mockAnalysis.recommendations} />);
      expect(screen.getByText(mockAnalysis.recommendations[0].title)).toBeInTheDocument();
      expect(screen.getByText(mockAnalysis.recommendations[0].description)).toBeInTheDocument();
    });

    it('renders empty state when no recommendations exist', () => {
      render(<Recommendations recommendations={[]} />);
      expect(screen.getByText(/no immediate remediation needed/i)).toBeInTheDocument();
    });
  });

  // --- HistoryTable ---
  describe('HistoryTable', () => {
    it('renders history items with links to analysis', () => {
      const items = [
        {
          analysis_id: 'a1b2c3d4-5678-90ab-cdef-1234567890ab',
          filename: 'test_traffic.pcap',
          created_at: '2026-09-09T10:30:00Z',
          status: 'completed',
          risk_label: 'HIGH',
          session_count: 4,
          finding_count: 5,
        },
      ];

      render(
        <BrowserRouter>
          <HistoryTable items={items} loading={false} />
        </BrowserRouter>
      );

      expect(screen.getByText('test_traffic.pcap')).toBeInTheDocument();
      expect(screen.getByText('completed')).toBeInTheDocument();
    });
  });
});
