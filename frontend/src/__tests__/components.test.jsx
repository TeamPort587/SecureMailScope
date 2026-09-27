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
import CopilotChat from '../components/CopilotChat';
import { copilotApi } from '../api/copilotApi';

import mockAnalysis from '../mock/mockAnalysis.json';

describe('Frontend Component Unit & Integration Tests', () => {
  // --- UploadForm ---
  describe('UploadForm', () => {
    it('renders upload prompt', () => {
      render(<UploadForm onUpload={vi.fn()} />);
      expect(screen.getByText(/choose a pcap file/i)).toBeInTheDocument();
      expect(screen.getByText('PCAP')).toBeInTheDocument();
    });

    it('rejects invalid file extension', () => {
      render(<UploadForm onUpload={vi.fn()} />);
      const input = document.querySelector('input[type="file"]');
      const badFile = new File(['dummy'], 'malware.exe', { type: 'application/octet-stream' });

      fireEvent.change(input, { target: { files: [badFile] } });
      expect(screen.getByText(/please select a valid \.pcap or \.pcapng/i)).toBeInTheDocument();
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

      expect(screen.getByText('High-risk security posture')).toBeInTheDocument();
      expect(screen.getByText('78')).toBeInTheDocument(); // Score
      expect(screen.getByText('rf-v1')).toBeInTheDocument(); // Model
      expect(screen.getByText('91%')).toBeInTheDocument(); // Confidence
      expect(screen.getAllByText('4').length).toBeGreaterThanOrEqual(1); // Total sessions
      expect(screen.getAllByText('2').length).toBeGreaterThanOrEqual(1); // Vulnerable sessions / counts
    });

    it('does not crash when optional fields are null', () => {
      render(<RiskSummary risk={null} summary={null} />);
      expect(screen.getByText('Security posture looks healthy')).toBeInTheDocument();
    });
  });

  // --- SessionTable & SessionDetails ---
  describe('SessionTable', () => {
    it('displays multiple sessions with protocols and ports', () => {
      render(
        <BrowserRouter>
          <SessionTable sessions={mockAnalysis.sessions} findings={mockAnalysis.findings} />
        </BrowserRouter>
      );
      expect(screen.getByText('smtp-001')).toBeInTheDocument();
      expect(screen.getByText('smtp-002')).toBeInTheDocument();
      expect(screen.getByText('imap-001')).toBeInTheDocument();
      expect(screen.getByText('pop3-001')).toBeInTheDocument();
    });

    it('opens session inspection modal with tri-state values when clicking inspect without analysisId', () => {
      render(
        <BrowserRouter>
          <SessionTable sessions={mockAnalysis.sessions} findings={mockAnalysis.findings} />
        </BrowserRouter>
      );
      const inspectButtons = screen.getAllByRole('button', { name: /inspect/i });
      fireEvent.click(inspectButtons[0]);

      // Verify Session details modal opens
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Protocol Handshake')).toBeInTheDocument();
      expect(screen.getByText('Upgrade Advertised')).toBeInTheDocument();
    });

    it('invokes onSelectSession callback when inspecting with custom handler', () => {
      const handleSelect = vi.fn();
      render(
        <BrowserRouter>
          <SessionTable
            sessions={mockAnalysis.sessions}
            findings={mockAnalysis.findings}
            onSelectSession={handleSelect}
          />
        </BrowserRouter>
      );
      const inspectButtons = screen.getAllByRole('button', { name: /inspect/i });
      fireEvent.click(inspectButtons[0]);
      expect(handleSelect).toHaveBeenCalledWith(mockAnalysis.sessions[0]);
    });

    it('paginates sessions at 15 items per page and allows navigation', () => {
      // Create 20 mock sessions
      const manySessions = Array.from({ length: 20 }, (_, idx) => ({
        ...mockAnalysis.sessions[0],
        session_id: `session-${String(idx + 1).padStart(3, '0')}`,
        tcp_stream: idx,
      }));

      render(
        <BrowserRouter>
          <SessionTable sessions={manySessions} findings={[]} />
        </BrowserRouter>
      );

      // Verify page 1 shows 15 items: session-001 to session-015
      expect(screen.getByText('session-001')).toBeInTheDocument();
      expect(screen.getByText('session-015')).toBeInTheDocument();
      expect(screen.queryByText('session-016')).not.toBeInTheDocument();

      // Check pagination footer
      expect(screen.getByText(/Showing/i)).toBeInTheDocument();
      expect(screen.getByText('20')).toBeInTheDocument();

      // Click Next page button
      const nextBtn = screen.getByRole('button', { name: /next page/i });
      fireEvent.click(nextBtn);

      // Verify page 2 shows session-016 to session-020
      expect(screen.getByText('session-016')).toBeInTheDocument();
      expect(screen.getByText('session-020')).toBeInTheDocument();
      expect(screen.queryByText('session-001')).not.toBeInTheDocument();
    });

    it('allows sorting sessions by clicking column header with 3-state cycle (ASC -> DESC -> Reset)', () => {
      const sample = [
        { ...mockAnalysis.sessions[0], session_id: 'zebra-001', tcp_stream: 1 },
        { ...mockAnalysis.sessions[0], session_id: 'alpha-001', tcp_stream: 2 },
      ];

      render(
        <BrowserRouter>
          <SessionTable sessions={sample} findings={[]} />
        </BrowserRouter>
      );

      // Initial natural order (tcp_stream 1 before 2)
      let cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('zebra-001');
      expect(cells[1]).toHaveTextContent('alpha-001');

      const sessionHeader = screen.getByText('Session');

      // Click 1: Sort by session_id ASC
      fireEvent.click(sessionHeader);
      cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('alpha-001');
      expect(cells[1]).toHaveTextContent('zebra-001');

      // Click 2: Sort by session_id DESC
      fireEvent.click(sessionHeader);
      cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('zebra-001');
      expect(cells[1]).toHaveTextContent('alpha-001');

      // Click 3: Revert to natural order (tcp_stream)
      fireEvent.click(sessionHeader);
      cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('zebra-001');
      expect(cells[1]).toHaveTextContent('alpha-001');
    });

    it('allows resetting sort via the Reset button', () => {
      const sample = [
        { ...mockAnalysis.sessions[0], session_id: 'zebra-001', tcp_stream: 1 },
        { ...mockAnalysis.sessions[0], session_id: 'alpha-001', tcp_stream: 2 },
      ];

      render(
        <BrowserRouter>
          <SessionTable sessions={sample} findings={[]} />
        </BrowserRouter>
      );

      // Sort by Session (alpha-001 first)
      fireEvent.click(screen.getByText('Session'));
      let cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('alpha-001');
      expect(cells[1]).toHaveTextContent('zebra-001');

      // Click Reset button to clear sort back to natural stream order
      const resetBtn = screen.getByRole('button', { name: /reset all filters and sorting/i });
      fireEvent.click(resetBtn);

      cells = screen.getAllByText(/alpha-001|zebra-001/);
      expect(cells[0]).toHaveTextContent('zebra-001');
      expect(cells[1]).toHaveTextContent('alpha-001');
    });
  });

  // --- FindingCard & EvidencePanel ---
  describe('FindingCard & EvidencePanel', () => {
    it('renders finding severity, type, title, and confidence', () => {
      const finding = mockAnalysis.findings[0];
      render(<FindingCard finding={finding} />);

      expect(screen.getByText(finding.title)).toBeInTheDocument();
      expect(screen.getByText(finding.description)).toBeInTheDocument();
      expect(screen.getByText(finding.finding_type)).toBeInTheDocument();
      expect(screen.getByText(finding.session_id)).toBeInTheDocument();
    });

    it('toggles evidence panel visibility', () => {
      const finding = mockAnalysis.findings[0];
      render(<FindingCard finding={finding} />);

      const evidenceBtn = screen.getAllByRole('button', { name: /evidence/i })[0];
      fireEvent.click(evidenceBtn);

      expect(screen.getByText(/supporting evidence/i)).toBeInTheDocument();
      expect(screen.getByText(/server port/i)).toBeInTheDocument();
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

  // --- CopilotChat ---
  describe('CopilotChat', () => {
    it('renders header, initial welcome message, and suggested questions', async () => {
      vi.spyOn(copilotApi, 'getStatus').mockResolvedValue({
        status: 'online',
        model: 'mailscope-sec:3b',
        model_available: true,
      });

      vi.spyOn(copilotApi, 'getSuggestions').mockResolvedValue([
        'What are the risks of plaintext email authentication observed here?',
        'How can I enforce modern TLS (v1.3) and strong ciphers in my mail server?',
      ]);

      render(<CopilotChat analysis={mockAnalysis} />);

      expect(screen.getByText('Agent SMS')).toBeInTheDocument();
      expect(screen.getByText('OLLAMA')).toBeInTheDocument();
      expect(await screen.findByText(/What are the risks of plaintext/i)).toBeInTheDocument();
      expect(screen.getByText(/How can I enforce modern TLS/i)).toBeInTheDocument();
    });

    it('submits a question and displays assistant response with source metadata', async () => {
      vi.spyOn(copilotApi, 'getStatus').mockResolvedValue({
        status: 'online',
        model: 'mailscope-sec:3b',
        model_available: true,
      });

      vi.spyOn(copilotApi, 'getSuggestions').mockResolvedValue([]);
      vi.spyOn(copilotApi, 'chat').mockResolvedValue({
        response: 'Enforce STARTTLS and reject plaintext AUTH commands.',
        model: 'mailscope-sec:3b',
        source: 'ollama',
      });

      render(<CopilotChat analysis={mockAnalysis} />);

      expect(await screen.findByText(/Agent SMS/i)).toBeInTheDocument();

      const input = screen.getByPlaceholderText(/Ask about security findings/i);
      fireEvent.change(input, { target: { value: 'How to fix plaintext auth?' } });

      const sendButton = screen.getByTitle('Send message');
      fireEvent.click(sendButton);

      expect(screen.getByText('How to fix plaintext auth?')).toBeInTheDocument();
      expect(await screen.findByText(/Enforce STARTTLS and reject plaintext/i)).toBeInTheDocument();
      expect(screen.getAllByText(/source: ollama/i).length).toBeGreaterThanOrEqual(1);
    });
  });
});
