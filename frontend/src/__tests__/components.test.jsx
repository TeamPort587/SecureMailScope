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
import Navbar from '../components/Navbar';
import FindingsList from '../components/FindingsList';
import GroupedFindingCard from '../components/GroupedFindingCard';
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

    it('filters sessions by sessionFilter and renders dismissible banner', () => {
      const sample = [
        { ...mockAnalysis.sessions[0], session_id: 'session-match-1', tcp_stream: 1 },
        { ...mockAnalysis.sessions[0], session_id: 'session-other-2', tcp_stream: 2 },
      ];
      const clearMock = vi.fn();

      render(
        <BrowserRouter>
          <SessionTable
            sessions={sample}
            findings={[]}
            sessionFilter={{ title: 'Insecure Authentication', sessionIds: ['session-match-1'] }}
            onClearSessionFilter={clearMock}
          />
        </BrowserRouter>
      );

      expect(screen.getByText(/Filtered by:/i)).toBeInTheDocument();
      expect(screen.getByText(/Insecure Authentication/i)).toBeInTheDocument();
      expect(screen.getByText('session-match-1')).toBeInTheDocument();
      expect(screen.queryByText('session-other-2')).not.toBeInTheDocument();

      const clearBtn = screen.getByRole('button', { name: /clear filter/i });
      fireEvent.click(clearBtn);
      expect(clearMock).toHaveBeenCalled();
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

    it('triggers onSelectSession callback when session button is clicked', () => {
      const finding = mockAnalysis.findings[0];
      const handleSelect = vi.fn();
      render(<FindingCard finding={finding} onSelectSession={handleSelect} />);

      const sessionCard = screen.getByRole('button', { name: new RegExp(finding.session_id, 'i') });
      fireEvent.click(sessionCard);

      expect(handleSelect).toHaveBeenCalledWith(finding.session_id);
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

    it('supports expanding drawer and clicking Open in table to filter sessions', () => {
      const findings = Array.from({ length: 8 }, (_, i) => ({
        finding_id: `f-${i}`,
        finding_type: 'PLAINTEXT_TRANSMISSION',
        session_id: `smtp-plain-${i}`,
      }));
      const rec = {
        recommendation_id: 'REC-PLAIN-01',
        title: 'Enforce Plaintext Encryption',
        description: 'Plaintext communication observed',
        priority: 'CRITICAL',
      };
      const filterMock = vi.fn();

      render(
        <Recommendations
          recommendations={[rec]}
          findings={findings}
          sessions={[]}
          onFilterSessionsInTable={filterMock}
        />
      );

      // 4 sample chips should be rendered
      expect(screen.getByText('smtp-plain-0')).toBeInTheDocument();
      expect(screen.getByText('smtp-plain-3')).toBeInTheDocument();
      // +4 more button
      const moreBtn = screen.getByRole('button', { name: /\+4 more/i });
      expect(moreBtn).toBeInTheDocument();

      // Open in table button
      const openBtn = screen.getByRole('button', { name: /open in table/i });
      fireEvent.click(openBtn);
      expect(filterMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Enforce Plaintext Encryption',
          sessionIds: expect.arrayContaining(['smtp-plain-0', 'smtp-plain-7']),
        })
      );
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

  // --- Navbar & ThemeToggle ---
  describe('Navbar & ThemeToggle', () => {
    it('renders ThemeToggle in Navbar, does not render Demo button, and toggles dark mode', () => {
      render(
        <BrowserRouter>
          <Navbar onLoadPreset={vi.fn()} onResetAnalysis={vi.fn()} onLogout={vi.fn()} user={{ email: 'analyst@test.local' }} />
        </BrowserRouter>
      );

      // Verify Demo button is NOT present
      const demoBtn = screen.queryByRole('button', { name: /demo/i });
      expect(demoBtn).not.toBeInTheDocument();

      // Verify Theme toggle button is present
      const themeToggleBtn = screen.getByRole('button', { name: /switch to (dark|light) mode/i });
      expect(themeToggleBtn).toBeInTheDocument();

      // Click to toggle
      const initialIsDark = document.documentElement.classList.contains('dark');
      fireEvent.click(themeToggleBtn);
      expect(document.documentElement.classList.contains('dark')).toBe(!initialIsDark);

      // Toggle back
      fireEvent.click(themeToggleBtn);
      expect(document.documentElement.classList.contains('dark')).toBe(initialIsDark);
    });

    it('renders Home button to the left of Upload button in Navbar', () => {
      render(
        <BrowserRouter>
          <Navbar onLoadPreset={vi.fn()} onResetAnalysis={vi.fn()} onLogout={vi.fn()} user={{ email: 'analyst@test.local' }} />
        </BrowserRouter>
      );

      const homeLink = screen.getByRole('link', { name: /home/i });
      expect(homeLink).toBeInTheDocument();

      const uploadBtn = screen.getByRole('button', { name: /upload/i });
      expect(uploadBtn).toBeInTheDocument();

      // Verify Home comes before Upload in DOM order
      expect(homeLink.compareDocumentPosition(uploadBtn)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
    });

    it('renders Sign In link when user is unauthenticated', () => {
      render(
        <BrowserRouter>
          <Navbar onLoadPreset={vi.fn()} onResetAnalysis={vi.fn()} onLogout={vi.fn()} user={null} />
        </BrowserRouter>
      );

      const signInLink = screen.getByRole('link', { name: /sign in/i });
      expect(signInLink).toBeInTheDocument();
      expect(signInLink).toHaveAttribute('href', '/login');
    });
  });

  // --- FindingsList & GroupedFindingCard ---
  describe('FindingsList & GroupedFindingCard', () => {
    const sampleFindings = [
      {
        finding_id: 'f-1',
        session_id: 'session-001',
        finding_type: 'PLAINTEXT',
        title: 'Plaintext Transmission Detected',
        description: 'Session communicated without TLS encryption.',
        severity: 'CRITICAL',
        confidence: 'OBSERVED',
        evidence: { port: 25 },
      },
      {
        finding_id: 'f-2',
        session_id: 'session-002',
        finding_type: 'PLAINTEXT',
        title: 'Plaintext Transmission Detected',
        description: 'Session communicated without TLS encryption.',
        severity: 'CRITICAL',
        confidence: 'OBSERVED',
        evidence: { port: 25 },
      },
      {
        finding_id: 'f-3',
        session_id: 'session-003',
        finding_type: 'WEAK_CIPHER',
        title: 'Weak TLS Cipher Detected',
        description: 'Legacy 3DES cipher negotiated.',
        severity: 'MEDIUM',
        confidence: 'OBSERVED',
        evidence: { cipher: '3DES' },
      },
    ];

    it('renders deduplicated grouped findings with affected sessions count and raw occurrences badge', () => {
      render(<FindingsList findings={sampleFindings} totalSessions={3} />);

      // Should show issue count and raw occurrences badge
      expect(screen.getByText(/2 issues/i)).toBeInTheDocument();
      expect(screen.getByText(/raw occurrences across capture/i)).toBeInTheDocument();

      // Deduplicated: PLAINTEXT has 2 sessions, so it renders 1 card with "2 sessions affected"
      expect(screen.getAllByText(/2 sessions affected/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/Plaintext Transmission Detected/i)).toBeInTheDocument();
      expect(screen.getByText(/Weak TLS Cipher Detected/i)).toBeInTheDocument();
    });

    it('toggles session explorer and allows switching active session evidence', () => {
      const handleSelect = vi.fn();
      render(
        <FindingsList
          findings={sampleFindings}
          totalSessions={3}
          onSelectSession={handleSelect}
        />
      );

      // Click "Explore sessions" on the Plaintext card
      const exploreBtn = screen.getAllByRole('button', { name: /explore sessions/i })[0];
      fireEvent.click(exploreBtn);

      // Session chips should appear
      expect(screen.getByRole('button', { name: /session-001/i })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /session-002/i })).toBeInTheDocument();

      // Click "Inspect session"
      const inspectBtn = screen.getByRole('button', { name: /inspect session/i });
      fireEvent.click(inspectBtn);
      expect(handleSelect).toHaveBeenCalledWith('session-001');

      // Click session-002 chip
      const session2Chip = screen.getByRole('button', { name: /session-002/i });
      fireEvent.click(session2Chip);
      fireEvent.click(inspectBtn);
      expect(handleSelect).toHaveBeenCalledWith('session-002');
    });

    it('filters grouped findings by severity', () => {
      render(<FindingsList findings={sampleFindings} totalSessions={3} />);

      // Filter by Medium
      const mediumBtn = screen.getByRole('button', { name: /medium/i });
      fireEvent.click(mediumBtn);

      // Only the weak cipher finding should be shown
      expect(screen.getByText(/Weak TLS Cipher Detected/i)).toBeInTheDocument();
      expect(screen.queryByText(/Plaintext Transmission Detected/i)).not.toBeInTheDocument();

      // Clear filter
      const clearBtn = screen.getByRole('button', { name: /clear/i });
      fireEvent.click(clearBtn);
      expect(screen.getByText(/Plaintext Transmission Detected/i)).toBeInTheDocument();
    });

    it('renders pagination when vulnerability types exceed page size', () => {
      const manyTypesFindings = Array.from({ length: 25 }, (_, i) => ({
        finding_id: `finding-${i + 1}`,
        session_id: `session-${i + 1}`,
        finding_type: `VULN_RULE_${i + 1}`,
        title: `Vulnerability Type #${i + 1}`,
        description: `Description for vuln #${i + 1}`,
        severity: 'HIGH',
        confidence: 'OBSERVED',
        evidence: {},
      }));

      render(<FindingsList findings={manyTypesFindings} totalSessions={25} />);

      // Pagination footer should be visible: 25 items with PAGE_SIZE 15 = 2 pages
      const paginationInfo = screen.getByText(/Showing/i);
      expect(paginationInfo).toHaveTextContent(/Showing 1 to 15 of 25 vulnerability types/i);
      expect(screen.getByRole('button', { name: /next page/i })).toBeInTheDocument();

      // Click next page
      fireEvent.click(screen.getByRole('button', { name: /next page/i }));
      expect(screen.getByText(/Showing/i)).toHaveTextContent(/Showing 16 to 25 of 25 vulnerability types/i);
    });

    it('mini-paginates session chips inside card and triggers onViewSessionsTab', () => {
      const handleViewTab = vi.fn();
      // 20 sessions for a single PLAINTEXT vulnerability
      const twentySessionsFindings = Array.from({ length: 20 }, (_, i) => ({
        finding_id: `f-${i + 1}`,
        session_id: `stream-session-${i + 1}`,
        finding_type: 'PLAINTEXT',
        title: 'Plaintext Transmission Detected',
        description: 'Plaintext transmission',
        severity: 'CRITICAL',
        confidence: 'OBSERVED',
        evidence: { port: 25 },
      }));

      render(
        <FindingsList
          findings={twentySessionsFindings}
          totalSessions={20}
          onViewSessionsTab={handleViewTab}
        />
      );

      // Expand sessions drawer
      fireEvent.click(screen.getByRole('button', { name: /explore sessions/i }));

      // "Open in Sessions table" button should be visible (since > 5 sessions)
      const openTableBtn = screen.getByRole('button', { name: /open in sessions table/i });
      expect(openTableBtn).toBeInTheDocument();
      fireEvent.click(openTableBtn);
      expect(handleViewTab).toHaveBeenCalled();

      // Mini-pagination should be active: 20 sessions with CHIPS_PER_PAGE 12 -> "Showing 1–12 of 20"
      expect(screen.getByText(/Showing/i)).toHaveTextContent(/Showing 1–12 of 20/i);
      expect(screen.getByText('1 / 2')).toBeInTheDocument();

      // Click Next session chips page
      const nextChipsBtn = screen.getByRole('button', { name: /next sessions page/i });
      fireEvent.click(nextChipsBtn);
      expect(screen.getByText('2 / 2')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /stream-session-13/i })).toBeInTheDocument();
    });

    it('calls onFilterSessionsInTable when clicking open in sessions table', () => {
      const handleFilterInTable = vi.fn();
      const findings = Array.from({ length: 8 }, (_, i) => ({
        finding_id: `f-${i}`,
        finding_type: 'INSECURE_AUTH',
        title: 'Insecure Authentication',
        severity: 'CRITICAL',
        confidence: 'OBSERVED',
        session_id: `auth-session-${i}`,
      }));

      render(
        <FindingsList
          findings={findings}
          totalSessions={8}
          onFilterSessionsInTable={handleFilterInTable}
        />
      );

      fireEvent.click(screen.getByRole('button', { name: /explore sessions/i }));
      const openTableBtn = screen.getByRole('button', { name: /open in sessions table/i });
      fireEvent.click(openTableBtn);
      expect(handleFilterInTable).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Insecure Authentication',
          sessionIds: expect.arrayContaining(['auth-session-0', 'auth-session-7']),
        })
      );
    });
  });
});


