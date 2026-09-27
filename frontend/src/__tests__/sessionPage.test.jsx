import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';

import SessionPage from '../pages/SessionPage';
import mockAnalysis from '../mock/mockAnalysis.json';
import { analysisApi } from '../api/analysisApi';

describe('SessionPage Tests', () => {
  const targetSession = mockAnalysis.sessions[0]; // smtp-001

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders session hero card, endpoints, wireshark filter, and protocol handshake', () => {
    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: `/analysis/${mockAnalysis.analysis_id}/session/${targetSession.session_id}`,
            state: {
              session: targetSession,
              analysis: mockAnalysis,
              analysisId: mockAnalysis.analysis_id,
              findings: mockAnalysis.findings,
            },
          },
        ]}
      >
        <Routes>
          <Route path="/analysis/:id/session/:sessionId" element={<SessionPage />} />
        </Routes>
      </MemoryRouter>
    );

    // Verify Session ID and protocol info
    expect(screen.getAllByText(targetSession.session_id).length).toBeGreaterThan(0);
    expect(screen.getByText('Session Security Inspection & Protocol Forensics')).toBeInTheDocument();

    // Verify Wireshark Filter section
    expect(screen.getByText(/Wireshark Display Filter:/i)).toBeInTheDocument();
    expect(screen.getByText(/Download Stream PCAP/i)).toBeInTheDocument();

    // Verify Connection Endpoints
    expect(screen.getByText('Connection Endpoints')).toBeInTheDocument();
    expect(screen.getByText('Client · Source')).toBeInTheDocument();
    expect(screen.getByText('Server · Destination')).toBeInTheDocument();

    // Verify Protocol Handshake
    expect(screen.getByText('Protocol Handshake')).toBeInTheDocument();
    expect(screen.getByText('Upgrade Advertised')).toBeInTheDocument();
    expect(screen.getByText('Upgrade Requested')).toBeInTheDocument();
  });

  it('copies Wireshark filter to clipboard when clicking copy button', async () => {
    const writeTextMock = vi.fn().mockResolvedValue();
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });

    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: `/analysis/${mockAnalysis.analysis_id}/session/${targetSession.session_id}`,
            state: {
              session: targetSession,
              analysis: mockAnalysis,
              analysisId: mockAnalysis.analysis_id,
              findings: mockAnalysis.findings,
            },
          },
        ]}
      >
        <Routes>
          <Route path="/analysis/:id/session/:sessionId" element={<SessionPage />} />
        </Routes>
      </MemoryRouter>
    );

    const copyBtn = screen.getByRole('button', { name: /copy filter/i });
    await waitFor(() => {
      fireEvent.click(copyBtn);
    });

    expect(writeTextMock).toHaveBeenCalled();
  });

  it('triggers PCAP download via analysisApi when clicking download stream pcap', async () => {
    const downloadSpy = vi.spyOn(analysisApi, 'downloadSessionPcap').mockResolvedValue(
      new Blob(['dummy pcap'], { type: 'application/vnd.tcpdump.pcap' })
    );

    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: `/analysis/${mockAnalysis.analysis_id}/session/${targetSession.session_id}`,
            state: {
              session: targetSession,
              analysis: mockAnalysis,
              analysisId: mockAnalysis.analysis_id,
              findings: mockAnalysis.findings,
            },
          },
        ]}
      >
        <Routes>
          <Route path="/analysis/:id/session/:sessionId" element={<SessionPage />} />
        </Routes>
      </MemoryRouter>
    );

    const downloadBtn = screen.getByRole('button', { name: /download stream pcap/i });
    fireEvent.click(downloadBtn);

    await waitFor(() => {
      expect(downloadSpy).toHaveBeenCalledWith(mockAnalysis.analysis_id, targetSession.session_id);
    });
  });

  it('renders not found state when session does not exist in analysis', async () => {
    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: `/analysis/${mockAnalysis.analysis_id}/session/non-existent-999`,
            state: {
              analysis: mockAnalysis,
              analysisId: mockAnalysis.analysis_id,
            },
          },
        ]}
      >
        <Routes>
          <Route path="/analysis/:id/session/:sessionId" element={<SessionPage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(screen.getByText('Session Not Found')).toBeInTheDocument();
    expect(screen.getByText(/Return to Session Table/i)).toBeInTheDocument();
  });

  it('renders three clearly separated sections with sticky jump navigation buttons', () => {
    const scrollToMock = vi.fn();
    window.scrollTo = scrollToMock;

    render(
      <MemoryRouter
        initialEntries={[
          {
            pathname: `/analysis/${mockAnalysis.analysis_id}/session/${targetSession.session_id}`,
            state: {
              session: targetSession,
              analysis: mockAnalysis,
              analysisId: mockAnalysis.analysis_id,
              findings: mockAnalysis.findings,
            },
          },
        ]}
      >
        <Routes>
          <Route path="/analysis/:id/session/:sessionId" element={<SessionPage />} />
        </Routes>
      </MemoryRouter>
    );

    // Verify Jump Navigation Bar
    const nav = screen.getByRole('navigation', { name: /session sections navigation/i });
    expect(nav).toBeInTheDocument();

    const forensicsBtn = screen.getByRole('button', { name: /^Session Forensics$/i });
    const standardsBtn = screen.getByRole('button', { name: /Standards Context & Comparison/i });
    const findingsBtn = screen.getByRole('button', { name: /Session Findings/i });

    expect(forensicsBtn).toBeInTheDocument();
    expect(standardsBtn).toBeInTheDocument();
    expect(findingsBtn).toBeInTheDocument();

    // Verify 3 distinct section headers
    expect(screen.getByText('Session Forensics & Network Telemetry')).toBeInTheDocument();
    expect(screen.getByText('Standards Context & Baseline Comparison')).toBeInTheDocument();
    expect(screen.getByText('Session Security Findings')).toBeInTheDocument();

    // Verify clicking jump buttons triggers window.scrollTo
    fireEvent.click(standardsBtn);
    expect(scrollToMock).toHaveBeenCalled();

    fireEvent.click(findingsBtn);
    expect(scrollToMock).toHaveBeenCalledTimes(2);

    fireEvent.click(forensicsBtn);
    expect(scrollToMock).toHaveBeenCalledTimes(3);
  });
});

