import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import AnomalyDetectionCard from '../components/AnomalyDetectionCard';

describe('AnomalyDetectionCard Component', () => {
  const sampleAssessment = {
    overall_status: 'ANOMALIES_DETECTED',
    total_sessions: 2,
    anomalous_count: 1,
    within_baseline_count: 1,
    insufficient_evidence_count: 0,
    unavailable_count: 0,
    error_count: 0,
    anomalous_session_ids: ['session-002'],
  };

  const sampleSessions = [
    {
      session_id: 'session-001',
      protocol: 'SMTP',
      client_ip: '10.0.0.1',
      client_port: 50000,
      server_ip: '10.0.0.2',
      server_port: 587,
      anomaly: {
        status: 'COMPLETE',
        classification: 'WITHIN_BASELINE',
        is_anomalous: false,
        raw_score: 0.15,
        decision_score: -0.15,
        explanation: {
          summary: 'Normal baseline activity.',
          deviations: [],
        },
      },
    },
    {
      session_id: 'session-002',
      protocol: 'SMTP',
      client_ip: '10.0.0.3',
      client_port: 50001,
      server_ip: '10.0.0.2',
      server_port: 587,
      anomaly: {
        status: 'COMPLETE',
        classification: 'ANOMALOUS',
        is_anomalous: true,
        raw_score: -0.25,
        decision_score: 0.25,
        explanation: {
          summary: 'High behavioral anomaly detected.',
          deviations: [
            {
              feature: 'if_auth_before_tls',
              observed: 1.0,
              baseline_mean: 0.01,
              description: 'Authentication observed prior to TLS negotiation.',
            },
          ],
          related_findings: ['finding-001'],
        },
      },
    },
  ];

  it('renders anomaly card with status and counts', () => {
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
      />
    );

    expect(screen.getByText('Behavioral Anomaly Detection')).toBeDefined();
    expect(screen.getByText(/1 Outlier.*Isolated/i)).toBeDefined();
    expect(screen.getByText('session-001')).toBeDefined();
    expect(screen.getByText('session-002')).toBeDefined();
  });

  it('filters sessions by anomalous and baseline tabs', () => {
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
      />
    );

    // Filter to Anomalous
    const anomFilterBtn = screen.getByRole('button', { name: /Anomalous/i });
    fireEvent.click(anomFilterBtn);
    expect(screen.getByText('session-002')).toBeDefined();
    expect(screen.queryByText('session-001')).toBeNull();

    // Filter to Baseline
    const baselineFilterBtn = screen.getByRole('button', { name: /Baseline/i });
    fireEvent.click(baselineFilterBtn);
    expect(screen.getByText('session-001')).toBeDefined();
    expect(screen.queryByText('session-002')).toBeNull();
  });

  it('expands session details when clicked', () => {
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
      />
    );

    const sessionRow = screen.getByText('session-002');
    fireEvent.click(sessionRow);

    expect(screen.getAllByText('High behavioral anomaly detected.').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Authentication observed prior to TLS negotiation.')).toBeDefined();
  });

  it('renders summary-only view without session breakdown table and triggers onViewAllAnomalies', () => {
    const handleViewAll = vi.fn();
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
        summaryOnly={true}
        onViewAllAnomalies={handleViewAll}
      />
    );

    expect(screen.getByText('Behavioral Anomaly Detection')).toBeDefined();
    // Breakdown table should NOT be rendered in summaryOnly mode
    expect(screen.queryByText('Session Anomaly Breakdown')).toBeNull();
    expect(screen.queryByText('session-001')).toBeNull();

    // Check that outlier badge is removed in summaryOnly mode
    expect(screen.queryByText(/Outlier.*Isolated/i)).toBeNull();

    // Check that methodology note and isolated info note are removed
    expect(screen.queryByText(/Methodology Note/i)).toBeNull();
    expect(screen.queryByText(/isolated from expected baseline patterns/i)).toBeNull();

    // Check that "view all anomalies" button is removed, and "view breakdown" button is present
    expect(screen.queryByRole('button', { name: /view all anomalies/i })).toBeNull();
    const viewBreakdownBtn = screen.getByRole('button', { name: /view breakdown/i });
    expect(viewBreakdownBtn).toBeDefined();
    fireEvent.click(viewBreakdownBtn);
    expect(handleViewAll).toHaveBeenCalledTimes(1);
  });

  it('paginates sessions at 15 items per page and navigates between pages', () => {
    // Generate 20 sessions
    const twentySessions = Array.from({ length: 20 }, (_, i) => ({
      session_id: `anom-sess-${String(i + 1).padStart(3, '0')}`,
      protocol: 'SMTP',
      client_ip: '10.0.0.1',
      client_port: 50000 + i,
      server_ip: '10.0.0.2',
      server_port: 587,
      anomaly: {
        is_anomalous: i % 2 === 0,
        decision_score: -0.1 + i * 0.02,
        explanation: { summary: `Summary for session ${i + 1}` },
      },
    }));

    render(
      <AnomalyDetectionCard
        anomalyAssessment={{ ...sampleAssessment, total_sessions: 20 }}
        sessions={twentySessions}
      />
    );

    // Initial page shows 1 to 15
    expect(screen.getByText('anom-sess-001')).toBeDefined();
    expect(screen.getByText('anom-sess-015')).toBeDefined();
    expect(screen.queryByText('anom-sess-016')).toBeNull();

    // Check pagination footer
    expect(screen.getByText(/Showing/i)).toBeDefined();
    expect(screen.getAllByText('20').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/of/i)).toBeDefined();

    // Click Next button
    const nextBtn = screen.getByRole('button', { name: /Next page/i });
    fireEvent.click(nextBtn);

    // Page 2 shows 16 to 20
    expect(screen.getByText('anom-sess-016')).toBeDefined();
    expect(screen.getByText('anom-sess-020')).toBeDefined();
    expect(screen.queryByText('anom-sess-001')).toBeNull();

    // Click Prev button
    const prevBtn = screen.getByRole('button', { name: /Previous page/i });
    fireEvent.click(prevBtn);
    expect(screen.getByText('anom-sess-001')).toBeDefined();
  });

  it('searches and filters sessions by text query', async () => {
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
      />
    );

    const searchInput = screen.getByRole('textbox', { name: /Search anomalies/i });
    act(() => {
      fireEvent.change(searchInput, { target: { value: 'session-002' } });
    });

    // Wait for debounce and filter update
    await vi.waitFor(() => {
      expect(screen.getByText('session-002')).toBeDefined();
      expect(screen.queryByText('session-001')).toBeNull();
    });
  });

  it('sorts sessions by score order and toggles order', () => {
    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
      />
    );

    // Default is decision_score ASC: session-001 has -0.15, session-002 has 0.25
    let items = screen.getAllByText(/session-001|session-002/);
    expect(items[0].textContent).toContain('session-001');
    expect(items[1].textContent).toContain('session-002');

    // Toggle to DESC by clicking Anomaly Score table header
    const scoreHeader = screen.getByText('Anomaly Score');
    fireEvent.click(scoreHeader);

    items = screen.getAllByText(/session-001|session-002/);
    expect(items[0].textContent).toContain('session-002');
    expect(items[1].textContent).toContain('session-001');
  });

  it('calls analysisApi.getSessions when analysisId is provided', async () => {
    const { analysisApi } = await import('../api/analysisApi');
    const spy = vi.spyOn(analysisApi, 'getSessions').mockResolvedValueOnce({
      items: [
        {
          session_id: 'server-anom-001',
          protocol: 'SMTP',
          client_ip: '192.168.1.10',
          client_port: 45000,
          server_ip: '192.168.1.1',
          server_port: 587,
          anomaly: {
            is_anomalous: true,
            decision_score: -0.42,
            explanation: { summary: 'Server-side anomalous session.' },
          },
        },
      ],
      pagination: {
        page: 1,
        limit: 15,
        total: 1,
        totalPages: 1,
      },
    });

    render(
      <AnomalyDetectionCard
        anomalyAssessment={sampleAssessment}
        sessions={sampleSessions}
        analysisId="test-analysis-123"
      />
    );

    await vi.waitFor(() => {
      expect(spy).toHaveBeenCalledWith(
        'test-analysis-123',
        expect.objectContaining({
          page: 1,
          limit: 15,
          anomaly: 'ALL',
          sortBy: 'decision_score',
          sortOrder: 'ASC',
        })
      );
      expect(screen.getByText('server-anom-001')).toBeDefined();
    });

    spy.mockRestore();
  });
});

