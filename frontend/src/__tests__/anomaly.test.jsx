import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
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
});
