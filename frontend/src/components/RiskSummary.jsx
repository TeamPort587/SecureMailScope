import React, { useMemo } from 'react';
import RiskBadge from './RiskBadge';
import { Shield, AlertTriangle, Layers, Bug, Lock, Unlock, Zap, Cpu } from 'lucide-react';
import { getSeverityConfig } from '../utils/severity';

export default function RiskSummary({ risk, summary, filename, uploadedAt, sessions = [] }) {
  const hasCollectiveRisk = Boolean(risk && risk.level);
  const riskConfig = getSeverityConfig(risk?.level);
  const score = typeof risk?.score === 'number' ? Math.round(risk.score) : 0;
  const confidence = typeof risk?.confidence === 'number' ? (risk.confidence * 100).toFixed(0) + '%' : '—';

  // Per-session risk breakdown
  const sessionRiskCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    (sessions || []).forEach((s) => {
      const lvl = (s.risk_label || '').toUpperCase();
      if (counts[lvl] !== undefined) {
        counts[lvl]++;
      }
    });
    return counts;
  }, [sessions]);

  return (
    <div className="w-full space-y-4">
      {/* Top Banner */}
      {hasCollectiveRisk ? (
        <div className={`relative overflow-hidden rounded-2xl border p-6 ${riskConfig.bg} ${riskConfig.border} backdrop-blur-sm`}>
          <div className={`absolute -right-10 -bottom-10 w-48 h-48 rounded-full blur-3xl opacity-20 ${riskConfig.indicator}`} />

          <div className="relative flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <RiskBadge level={risk?.level} size="lg" />
                <span className="text-xs font-mono uppercase text-slate-400">
                  {risk?.method || 'HEURISTIC + ML MODEL'}
                </span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
                Overall Security Posture: <span className={riskConfig.text}>{risk?.level || 'UNKNOWN'}</span>
              </h2>
              <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
                {risk?.level === 'CRITICAL' && 'Immediate exposure detected. Plaintext authentication or unencrypted sensitive mail streams were captured.'}
                {risk?.level === 'HIGH' && 'High-risk protocol failures observed. STARTTLS downgrade or missing transport encryption.'}
                {risk?.level === 'MEDIUM' && 'Moderate security gaps identified. Legacy cipher suites or incomplete encryption negotiation.'}
                {risk?.level === 'LOW' && 'Robust cryptographic protection observed with modern TLS negotiation and forward secrecy.'}
                {risk?.level === 'INFO' && 'All analyzed sessions meet standard security requirements.'}
              </p>

              <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono pt-1">
                <span className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-slate-400" />
                  Model: <strong className="text-slate-200">{risk?.model_version || 'rf-v1'}</strong>
                </span>
                <span>•</span>
                <span>Confidence: <strong className="text-slate-200">{confidence}</strong></span>
                {filename && (
                  <>
                    <span>•</span>
                    <span>Capture: <strong className="text-slate-200">{filename}</strong></span>
                  </>
                )}
              </div>
            </div>

            {/* Risk Score Circle Gauge */}
            <div className="flex items-center gap-4 bg-slate-950/70 p-4 rounded-xl border border-slate-800 shrink-0 self-start md:self-auto">
              <div className="relative w-20 h-20 flex items-center justify-center">
                <svg className="w-20 h-20 -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-slate-800"
                    strokeWidth="3.5"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                  <path
                    className={riskConfig.text}
                    strokeDasharray={`${score}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                    stroke="currentColor"
                    fill="none"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                  />
                </svg>
                <div className="absolute flex flex-col items-center justify-center text-center">
                  <span className="text-xl font-bold font-mono text-white leading-none">{score}</span>
                  <span className="text-[9px] uppercase font-mono text-slate-400">/ 100</span>
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-200">Risk Score</p>
                <p className="text-[11px] text-slate-400 mt-0.5">Scored from 0 (Safe) to 100 (Compromised)</p>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/80 p-6 backdrop-blur-sm">
          <div className="relative flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-brand-500/10 text-brand-400 border border-brand-500/20">
                  PER-SESSION EVALUATION
                </span>
                {filename && (
                  <span className="text-xs font-mono text-slate-400">
                    Capture: <strong className="text-slate-200">{filename}</strong>
                  </span>
                )}
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
                Individual Session Risk Posture
              </h2>
              <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
                PCAP traffic is evaluated per connection stream. Each reconstructed email session receives an independent cryptographic risk classification based on passive TLS inspection.
              </p>
            </div>

            {/* Session Risk Tier Breakdown Chips */}
            <div className="flex flex-wrap items-center gap-2.5 bg-slate-950/70 p-4 rounded-xl border border-slate-800 shrink-0">
              <div className="flex flex-col items-center px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 min-w-[70px]">
                <span className="text-xs font-mono font-bold text-red-400">{sessionRiskCounts.CRITICAL}</span>
                <span className="text-[10px] uppercase font-mono text-red-300">Critical</span>
              </div>
              <div className="flex flex-col items-center px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 min-w-[70px]">
                <span className="text-xs font-mono font-bold text-amber-400">{sessionRiskCounts.HIGH}</span>
                <span className="text-[10px] uppercase font-mono text-amber-300">High</span>
              </div>
              <div className="flex flex-col items-center px-3 py-1.5 rounded-lg bg-yellow-500/10 border border-yellow-500/20 min-w-[70px]">
                <span className="text-xs font-mono font-bold text-yellow-400">{sessionRiskCounts.MEDIUM}</span>
                <span className="text-[10px] uppercase font-mono text-yellow-300">Medium</span>
              </div>
              <div className="flex flex-col items-center px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 min-w-[70px]">
                <span className="text-xs font-mono font-bold text-emerald-400">{sessionRiskCounts.LOW}</span>
                <span className="text-[10px] uppercase font-mono text-emerald-300">Low</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Total Sessions */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400 shrink-0">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Total Sessions</p>
            <p className="text-xl font-bold font-mono text-slate-100">{summary?.total_sessions ?? 0}</p>
          </div>
        </div>

        {/* Vulnerable Sessions */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400 shrink-0">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Vulnerable</p>
            <p className="text-xl font-bold font-mono text-red-400">{summary?.vulnerable_sessions ?? 0}</p>
          </div>
        </div>

        {/* Findings Count */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
            <Bug className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Findings</p>
            <p className="text-xl font-bold font-mono text-amber-400">{summary?.findings_count ?? 0}</p>
          </div>
        </div>

        {/* Plaintext / Unencrypted Sessions */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 shrink-0">
            <Unlock className="w-5 h-5" />
          </div>
          <div>
            <p className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">Plaintext Sessions</p>
            <p className="text-xl font-bold font-mono text-rose-400">{summary?.plaintext_sessions ?? 0}</p>
          </div>
        </div>
      </div>

      {/* Protocol & Encryption Breakdown Pill Bar */}
      <div className="p-3.5 rounded-xl bg-slate-900/40 border border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 font-medium">Protocols:</span>
          {typeof summary?.smtp_sessions === 'number' && (
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
              SMTP: <strong>{summary.smtp_sessions}</strong>
            </span>
          )}
          {typeof summary?.imap_sessions === 'number' && (
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
              IMAP: <strong>{summary.imap_sessions}</strong>
            </span>
          )}
          {typeof summary?.pop3_sessions === 'number' && (
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px]">
              POP3: <strong>{summary.pop3_sessions}</strong>
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-slate-400 font-medium">Transport Encryption:</span>
          {typeof summary?.starttls_sessions === 'number' && (
            <span className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 font-mono text-[11px] border border-sky-500/20">
              STARTTLS: <strong>{summary.starttls_sessions}</strong>
            </span>
          )}
          {typeof summary?.implicit_tls_sessions === 'number' && (
            <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 font-mono text-[11px] border border-emerald-500/20">
              Implicit TLS: <strong>{summary.implicit_tls_sessions}</strong>
            </span>
          )}
          {typeof summary?.plaintext_sessions === 'number' && summary.plaintext_sessions > 0 && (
            <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 font-mono text-[11px] border border-rose-500/20">
              Plaintext: <strong>{summary.plaintext_sessions}</strong>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
