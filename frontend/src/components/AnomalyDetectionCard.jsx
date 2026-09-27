import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Info,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  ArrowRight,
  ShieldAlert,
  Sliders,
  ExternalLink,
} from 'lucide-react';

/**
 * AnomalyDetectionCard
 *
 * Renders the Isolation Forest anomaly assessment at both PCAP-level
 * and per-session level. Conforms strictly to SecureMailScope design
 * system tokens and contract formats.
 */
export default function AnomalyDetectionCard({
  anomalyAssessment,
  sessions = [],
  findings = [],
  onSelectSession,
}) {
  const [expandedSessionId, setExpandedSessionId] = useState(null);
  const [filterType, setFilterType] = useState('ALL'); // 'ALL' | 'ANOMALOUS' | 'BASELINE'

  if (!anomalyAssessment && (!sessions || sessions.length === 0)) {
    return null;
  }

  // Extract aggregate metrics with fallbacks
  const totalSessions = anomalyAssessment?.total_sessions ?? sessions.length;
  const anomalousCount =
    anomalyAssessment?.anomalous_count ??
    sessions.filter((s) => s?.anomaly?.is_anomalous).length;
  const baselineCount =
    anomalyAssessment?.within_baseline_count ??
    sessions.filter((s) => s?.anomaly?.is_anomalous === false).length;
  const overallStatus =
    anomalyAssessment?.overall_status ||
    (anomalousCount > 0 ? 'ANOMALIES_DETECTED' : 'ALL_WITHIN_BASELINE');

  // Filtered session list
  const sessionsWithAnomaly = sessions.filter((s) => {
    if (filterType === 'ANOMALOUS') return s?.anomaly?.is_anomalous === true;
    if (filterType === 'BASELINE') return s?.anomaly?.is_anomalous === false;
    return true;
  });

  const toggleExpand = (sessionId) => {
    setExpandedSessionId((prev) => (prev === sessionId ? null : sessionId));
  };

  return (
    <div
      id="anomaly-detection-card"
      className="rounded-2xl border border-slate-200/80 bg-white shadow-sm overflow-hidden transition-all duration-200"
    >
      {/* CARD HEADER */}
      <div className="border-b border-slate-100 bg-gradient-to-r from-slate-50 via-white to-indigo-50/20 px-6 py-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl shadow-sm ${
                anomalousCount > 0
                  ? 'bg-amber-500/10 text-amber-600 border border-amber-500/20'
                  : 'bg-emerald-500/10 text-emerald-600 border border-emerald-500/20'
              }`}
            >
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold text-slate-900 tracking-tight">
                  Behavioral Anomaly Detection
                </h3>
                <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-mono font-medium text-slate-600 border border-slate-200">
                  Isolation Forest · if-v1
                </span>
              </div>
              <p className="mt-0.5 text-xs text-slate-500">
                Unsupervised anomaly isolation detecting rare pattern outliers and traffic anomalies
              </p>
            </div>
          </div>

          {/* STATUS PILL */}
          <div className="flex items-center gap-2">
            {overallStatus === 'ANOMALIES_DETECTED' ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-800">
                <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse" />
                {anomalousCount} Outlier{anomalousCount === 1 ? '' : 's'} Isolated
              </span>
            ) : overallStatus === 'MODEL_UNAVAILABLE' ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-slate-600">
                <HelpCircle className="h-3.5 w-3.5" />
                Model Unavailable
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-800">
                <CheckCircle2 className="h-3.5 w-3.5" />
                All Within Baseline
              </span>
            )}
          </div>
        </div>
      </div>

      {/* METRICS STRIP */}
      <div className="grid grid-cols-2 divide-x divide-y sm:divide-y-0 divide-slate-100 sm:grid-cols-4 bg-slate-50/50 border-b border-slate-100">
        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Total Analyzed
          </p>
          <p className="mt-1 text-xl font-bold text-slate-900 font-mono">
            {totalSessions}
          </p>
          <span className="text-[10px] text-slate-400">Reconstructed TCP streams</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Anomalous
          </p>
          <p
            className={`mt-1 text-xl font-bold font-mono ${
              anomalousCount > 0 ? 'text-amber-600' : 'text-slate-700'
            }`}
          >
            {anomalousCount}
          </p>
          <span className="text-[10px] text-slate-400">Exceeds isolation threshold</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Within Baseline
          </p>
          <p className="mt-1 text-xl font-bold text-emerald-600 font-mono">
            {baselineCount}
          </p>
          <span className="text-[10px] text-slate-400">Normal distribution bounds</span>
        </div>

        <div className="p-4 sm:px-6">
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            Feature Dimension
          </p>
          <p className="mt-1 text-xl font-bold text-indigo-600 font-mono">
            30
          </p>
          <span className="text-[10px] text-slate-400">Features per session vector</span>
        </div>
      </div>

      {/* FILTER TABS & SESSIONS LIST */}
      <div className="p-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between mb-4">
          <h4 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
            <Layers className="h-4 w-4 text-slate-500" />
            Session Anomaly Breakdown
          </h4>

          {/* FILTER BUTTONS */}
          <div className="flex items-center rounded-lg border border-slate-200 bg-slate-50 p-0.5 text-xs font-medium">
            <button
              type="button"
              onClick={() => setFilterType('ALL')}
              className={`rounded-md px-2.5 py-1 transition-colors ${
                filterType === 'ALL'
                  ? 'bg-white text-slate-900 shadow-sm font-semibold'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All ({sessions.length})
            </button>
            <button
              type="button"
              onClick={() => setFilterType('ANOMALOUS')}
              className={`rounded-md px-2.5 py-1 transition-colors ${
                filterType === 'ANOMALOUS'
                  ? 'bg-white text-amber-700 shadow-sm font-semibold'
                  : 'text-slate-600 hover:text-amber-700'
              }`}
            >
              Anomalous ({anomalousCount})
            </button>
            <button
              type="button"
              onClick={() => setFilterType('BASELINE')}
              className={`rounded-md px-2.5 py-1 transition-colors ${
                filterType === 'BASELINE'
                  ? 'bg-white text-emerald-700 shadow-sm font-semibold'
                  : 'text-slate-600 hover:text-emerald-700'
              }`}
            >
              Baseline ({baselineCount})
            </button>
          </div>
        </div>

        {/* SESSIONS ACCORDION LIST */}
        <div className="space-y-3">
          {sessionsWithAnomaly.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-200 bg-slate-50/50 p-8 text-center">
              <CheckCircle2 className="mx-auto h-8 w-8 text-slate-400" />
              <p className="mt-2 text-sm font-medium text-slate-700">
                No sessions match filter
              </p>
              <p className="text-xs text-slate-400">
                Try switching the filter to view all sessions.
              </p>
            </div>
          ) : (
            sessionsWithAnomaly.map((session) => {
              const anomaly = session?.anomaly;
              const isAnom = anomaly?.is_anomalous === true;
              const isExpanded = expandedSessionId === session.session_id;

              return (
                <div
                  key={session.session_id}
                  className={`rounded-xl border transition-all duration-150 ${
                    isAnom
                      ? 'border-amber-200/90 bg-amber-50/20 hover:border-amber-300'
                      : 'border-slate-200 bg-white hover:border-slate-300'
                  }`}
                >
                  {/* SESSION SUMMARY BAR */}
                  <div
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-4 cursor-pointer select-none gap-3"
                    onClick={() => toggleExpand(session.session_id)}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-xs font-bold font-mono ${
                          isAnom
                            ? 'bg-amber-100 text-amber-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}
                      >
                        {session.protocol || 'TCP'}
                      </div>

                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs font-bold text-slate-900">
                            {session.session_id}
                          </span>
                          <span className="text-[11px] text-slate-400">
                            {session.client_ip}:{session.client_port} → {session.server_ip}:
                            {session.server_port}
                          </span>
                        </div>
                        <p className="text-xs text-slate-500 truncate mt-0.5">
                          {anomaly?.explanation?.summary ||
                            (isAnom
                              ? 'Statistically isolated from expected baseline patterns.'
                              : 'Conforms to baseline traffic distribution.')}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0 self-end sm:self-center">
                      {isAnom ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-[11px] font-semibold text-amber-800 border border-amber-200">
                          <AlertTriangle className="h-3 w-3" />
                          ANOMALOUS
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="h-3 w-3" />
                          BASELINE
                        </span>
                      )}

                      {typeof anomaly?.decision_score === 'number' && (
                        <span className="hidden sm:inline-flex text-[11px] font-mono text-slate-500 bg-slate-100 rounded px-1.5 py-0.5" title="Decision Score">
                          score: {anomaly.decision_score.toFixed(3)}
                        </span>
                      )}

                      <button
                        type="button"
                        className="text-slate-400 hover:text-slate-600 p-1"
                        aria-label="Toggle details"
                      >
                        {isExpanded ? (
                          <ChevronUp className="h-4 w-4" />
                        ) : (
                          <ChevronDown className="h-4 w-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* EXPANDED DETAILS */}
                  {isExpanded && (
                    <div className="border-t border-slate-100 bg-white/70 p-4 sm:p-5 rounded-b-xl space-y-4">
                      {/* EXPLANATION NARRATIVE */}
                      <div>
                        <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                          <Info className="h-3.5 w-3.5" />
                          Explanation & Rationale
                        </h5>
                        <p className="mt-1 text-xs leading-relaxed text-slate-700 bg-slate-50 p-3 rounded-lg border border-slate-200/60">
                          {anomaly?.explanation?.summary ||
                            'No detailed narrative provided for this session.'}
                        </p>
                      </div>

                      {/* STATISTICAL DEVIATIONS */}
                      {Array.isArray(anomaly?.explanation?.deviations) &&
                        anomaly.explanation.deviations.length > 0 && (
                          <div>
                            <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5 mb-2">
                              <Sliders className="h-3.5 w-3.5" />
                              Key Deviations from Baseline
                            </h5>
                            <div className="grid gap-2 sm:grid-cols-2">
                              {anomaly.explanation.deviations.map((dev, idx) => (
                                <div
                                  key={idx}
                                  className="rounded-lg border border-slate-200 bg-white p-2.5 text-xs shadow-2xs"
                                >
                                  <div className="flex items-center justify-between font-mono text-[11px]">
                                    <span className="font-semibold text-slate-800">
                                      {dev.feature || dev.name || 'feature'}
                                    </span>
                                    <span className="text-amber-700 font-bold">
                                      obs: {typeof dev.observed === 'number' ? dev.observed.toFixed(2) : String(dev.observed)}
                                    </span>
                                  </div>
                                  {dev.baseline_mean !== undefined && (
                                    <div className="text-[10px] text-slate-400 mt-0.5">
                                      baseline mean: {typeof dev.baseline_mean === 'number' ? dev.baseline_mean.toFixed(2) : dev.baseline_mean}
                                    </div>
                                  )}
                                  {dev.description && (
                                    <p className="mt-1 text-[11px] text-slate-600">
                                      {dev.description}
                                    </p>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                      {/* CROSS-REFERENCED DETERMINISTIC FINDINGS */}
                      {Array.isArray(anomaly?.explanation?.related_findings) &&
                        anomaly.explanation.related_findings.length > 0 && (
                          <div>
                            <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5 mb-1.5">
                              <ShieldAlert className="h-3.5 w-3.5" />
                              Related Rule Engine Findings
                            </h5>
                            <div className="flex flex-wrap gap-1.5">
                              {anomaly.explanation.related_findings.map((fid) => (
                                <span
                                  key={fid}
                                  className="inline-flex items-center rounded-md bg-rose-50 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-700 border border-rose-200"
                                >
                                  {fid}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                      {/* ACTION: INSPECT SESSION IN DETAILS DRAWER */}
                      {onSelectSession && (
                        <div className="flex justify-end pt-2 border-t border-slate-100">
                          <button
                            type="button"
                            onClick={() => onSelectSession(session)}
                            className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 hover:text-indigo-800 transition-colors"
                          >
                            Inspect full session telemetry
                            <ExternalLink className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* FOOTER NOTICE / CAVEAT */}
      <div className="bg-slate-50/70 border-t border-slate-100 px-6 py-3 flex items-start sm:items-center gap-2 text-[11px] text-slate-500">
        <Info className="h-3.5 w-3.5 shrink-0 text-slate-400 mt-0.5 sm:mt-0" />
        <span>
          <strong>Methodology Note:</strong> Isolation Forest measures anomalous behavior independently from the supervised Random Forest risk engine. High anomaly scores highlight statistical outliers and may detect novel threats or operational defects.
        </span>
      </div>
    </div>
  );
}
