import React, { useState, useMemo } from 'react';
import FindingCard from './FindingCard';
import EmptyState from './EmptyState';
import { Bug, Filter, ShieldCheck } from 'lucide-react';
import { compareSeverity } from '../utils/severity';

export default function FindingsList({ findings = [] }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');

  // Sort findings descending by severity rank
  const sortedFindings = useMemo(() => {
    return [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
  }, [findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    if (severityFilter === 'ALL') return sortedFindings;
    return sortedFindings.filter((f) => (f.severity || '').toUpperCase() === severityFilter);
  }, [sortedFindings, severityFilter]);

  // Severity counts
  const counts = useMemo(() => {
    const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((f) => {
      const s = (f.severity || 'INFO').toUpperCase();
      if (c[s] !== undefined) c[s]++;
    });
    return c;
  }, [findings]);

  return (
    <div className="w-full space-y-4">
      {/* Header & Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Bug className="w-4 h-4 text-amber-400" />
            <span>Security Findings & Heuristics</span>
            <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700">
              {filteredFindings.length} of {findings.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400">
            Authoritative detections emitted by the rule engine and protocol dissectors.
          </p>
        </div>

        {/* Severity Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
              severityFilter === 'ALL'
                ? 'bg-slate-800 text-white border border-slate-700'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
            }`}
          >
            All ({findings.length})
          </button>
          {counts.CRITICAL > 0 && (
            <button
              onClick={() => setSeverityFilter('CRITICAL')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors font-mono ${
                severityFilter === 'CRITICAL'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                  : 'text-red-400 hover:bg-red-500/10'
              }`}
            >
              CRITICAL ({counts.CRITICAL})
            </button>
          )}
          {counts.HIGH > 0 && (
            <button
              onClick={() => setSeverityFilter('HIGH')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors font-mono ${
                severityFilter === 'HIGH'
                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                  : 'text-orange-400 hover:bg-orange-500/10'
              }`}
            >
              HIGH ({counts.HIGH})
            </button>
          )}
          {counts.MEDIUM > 0 && (
            <button
              onClick={() => setSeverityFilter('MEDIUM')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors font-mono ${
                severityFilter === 'MEDIUM'
                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                  : 'text-amber-400 hover:bg-amber-500/10'
              }`}
            >
              MEDIUM ({counts.MEDIUM})
            </button>
          )}
          {counts.INFO > 0 && (
            <button
              onClick={() => setSeverityFilter('INFO')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors font-mono ${
                severityFilter === 'INFO'
                  ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                  : 'text-blue-400 hover:bg-blue-500/10'
              }`}
            >
              INFO ({counts.INFO})
            </button>
          )}
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length > 0 ? (
        <div className="space-y-3">
          {filteredFindings.map((finding) => (
            <FindingCard key={finding.finding_id} finding={finding} />
          ))}
        </div>
      ) : findings.length === 0 ? (
        <EmptyState
          title="No Security Findings Detected"
          message="No protocol violations, cleartext credentials, or downgrade attacks were identified in this capture."
          icon="secure"
        />
      ) : (
        <EmptyState
          title="No Findings for Selected Severity"
          message={`No findings match the filter '${severityFilter}'.`}
        />
      )}
    </div>
  );
}
