import React, { useState } from 'react';
import RiskBadge from './RiskBadge';
import EvidencePanel from './EvidencePanel';
import { ChevronDown, ChevronUp, Terminal, ShieldAlert } from 'lucide-react';
import { getSeverityConfig } from '../utils/severity';

export default function FindingCard({ finding }) {
  const [showEvidence, setShowEvidence] = useState(false);
  const config = getSeverityConfig(finding.severity);

  return (
    <div className={`rounded-xl border p-4 transition-all bg-slate-900/60 ${config.border} hover:bg-slate-900/80`}>
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        {/* Finding Header */}
        <div className="space-y-1.5 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge level={finding.severity} size="sm" />
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              Type: {finding.finding_type}
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-brand-500/10 text-brand-300 border border-brand-500/20">
              Session: {finding.session_id}
            </span>
            <span className="text-[11px] font-mono text-slate-400">
              Confidence: <strong className="text-slate-200">{finding.confidence || 'OBSERVED'}</strong>
            </span>
          </div>

          <h4 className="text-sm font-bold text-white tracking-tight">
            {finding.title}
          </h4>

          <p className="text-xs text-slate-300 leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* Evidence Toggle Button */}
        {finding.evidence && (
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors shrink-0 ${
              showEvidence
                ? 'bg-brand-500/20 text-brand-300 border-brand-500/40'
                : 'bg-slate-800/80 hover:bg-slate-800 text-slate-300 border-slate-700'
            }`}
            aria-expanded={showEvidence}
          >
            <Terminal className="w-3.5 h-3.5 text-brand-400" />
            <span>Evidence</span>
            {showEvidence ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {/* Expandable Evidence Drawer */}
      {showEvidence && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 animate-in fade-in duration-150">
          <EvidencePanel evidence={finding.evidence} />
        </div>
      )}
    </div>
  );
}
