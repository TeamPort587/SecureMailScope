import React from 'react';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import { Lightbulb, CheckCircle2, ArrowRight } from 'lucide-react';
import { getSeverityConfig } from '../utils/severity';

export default function Recommendations({ recommendations = [] }) {
  if (!recommendations || recommendations.length === 0) {
    return (
      <div className="w-full space-y-3">
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-emerald-400" />
          <span>Remediation & Hardening Recommendations</span>
        </h3>
        <EmptyState
          title="No Immediate Remediation Needed"
          message="The analyzed email traffic conforms to standard cryptographic and transport requirements."
          icon="secure"
        />
      </div>
    );
  }

  return (
    <div className="w-full space-y-4">
      <div>
        <h3 className="text-base font-bold text-white flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-emerald-400" />
          <span>Remediation & Hardening Recommendations</span>
          <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700">
            {recommendations.length}
          </span>
        </h3>
        <p className="text-xs text-slate-400">
          Actionable configuration guidance derived directly from observed protocol weaknesses.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {recommendations.map((rec) => {
          const config = getSeverityConfig(rec.priority);
          return (
            <div
              key={rec.recommendation_id}
              className={`rounded-xl border p-4.5 bg-slate-900/70 ${config.border} flex flex-col justify-between gap-3 shadow-sm`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <RiskBadge level={rec.priority} size="sm" />
                  <span className="text-[11px] font-mono text-slate-500">
                    {rec.recommendation_id}
                  </span>
                </div>

                <h4 className="text-sm font-bold text-slate-100">
                  {rec.title}
                </h4>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {rec.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <CheckCircle2 className="w-3.5 h-3.5 text-brand-400" />
                  <span>MTA / Client Policy Hardening</span>
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
