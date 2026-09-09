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
    <div className="w-full space-y-5">
      <div>
        <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
          <span>Remediation & Hardening Recommendations</span>
          <span className="text-xs font-mono text-slate-600 dark:text-slate-400 px-2.5 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700">
            {recommendations.length}
          </span>
        </h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Actionable configuration guidance derived directly from observed protocol weaknesses.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {recommendations.map((rec) => {
          const config = getSeverityConfig(rec.priority);
          return (
            <div
              key={rec.recommendation_id}
              className={`rounded-2xl border p-5 sm:p-6 bg-white dark:bg-slate-900/80 border-slate-200 dark:border-slate-800 ${config.border} flex flex-col justify-between gap-4 shadow-sm hover:shadow-md transition-all`}
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <RiskBadge level={rec.priority} size="sm" />
                  <span className="text-[11px] font-mono text-slate-400 dark:text-slate-500 truncate max-w-[200px]" title={rec.recommendation_id}>
                    {rec.recommendation_id}
                  </span>
                </div>

                <h4 className="text-sm sm:text-base font-bold text-slate-900 dark:text-slate-100 leading-snug">
                  {rec.title}
                </h4>

                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                  {rec.description}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
                <span className="flex items-center gap-1.5 font-medium">
                  <CheckCircle2 className="w-4 h-4 text-brand-600 dark:text-brand-400 shrink-0" />
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
