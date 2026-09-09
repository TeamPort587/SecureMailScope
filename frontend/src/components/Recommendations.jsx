import React from 'react';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import { Lightbulb, CheckCircle2 } from 'lucide-react';

export default function Recommendations({
  recommendations = [],
}) {
  if (!recommendations || recommendations.length === 0) {
    return (
      <section className="w-full">
        <SectionHeader />

        <div className="mt-4">
          <EmptyState
            title="No Immediate Remediation Needed"
            message="The analyzed email traffic conforms to the expected cryptographic and transport security requirements."
            icon="secure"
          />
        </div>
      </section>
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
    </div>
  );
}

/* ---------------------------------------------------------
   Recommendation Card
--------------------------------------------------------- */

function RecommendationCard({ recommendation }) {
  const priority = (
    recommendation?.priority || 'INFO'
  ).toUpperCase();

  const styles = {
    CRITICAL: {
      accent: 'bg-red-500',
      tint: 'from-red-50/35 via-white to-white',

      actionBg: 'bg-red-50/55',
      actionBorder: 'border-red-200',
      actionIcon: 'border-red-200 bg-white text-red-600',
      actionLabel: 'text-red-700',
    },

    HIGH: {
      accent: 'bg-orange-500',
      tint: 'from-orange-50/30 via-white to-white',

      actionBg: 'bg-orange-50/50',
      actionBorder: 'border-orange-200',
      actionIcon: 'border-orange-200 bg-white text-orange-600',
      actionLabel: 'text-orange-700',
    },

    MEDIUM: {
      accent: 'bg-amber-500',
      tint: 'from-amber-50/25 via-white to-white',

      actionBg: 'bg-amber-50/45',
      actionBorder: 'border-amber-200',
      actionIcon: 'border-amber-200 bg-white text-amber-600',
      actionLabel: 'text-amber-700',
    },

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