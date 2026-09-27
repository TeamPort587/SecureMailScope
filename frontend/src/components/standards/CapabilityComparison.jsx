import React from 'react';
import { ShieldCheck, ShieldAlert, Sparkles, Check, ArrowRight } from 'lucide-react';
import StandardsBadge from './StandardsBadge';
import StandardsProvenance from './StandardsProvenance';

export default function CapabilityComparison({ result }) {
  if (!result) return null;

  const {
    label,
    observed,
    status,
    preferred = [],
    options = [],
    rationale,
    profile,
    profile_name,
    sources = [],
    metadata = {},
  } = result;

  const normalizedObserved = String(observed || '').toLowerCase().trim();

  const isOptionObserved = (opt) => {
    const optVal = String(opt.value || '').toLowerCase().replace(/_/g, ' ').trim();
    const optLbl = String(opt.label || '').toLowerCase().replace(/_/g, ' ').trim();
    const obs = normalizedObserved.replace(/_/g, ' ');
    return (
      optVal === obs ||
      optLbl === obs ||
      obs.includes(optVal) ||
      obs.includes(optLbl) ||
      optVal.includes(obs)
    );
  };

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/90 p-4 shadow-sm transition-all">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100 dark:border-slate-800">
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
            {label}
          </h4>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="font-mono text-sm font-semibold text-slate-800 dark:text-slate-100">
              {observed || 'None'}
            </span>
            <span className="text-xs text-slate-400 font-sans">
              Standing:
            </span>
            <StandardsBadge status={status} size="sm" />
          </div>
        </div>
      </div>

      {/* Binary / Capability Cards */}
      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
        {options.map((opt, idx) => {
          const isObs = isOptionObserved(opt);
          const isPref = (opt.status === 'PREFERRED' || opt.status === 'RECOMMENDED');

          let cardBorder = 'border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30';
          if (isObs) {
            cardBorder = isPref
              ? 'border-emerald-400 dark:border-emerald-700 bg-emerald-50/40 dark:bg-emerald-950/20 ring-2 ring-emerald-400/40'
              : 'border-amber-400 dark:border-amber-700 bg-amber-50/40 dark:bg-amber-950/20 ring-2 ring-amber-400/40';
          }

          return (
            <div
              key={idx}
              className={`rounded-xl border p-3.5 relative transition-all flex flex-col justify-between ${cardBorder}`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    {isPref ? (
                      <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <ShieldAlert className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                    )}
                    <span className="font-mono text-xs font-bold text-slate-800 dark:text-slate-100">
                      {opt.label || opt.value}
                    </span>
                  </div>

                  <StandardsBadge status={opt.status} size="sm" showIcon={false} />
                </div>

                <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">
                  {opt.description}
                </p>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-200/60 dark:border-slate-800 flex items-center justify-between">
                {isObs ? (
                  <span className="inline-flex items-center gap-1 rounded bg-slate-900 dark:bg-white text-white dark:text-slate-900 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider">
                    <Check className="h-3 w-3 stroke-[3]" />
                    <span>Observed in Session</span>
                  </span>
                ) : (
                  <span className="text-[10px] text-slate-400">
                    Not Negotiated
                  </span>
                )}

                {isPref && (
                  <span className="text-[10px] font-semibold text-emerald-700 dark:text-emerald-400">
                    Industry Target
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Rationale */}
      {rationale && (
        <div className="mt-4 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200/70 dark:border-slate-800 p-3">
          <p className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">
            <span className="font-semibold text-slate-800 dark:text-slate-100">Standards Standing: </span>
            {rationale}
          </p>
        </div>
      )}

      {/* Provenance */}
      <StandardsProvenance
        profile={profile}
        profileName={profile_name}
        sources={sources}
        metadata={metadata}
      />
    </div>
  );
}
