import React from 'react';
import {
  ArrowDown,
  Star,
  Check,
  ArrowRight,
  AlertTriangle,
  AlertCircle,
  Circle,
} from 'lucide-react';
import StandardsBadge from './StandardsBadge';
import StandardsProvenance from './StandardsProvenance';

export default function StandardsSpectrum({ result }) {
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

  // Determine which option matches the observed configuration
  const normalizedObserved = String(observed || '').toLowerCase().trim();

  const getOptionStatusStyle = (optStatus) => {
    const s = String(optStatus || '').toUpperCase();
    if (s === 'PREFERRED' || s === 'RECOMMENDED') {
      return {
        node: 'border-emerald-400 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400',
        badge: 'bg-emerald-50/60 border-emerald-200 text-emerald-700 dark:bg-emerald-950/30 dark:border-emerald-800 dark:text-emerald-400',
      };
    }
    if (s === 'ACCEPTABLE') {
      return {
        node: 'border-sky-300 bg-sky-50 dark:bg-sky-950/30 text-sky-600 dark:text-sky-400',
        badge: 'bg-sky-50/60 border-sky-200 text-sky-700 dark:bg-sky-950/30 dark:border-sky-800 dark:text-sky-400',
      };
    }
    if (s === 'NOT_RECOMMENDED') {
      return {
        node: 'border-amber-300 bg-amber-50 dark:bg-amber-950/30 text-amber-600 dark:text-amber-400',
        badge: 'bg-amber-50/60 border-amber-200 text-amber-700 dark:bg-amber-950/30 dark:border-amber-800 dark:text-amber-400',
      };
    }
    return {
      node: 'border-rose-300 bg-rose-50 dark:bg-rose-950/30 text-rose-500 dark:text-rose-400',
      badge: 'bg-rose-50/60 border-rose-200 text-rose-700 dark:bg-rose-950/30 dark:border-rose-800 dark:text-rose-400',
    };
  };

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

  const isOptionPreferred = (opt) => {
    return preferred.some(
      (p) =>
        String(p).toLowerCase().trim() === String(opt.value).toLowerCase().trim() ||
        String(p).toLowerCase().trim() === String(opt.label).toLowerCase().trim()
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

      {/* Spectrum Visualization Track */}
      <div className="mt-6 mb-4 px-2">
        {/* Scale Direction Indicators */}
        <div className="flex items-center justify-between text-[11px] font-bold uppercase tracking-wider mb-4 px-1">
          <span className="flex items-center gap-1.5 text-rose-500 dark:text-rose-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-rose-500" />
            <span>Less preferred</span>
          </span>
          <span className="flex items-center gap-1.5 text-brand-600 dark:text-brand-400">
            <span>Spectrum Progression</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </span>
          <span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
            <span>More preferred</span>
          </span>
        </div>

        {/* Horizontal Track with Step Nodes */}
        <div className="relative">
          {/* Background Connecting Line with gradient matching progression */}
          <div className="absolute top-5 left-6 right-6 h-1 bg-gradient-to-r from-rose-200 via-sky-200 to-emerald-300 dark:from-rose-900/50 dark:via-sky-900/50 dark:to-emerald-900/50 -translate-y-1/2 z-0 rounded-full" />

          {/* Options Grid */}
          <div
            className="relative z-10 grid gap-2"
            style={{
              gridTemplateColumns: `repeat(${Math.max(options.length, 1)}, minmax(0, 1fr))`,
            }}
          >
            {options.map((opt, idx) => {
              const isObs = isOptionObserved(opt);
              const isPref = isOptionPreferred(opt);
              const style = getOptionStatusStyle(opt.status);

              return (
                <div key={idx} className="flex flex-col items-center text-center">
                  {/* Observed Pointer Indicator (Above Node) */}
                  <div className="h-7 flex items-end justify-center mb-1">
                    {isObs && (
                      <span className="animate-observed-badge inline-flex items-center gap-1 rounded-full bg-slate-900 dark:bg-white text-white dark:text-slate-900 px-2.5 py-0.5 text-[9px] font-bold tracking-wider uppercase transition-all select-none">
                        <ArrowDown className="h-2.5 w-2.5 text-sky-400 dark:text-sky-600 shrink-0" />
                        <span>Observed</span>
                      </span>
                    )}
                  </div>

                  {/* Milestone Node Circle */}
                  <div
                    className={`relative flex h-9 w-9 items-center justify-center rounded-full border-2 transition-all ${style.node}`}
                    title={`${opt.label}: ${opt.status} ${opt.description ? `\n\n${opt.description}` : ''}`}
                  >
                    {isPref || opt.status === 'PREFERRED' || opt.status === 'RECOMMENDED' ? (
                      <Star className="h-4 w-4 fill-current" />
                    ) : opt.status === 'ACCEPTABLE' ? (
                      <Check className="h-4 w-4 stroke-[2.5]" />
                    ) : opt.status === 'NOT_RECOMMENDED' ? (
                      <AlertCircle className="h-4 w-4" />
                    ) : opt.status === 'DEPRECATED' ? (
                      <AlertTriangle className="h-4 w-4" />
                    ) : (
                      <Circle className="h-2.5 w-2.5 fill-current opacity-70" />
                    )}
                  </div>

                  {/* Option Label */}
                  <p className={`mt-2 font-mono text-xs font-bold leading-tight ${
                    isObs
                      ? 'text-slate-900 dark:text-white'
                      : 'text-slate-700 dark:text-slate-300'
                  }`}>
                    {opt.label || opt.value}
                  </p>

                  {/* Status Sub-badge */}
                  <span
                    className={`mt-1 inline-block rounded border px-1.5 py-0.2 text-[9px] font-semibold uppercase tracking-tight ${style.badge}`}
                  >
                    {opt.status}
                  </span>

                  {/* Description note */}
                  {opt.description && (
                    <p className="mt-1 text-[10px] text-slate-500 dark:text-slate-400 leading-tight hidden sm:block max-w-[140px]">
                      {opt.description}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Rationale & Context Note */}
      {rationale && (
        <div className="mt-4 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200/70 dark:border-slate-800 p-3">
          <p className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">
            <span className="font-semibold text-slate-800 dark:text-slate-100">Standards Standing: </span>
            {rationale}
          </p>
        </div>
      )}

      {/* Authoritative Provenance & Links */}
      <StandardsProvenance
        profile={profile}
        profileName={profile_name}
        sources={sources}
        metadata={metadata}
      />
    </div>
  );
}
