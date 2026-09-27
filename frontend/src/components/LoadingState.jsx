import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingState({
  message = 'Loading security analysis data...',
  subtext = 'Inspecting captured packets and evaluating protocol constraints',
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-200/80 bg-white dark:bg-slate-900/80 dark:border-slate-800 p-10 sm:p-14 text-center shadow-sm">
      {/* Ambient background glows */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-12 -top-12 h-48 w-48 rounded-full bg-brand-400/[0.07] blur-3xl" />
        <div className="absolute -right-12 -bottom-12 h-48 w-48 rounded-full bg-sky-300/[0.08] blur-3xl" />
      </div>

      {/* Top brand hairline accent */}
      <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-brand-500 to-transparent" />

      <div className="relative z-10 flex flex-col items-center justify-center">
        {/* Animated spinner badge */}
        <div className="relative mb-5 flex items-center justify-center">
          <div className="absolute h-16 w-16 rounded-2xl bg-brand-400/20 blur-md animate-pulse" />
          <div className="relative flex h-14 w-14 items-center justify-center rounded-2xl border border-brand-200/80 bg-brand-50/80 dark:bg-brand-950/40 dark:border-brand-800/60 shadow-sm">
            <Loader2 className="h-7 w-7 animate-spin text-brand-600 dark:text-brand-400" />
          </div>
        </div>

        {/* Status indicator pill */}
        <div className="mb-3 inline-flex items-center gap-1.5 rounded-full border border-brand-100 bg-brand-50/80 dark:border-brand-900/50 dark:bg-brand-950/50 px-3 py-1 text-[11px] font-semibold text-brand-700 dark:text-brand-300">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-brand-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-brand-500" />
          </span>
          <span className="uppercase tracking-wider">Processing</span>
        </div>

        {/* Main message */}
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 sm:text-lg">
          {message}
        </h3>

        {/* Subtext */}
        {subtext && (
          <p className="mt-1.5 max-w-md text-xs sm:text-sm text-slate-500 dark:text-slate-400 leading-relaxed">
            {subtext}
          </p>
        )}

        {/* Subtle animated shimmer line */}
        <div className="mt-6 h-1 w-36 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
          <div className="h-full w-full bg-gradient-to-r from-brand-300 via-brand-500 to-sky-400 animate-pulse rounded-full" />
        </div>
      </div>
    </div>
  );
}

