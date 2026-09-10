import React from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

export default function ErrorState({
  title = 'Analysis Encountered An Error',
  message = 'Unable to complete the requested analysis operation.',
  onRetry = null,
}) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-rose-200/80 bg-white dark:bg-slate-900/80 dark:border-rose-950 p-8 sm:p-10 text-center shadow-sm">
      {/* Top accent hairline */}
      <div className="absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-rose-500 to-transparent" />

      <div className="relative z-10 flex flex-col items-center justify-center">
        {/* Icon */}
        <div className="relative mb-4 flex items-center justify-center">
          <div className="w-13 h-13 rounded-2xl bg-rose-50 border border-rose-200/80 dark:bg-rose-950/40 dark:border-rose-800/60 p-3 flex items-center justify-center text-rose-600 dark:text-rose-400 shadow-sm">
            <AlertOctagon className="w-6 h-6" />
          </div>
        </div>

        {/* Title */}
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h3>

        {/* Message */}
        <p className="text-sm text-slate-500 dark:text-slate-400 mt-1.5 max-w-md leading-relaxed">{message}</p>

        {/* Action */}
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-5 inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-rose-600 hover:bg-rose-700 text-white shadow-sm transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Try Again</span>
          </button>
        )}
      </div>
    </div>
  );
}

