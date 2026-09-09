import React from 'react';
import { AlertOctagon, RefreshCw } from 'lucide-react';

export default function ErrorState({ title = 'Analysis Encountered An Error', message = 'Unable to complete the requested analysis operation.', onRetry = null }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center rounded-xl bg-red-950/20 border border-red-500/30">
      <div className="w-12 h-12 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400 mb-3">
        <AlertOctagon className="w-6 h-6" />
      </div>
      <h3 className="text-base font-semibold text-red-300">{title}</h3>
      <p className="text-sm text-red-200/80 mt-1 max-w-md">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-200 border border-red-500/40 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Try Again</span>
        </button>
      )}
    </div>
  );
}
