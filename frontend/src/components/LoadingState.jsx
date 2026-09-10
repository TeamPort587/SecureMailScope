import React from 'react';
import { Loader2 } from 'lucide-react';

export default function LoadingState({ message = 'Loading security analysis data...', subtext = 'Inspecting captured packets and evaluating protocol constraints' }) {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center rounded-xl bg-slate-900/60 border border-slate-800 backdrop-blur-sm">
      <div className="relative mb-4">
        <div className="w-12 h-12 rounded-full border-2 border-brand-500/20 border-t-brand-500 animate-spin flex items-center justify-center">
          <Loader2 className="w-6 h-6 text-brand-400 animate-spin" />
        </div>
      </div>
      <p className="text-base font-medium text-slate-200">{message}</p>
      {subtext && <p className="text-sm text-slate-400 mt-1 max-w-md">{subtext}</p>}
    </div>
  );
}
