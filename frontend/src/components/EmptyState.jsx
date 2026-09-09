import React from 'react';
import { ShieldCheck, FileQuestion } from 'lucide-react';

export default function EmptyState({ title = 'No Data Available', message = 'No security records matched the selected query.', icon = 'search' }) {
  const Icon = icon === 'secure' ? ShieldCheck : FileQuestion;
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center rounded-xl bg-slate-900/40 border border-slate-800">
      <div className="w-10 h-10 rounded-full bg-slate-800 flex items-center justify-center text-slate-400 mb-2">
        <Icon className="w-5 h-5" />
      </div>
      <h4 className="text-sm font-semibold text-slate-300">{title}</h4>
      <p className="text-xs text-slate-500 mt-1 max-w-sm">{message}</p>
    </div>
  );
}
