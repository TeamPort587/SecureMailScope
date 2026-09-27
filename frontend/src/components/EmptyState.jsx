import React from 'react';
import { ShieldCheck, FileQuestion } from 'lucide-react';

export default function EmptyState({
  title = 'No Data Available',
  message = 'No security records matched the selected query.',
  icon = 'search',
}) {
  const Icon = icon === 'secure' ? ShieldCheck : FileQuestion;
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-200/80 bg-white dark:bg-slate-900/80 dark:border-slate-800 p-8 sm:p-10 text-center shadow-sm">
      <div className="flex flex-col items-center justify-center">
        <div className="w-12 h-12 rounded-2xl bg-slate-100 border border-slate-200 dark:bg-slate-800 dark:border-slate-700 flex items-center justify-center text-slate-400 dark:text-slate-500 mb-3 shadow-inner">
          <Icon className="w-6 h-6" />
        </div>
        <h4 className="text-base font-semibold text-slate-800 dark:text-slate-200">{title}</h4>
        <p className="text-xs sm:text-sm text-slate-500 dark:text-slate-400 mt-1 max-w-sm leading-relaxed">{message}</p>
      </div>
    </div>
  );
}

