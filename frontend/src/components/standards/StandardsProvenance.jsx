import React, { useState } from 'react';
import { BookOpen, ExternalLink, ChevronDown, ChevronUp, Calendar, CheckSquare } from 'lucide-react';

export default function StandardsProvenance({ profile, profileName, sources = [], metadata = {} }) {
  const [isOpen, setIsOpen] = useState(false);

  if (!sources || sources.length === 0) return null;

  return (
    <div className="mt-3 border-t border-slate-100 dark:border-slate-800/80 pt-2.5">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex w-full items-center justify-between py-1 text-xs text-slate-500 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
      >
        <span className="flex items-center gap-1.5 font-medium">
          <BookOpen className="h-3.5 w-3.5 text-slate-400" />
          <span>Authoritative Guidance & Provenance</span>
          <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono">
            ({sources.length} {sources.length === 1 ? 'source' : 'sources'})
          </span>
        </span>
        {isOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
      </button>

      {isOpen && (
        <div className="mt-2.5 space-y-2 rounded-lg bg-slate-50/80 dark:bg-slate-900/60 p-3 border border-slate-200/80 dark:border-slate-800 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-200/60 dark:border-slate-800 text-[11px]">
            <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
              <span className="font-semibold text-slate-700 dark:text-slate-200">Profile:</span>
              <span className="font-mono text-brand-700 dark:text-brand-400 bg-brand-50 dark:bg-brand-950/60 px-1.5 py-0.5 rounded">
                {profileName || profile}
              </span>
            </div>

            {metadata?.last_reviewed && (
              <div className="flex items-center gap-1 text-slate-400 text-[10px]">
                <Calendar className="h-3 w-3" />
                <span>Reviewed: {metadata.last_reviewed}</span>
              </div>
            )}
          </div>

          <div className="space-y-2 pt-1">
            {sources.map((src, idx) => (
              <div
                key={idx}
                className="rounded-md bg-white dark:bg-slate-800/80 p-2.5 border border-slate-200/60 dark:border-slate-700/60"
              >
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="font-mono font-bold text-slate-800 dark:text-slate-100">
                      {src.name}
                    </span>
                    {src.title && (
                      <span className="ml-1.5 text-slate-600 dark:text-slate-300 font-medium">
                        — {src.title}
                      </span>
                    )}
                  </div>

                  {src.url && (
                    <a
                      href={src.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex shrink-0 items-center gap-1 text-[11px] font-semibold text-brand-600 dark:text-brand-400 hover:underline"
                    >
                      <span>View Standard</span>
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>

                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500 dark:text-slate-400">
                  {src.section && (
                    <span className="font-mono bg-slate-100 dark:bg-slate-700/60 px-1.5 py-0.5 rounded text-slate-600 dark:text-slate-300">
                      {src.section}
                    </span>
                  )}
                  {src.effective_status && (
                    <span className="flex items-center gap-1">
                      <CheckSquare className="h-3 w-3 text-emerald-500" />
                      <span>Status: {src.effective_status.replace(/_/g, ' ')}</span>
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
