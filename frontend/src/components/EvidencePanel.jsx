import React, { useState } from 'react';
import {
  Check,
  Copy,
  FileJson,
  CheckCircle2,
  XCircle,
} from 'lucide-react';

const ACRONYMS = new Set(['PFS', 'TLS', 'SSL', 'IP', 'TCP', 'UDP', 'DNS', 'SMTP', 'IMAP', 'POP3']);

function formatKey(key) {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w+/g, (word) => {
      const upper = word.toUpperCase();
      if (ACRONYMS.has(upper)) {
        return upper;
      }
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    });
}

function formatValue(value) {
  if (value === null || value === undefined || value === '') {
    return 'Not available';
  }

  if (typeof value === 'object') {
    return JSON.stringify(value);
  }

  return String(value);
}

export default function EvidencePanel({ evidence }) {
  const [copied, setCopied] = useState(false);

  if (!evidence || Object.keys(evidence).length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-900/60 px-4 py-5 text-center">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          No additional technical evidence is available for this finding.
        </p>
      </div>
    );
  }

  const entries = Object.entries(evidence);
  const jsonString = JSON.stringify(evidence, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(jsonString);
      setCopied(true);

      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
      {/* Evidence toolbar */}
      <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-850/80 px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-blue-100 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/40">
            <FileJson className="h-4 w-4 text-blue-600 dark:text-blue-400" />
          </div>

          <div>
            <p className="text-xs font-semibold text-slate-800 dark:text-white">
              Supporting evidence
            </p>

            <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
              {entries.length} attribute
              {entries.length !== 1 ? 's' : ''} observed in the capture
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={handleCopy}
          className="
            inline-flex items-center gap-1.5
            rounded-lg border border-slate-200 dark:border-slate-700
            bg-white dark:bg-slate-800 px-2.5 py-1.5
            text-[11px] font-medium text-slate-600 dark:text-slate-300
            transition-all
            hover:border-slate-300 dark:hover:border-slate-600
            hover:bg-slate-50 dark:hover:bg-slate-700
            hover:text-slate-900 dark:hover:text-white
          "
          title="Copy evidence as JSON"
        >
          {copied ? (
            <Check className="h-3.5 w-3.5 text-yellow-600 dark:text-yellow-400" />
          ) : (
            <Copy className="h-3.5 w-3.5 text-slate-400" />
          )}

          <span className={copied ? 'text-yellow-700 dark:text-yellow-300' : ''}>
            {copied ? 'Copied' : 'Copy JSON'}
          </span>
        </button>
      </div>

      {/* Evidence attributes */}
      <div className="divide-y divide-slate-100 dark:divide-slate-800">
        {entries.map(([key, value]) => {
          const isBoolean = typeof value === 'boolean';
          const isObject =
            typeof value === 'object' &&
            value !== null;

          return (
            <div
              key={key}
              className="
                flex flex-col gap-2
                px-4 py-3.5
                transition-colors
                hover:bg-slate-50/50 dark:hover:bg-slate-800/40
                sm:flex-row
                sm:items-center
                sm:justify-between
              "
            >
              <div className="min-w-0">
                <p className="text-xs font-semibold text-slate-700 dark:text-slate-200">
                  {formatKey(key)}
                </p>
              </div>

              <div className="sm:max-w-[58%]">
                {isBoolean ? (
                  <span
                    className={`
                      inline-flex items-center gap-1.5
                      rounded-lg border px-2.5 py-1
                      text-[11px] font-semibold
                      ${
                        value
                          ? 'border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-300'
                          : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                      }
                    `}
                  >
                    {value ? (
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5" />
                    )}

                    {value ? 'Observed' : 'Not observed'}
                  </span>
                ) : (
                  <code
                    className="
                      block break-all rounded-lg
                      border border-slate-100 dark:border-slate-800
                      bg-slate-50/80 dark:bg-slate-950/60
                      px-3 py-2
                      font-mono
                      text-[11px] leading-5
                      text-slate-700 dark:text-slate-300
                    "
                  >
                    {formatValue(value)}
                  </code>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}