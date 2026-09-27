import React from 'react';
import { EyeOff, CheckCircle2, AlertCircle, Clock, Calendar, HelpCircle, ShieldAlert, ShieldCheck } from 'lucide-react';
import StandardsBadge from './StandardsBadge';
import StandardsProvenance from './StandardsProvenance';

export default function StatusAssessment({ result }) {
  if (!result) return null;

  const {
    label,
    observed,
    status,
    rationale,
    profile,
    profile_name,
    sources = [],
    metadata = {},
  } = result;

  const isNotObservable = status === 'NOT_OBSERVABLE';
  const isValid = status === 'ACCEPTABLE' || status === 'PREFERRED';

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

      {/* Main Status Display */}
      {isNotObservable ? (
        <div className="mt-4 rounded-xl border border-purple-200 dark:border-purple-850 bg-gradient-to-r from-purple-50/60 via-purple-50/30 to-white dark:from-purple-950/30 dark:via-purple-950/10 dark:to-slate-900 p-4">
          <div className="flex items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-purple-200 dark:border-purple-800 bg-white dark:bg-slate-800 shadow-sm">
              <EyeOff className="h-4 w-4 text-purple-600 dark:text-purple-400" />
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <h5 className="text-xs font-bold text-purple-900 dark:text-purple-300">
                  Encrypted Handshake Privacy (Passive Capture Property)
                </h5>
                <span className="font-mono text-[10px] bg-purple-100 dark:bg-purple-900/60 text-purple-700 dark:text-purple-300 px-1.5 py-0.5 rounded font-bold">
                  PASSIVE EPISTEMOLOGY
                </span>
              </div>

              <p className="text-xs leading-relaxed text-purple-800/90 dark:text-purple-300/80">
                In TLS 1.3, the certificate payload is encrypted in-flight between client and server.
                Under passive PCAP inspection, unobservable certificates represent modern privacy
                protection and MUST NOT be classified as invalid or insecure.
              </p>
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-4 space-y-2">
          <div className={`rounded-xl border p-4 flex items-start gap-3.5 ${
            isValid
              ? 'border-emerald-200 dark:border-emerald-800/60 bg-emerald-50/40 dark:bg-emerald-950/20'
              : 'border-rose-200 dark:border-rose-800/60 bg-rose-50/40 dark:bg-rose-950/20'
          }`}>
            <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-white dark:bg-slate-800 shadow-sm ${
              isValid
                ? 'border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400'
                : 'border-rose-200 dark:border-rose-800 text-rose-600 dark:text-rose-400'
            }`}>
              {isValid ? (
                <ShieldCheck className="h-5 w-5" />
              ) : (
                <ShieldAlert className="h-5 w-5" />
              )}
            </div>

            <div className="space-y-1 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h5 className={`text-xs font-bold ${
                  isValid ? 'text-emerald-900 dark:text-emerald-300' : 'text-rose-900 dark:text-rose-300'
                }`}>
                  {observed}
                </h5>
              </div>

              <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300 bg-white/70 dark:bg-slate-800/60 px-2.5 py-1.5 rounded-lg border border-slate-200/60 dark:border-slate-700/60">
                  <Clock className="h-3.5 w-3.5 text-slate-400" />
                  <span>Validity Window Checked Against Capture Reference</span>
                </div>

                <div className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300 bg-white/70 dark:bg-slate-800/60 px-2.5 py-1.5 rounded-lg border border-slate-200/60 dark:border-slate-700/60">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                  <span>NIST SP 800-52 Temporal Constraints Evaluated</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

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
