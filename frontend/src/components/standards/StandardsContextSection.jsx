import React, { useState } from 'react';
import { Compass, BookCheck, ShieldCheck, Sparkles, Filter, Info } from 'lucide-react';
import StandardsSpectrum from './StandardsSpectrum';
import CapabilityComparison from './CapabilityComparison';
import StatusAssessment from './StatusAssessment';

export default function StandardsContextSection({ standardsContext = [], session = null, hideHeader = false }) {
  const [activeTab, setActiveTab] = useState('ALL');

  if (!standardsContext || standardsContext.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-slate-200 dark:border-slate-800 bg-white/60 dark:bg-slate-900/60 p-5 text-center text-xs text-slate-500 dark:text-slate-400">
        <Compass className="h-5 w-5 mx-auto mb-2 text-slate-400 dark:text-slate-500" />
        <p>No standards configuration comparisons are available for this session.</p>
      </div>
    );
  }

  // Filter comparisons based on tab
  const filteredItems = standardsContext.filter((item) => {
    if (activeTab === 'ALL') return true;
    if (activeTab === 'TLS') {
      return item.profile === 'ietf-modern-tls' || item.field.includes('tls') || item.field.includes('cipher') || item.field === 'pfs';
    }
    if (activeTab === 'EMAIL') {
      return item.profile === 'email-security' || item.field.includes('email');
    }
    if (activeTab === 'NIST') {
      return item.profile === 'nist-tls' || item.field.includes('certificate');
    }
    return true;
  });

  return (
    <section className="space-y-3.5">
      {/* Section Header */}
      {!hideHeader && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-sky-200 dark:border-sky-800 bg-sky-50 dark:bg-sky-950/60 text-sky-600 dark:text-sky-400">
              <Compass className="h-4 w-4" />
            </div>

            <div>
              <h4 className="text-[15px] font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <span>Standards Context & Configuration Comparison</span>
                <span className="font-mono text-[10px] bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded-full font-bold">
                  {standardsContext.length} {standardsContext.length === 1 ? 'PROPERTY' : 'PROPERTIES'}
                </span>
              </h4>
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                Evaluates where observed configurations sit relative to authoritative industry baselines and preferences.
              </p>
            </div>
          </div>

          {/* Informational Epistemology Pill */}
          <div className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 px-2.5 py-1 text-[11px] text-slate-500 dark:text-slate-400">
            <Info className="h-3.5 w-3.5 text-brand-500 shrink-0" />
            <span>Contextual guidance · Separate from risk scoring</span>
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center gap-1.5 border-b border-slate-200/80 dark:border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('ALL')}
          className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
            activeTab === 'ALL'
              ? 'bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          All Guidance ({standardsContext.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('TLS')}
          className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
            activeTab === 'TLS'
              ? 'bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          IETF Modern TLS (RFC 9325 / 8996)
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('EMAIL')}
          className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
            activeTab === 'EMAIL'
              ? 'bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          Email Security (RFC 8314)
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('NIST')}
          className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
            activeTab === 'NIST'
              ? 'bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 border border-brand-200 dark:border-brand-800'
              : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
          }`}
        >
          NIST TLS & Keys (SP 800-52 / 57)
        </button>
      </div>

      {/* Comparisons List */}
      <div className="space-y-3.5 pt-1">
        {filteredItems.map((item, idx) => {
          if (item.visualization === 'capability_comparison') {
            return <CapabilityComparison key={item.field || idx} result={item} />;
          }
          if (item.visualization === 'status_assessment') {
            return <StatusAssessment key={item.field || idx} result={item} />;
          }
          // Default to ordered / categorical spectrum
          return <StandardsSpectrum key={item.field || idx} result={item} />;
        })}
      </div>
    </section>
  );
}
