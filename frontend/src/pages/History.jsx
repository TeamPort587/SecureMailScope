import React from 'react';
import { useHistory } from '../hooks/useHistory';
import HistoryTable from '../components/HistoryTable';
import ErrorState from '../components/ErrorState';
import { History as HistoryIcon, RefreshCw, Layers } from 'lucide-react';

export default function History() {
  const { items, pagination, loading, error, refresh } = useHistory(1, 20);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 rounded-2xl bg-slate-900/50 border border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center text-brand-400">
              <HistoryIcon className="w-4 h-4" />
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              Analysis History Log
            </h1>
          </div>
          <p className="text-xs sm:text-sm text-slate-400">
            Audit log of previously uploaded email PCAP captures persisted in the PostgreSQL gateway database.
          </p>
        </div>

        <button
          onClick={() => refresh()}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Log</span>
        </button>
      </div>

      {/* Error state if any */}
      {error && (
        <ErrorState
          title="Could Not Load Analysis History"
          message={error}
          onRetry={() => refresh()}
        />
      )}

      {/* History Table */}
      <HistoryTable items={items} loading={loading} />

      {/* Pagination Footer */}
      {pagination && pagination.total > 0 && (
        <div className="flex items-center justify-between text-xs text-slate-400 px-2">
          <span>
            Showing <strong>{items.length}</strong> of <strong>{pagination.total}</strong> stored analyses
          </span>
          <span className="font-mono text-[11px] text-slate-500">
            Page {pagination.page}
          </span>
        </div>
      )}
    </div>
  );
}
