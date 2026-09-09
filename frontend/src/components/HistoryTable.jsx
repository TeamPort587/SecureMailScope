import React from 'react';
import { Link } from 'react-router-dom';
import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';
import { History, FileText, ArrowRight, CheckCircle2, Clock, AlertCircle } from 'lucide-react';
import { formatDate } from '../utils/formatters';

export default function HistoryTable({ items = [], loading = false }) {
  if (loading) {
    return (
      <div className="py-12 text-center text-slate-400 text-xs font-mono animate-pulse">
        Loading historical analysis logs from Node.js Gateway...
      </div>
    );
  }

  if (!items || items.length === 0) {
    return (
      <EmptyState
        title="No Past Analyses Found"
        message="Upload a PCAP capture on the dashboard to generate your first email security analysis."
        icon="search"
      />
    );
  }

  return (
    <div className="w-full rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 overflow-hidden shadow-sm">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-600 dark:text-slate-300">
          <thead className="bg-slate-50 dark:bg-slate-950/70 border-b border-slate-200 dark:border-slate-800 text-[11px] font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider font-mono">
            <tr>
              <th scope="col" className="py-3 px-3.5">Analysis ID</th>
              <th scope="col" className="py-3 px-3">Capture File</th>
              <th scope="col" className="py-3 px-3">Analyzed Date</th>
              <th scope="col" className="py-3 px-3">Status</th>
              <th scope="col" className="py-3 px-3">Overall Risk</th>
              <th scope="col" className="py-3 px-3">Sessions</th>
              <th scope="col" className="py-3 px-3">Findings</th>
              <th scope="col" className="py-3 px-3.5 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-mono">
            {items.map((item) => (
              <tr
                key={item.analysis_id}
                className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors group"
              >
                {/* ID */}
                <td className="py-3 px-3.5 font-bold text-slate-900 dark:text-slate-200">
                  <Link
                    to={`/analysis/${item.analysis_id}`}
                    className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                  >
                    {item.analysis_id.slice(0, 16)}...
                  </Link>
                </td>

                {/* Filename */}
                <td className="py-3 px-3 font-sans font-medium text-slate-900 dark:text-slate-200">
                  <div className="flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
                    <span>{item.filename}</span>
                  </div>
                </td>

                {/* Date */}
                <td className="py-3 px-3 text-slate-400">
                  {formatDate(item.created_at || item.uploaded_at)}
                </td>

                {/* Status */}
                <td className="py-3 px-3">
                  {item.status === 'FAILED' ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-sans px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                      <AlertCircle className="w-3 h-3" />
                      <span className="capitalize">{item.status || 'failed'}</span>
                    </span>
                  ) : item.status === 'PROCESSING' ? (
                    <span className="inline-flex items-center gap-1 text-[11px] font-sans px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                      <Clock className="w-3 h-3" />
                      <span className="capitalize">{item.status || 'processing'}</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] font-sans px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                      <CheckCircle2 className="w-3 h-3" />
                      <span className="capitalize">{item.status || 'completed'}</span>
                    </span>
                  )}
                </td>

                {/* Risk */}
                <td className="py-3 px-3">
                  <RiskBadge level={item.risk_label || 'INFO'} size="sm" />
                </td>

                {/* Sessions */}
                <td className="py-3 px-3 text-slate-300">
                  {item.session_count ?? '—'}
                </td>

                {/* Findings */}
                <td className="py-3 px-3">
                  <span className={item.finding_count > 0 ? 'text-amber-400 font-semibold' : 'text-slate-400'}>
                    {item.finding_count ?? '—'}
                  </span>
                </td>

                {/* Action */}
                <td className="py-3 px-3.5 text-right font-sans">
                  <Link
                    to={`/analysis/${item.analysis_id}`}
                    className="inline-flex items-center gap-1 px-3 py-1 text-xs rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-brand-600 dark:hover:bg-brand-600 text-slate-700 dark:text-slate-200 hover:text-white dark:hover:text-white border border-slate-200 dark:border-slate-700 transition-colors"
                  >
                    <span>Inspect</span>
                    <ArrowRight className="w-3 h-3" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
