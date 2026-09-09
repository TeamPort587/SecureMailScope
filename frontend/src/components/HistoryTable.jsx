import React from 'react';

import { Link } from 'react-router-dom';

import RiskBadge from './RiskBadge';
import EmptyState from './EmptyState';

import {
  FileText,
  ArrowRight,
  CheckCircle2,
} from 'lucide-react';

import { formatDate } from '../utils/formatters';


export default function HistoryTable({
  items = [],
  loading = false,
}) {

  /* =====================================================
      LOADING
  ====================================================== */

  if (loading) {

    return (

      <div className="flex min-h-[280px] items-center justify-center">

        <div className="flex flex-col items-center gap-3">

          <div className="
            h-8 w-8
            rounded-full
            border-2 border-slate-200
            border-t-brand-600
            animate-spin
          " />

          <p className="text-xs text-slate-400">
            Loading history...
          </p>

        </div>

      </div>

    );

  }


  /* =====================================================
      EMPTY
  ====================================================== */

  if (!items || items.length === 0) {

    return (

      <div className="py-4">

        <EmptyState
          title="No analyses found"
          message="Upload a PCAP capture from the Dashboard to generate your first security analysis."
          icon="search"
        />

      </div>

    );

  }


  /* =====================================================
      TABLE
  ====================================================== */

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


/* ===============================================================
   ROW
=============================================================== */

function HistoryRow({ item, rowIdx }) {

  const findingsCount =
    item.finding_count ?? null;

  const hasFinding = findingsCount > 0;

  return (

    <tr className="
      group
      transition-colors
      hover:bg-slate-50/70
    ">

      {/* ANALYSIS ID */}

      <td className="whitespace-nowrap pl-5 pr-4 py-3.5 sm:pl-6">

        <Link
          to={`/analysis/${item.analysis_id}`}
          className="
            font-mono
            text-[11px]
            font-semibold
            text-brand-600
            transition-colors
            hover:text-brand-700
          "
        >
          {item.analysis_id?.slice(0, 12) || '—'}
          <span className="text-slate-300">...</span>
        </Link>

      </td>


      {/* FILENAME */}

      <td className="min-w-[180px] px-4 py-3.5">

        <div className="flex items-center gap-2.5">

          <div className="
            flex h-7 w-7 shrink-0
            items-center justify-center
            rounded-lg
            bg-slate-100
          ">

            <FileText className="h-3.5 w-3.5 text-slate-400" />

          </div>

          <span
            className="
              max-w-[200px]
              truncate
              text-sm
              font-medium
              text-slate-700
            "
            title={item.filename}
          >
            {item.filename || 'Unknown capture'}
          </span>

        </div>

      </td>


      {/* DATE */}

      <td className="whitespace-nowrap px-4 py-3.5">

        <span className="text-xs text-slate-400">
          {formatDate(item.created_at || item.uploaded_at)}
        </span>

      </td>


      {/* STATUS */}

      <td className="whitespace-nowrap px-4 py-3.5">

        <span className="
          inline-flex
          items-center
          gap-1.5
          rounded-full
          bg-yellow-50
          px-2.5 py-1
          text-[11px]
          font-semibold
          text-yellow-600
        ">

          <span className="
            h-1.5 w-1.5
            rounded-full
            bg-yellow-500
          " />

          <span className="capitalize">
            {item.status || 'completed'}
          </span>

        </span>

      </td>


      {/* RISK */}

      <td className="whitespace-nowrap px-4 py-3.5">

        <RiskBadge
          level={item.risk_label || 'INFO'}
          size="sm"
        />

      </td>


      {/* SESSIONS */}

      <td className="whitespace-nowrap px-4 py-3.5">

        <span className="
          font-mono
          text-xs
          font-semibold
          text-slate-600
        ">
          {item.session_count ?? '—'}
        </span>

      </td>


      {/* FINDINGS */}

      <td className="whitespace-nowrap px-4 py-3.5">

        <span className={`
          inline-flex
          items-center
          justify-center
          min-w-[22px]
          rounded-md
          px-1.5 py-0.5
          font-mono
          text-xs
          font-semibold
          ${
            hasFinding
              ? 'bg-amber-50 text-amber-700'
              : 'text-slate-400'
          }
        `}>
          {findingsCount ?? '—'}
        </span>

      </td>


      {/* ACTION */}

      <td className="whitespace-nowrap pr-5 pl-4 py-3.5 text-right sm:pr-6">

        <Link
          to={`/analysis/${item.analysis_id}`}
          className="
            inline-flex
            items-center
            gap-1
            rounded-lg
            border border-slate-200
            bg-white
            px-3 py-1.5
            text-[11px]
            font-semibold
            text-slate-600
            shadow-sm
            transition-all
            hover:border-brand-200
            hover:bg-brand-50
            hover:text-brand-700
            hover:shadow
          "
        >
          Inspect
          <ArrowRight className="
            h-3 w-3
            transition-transform
            group-hover:translate-x-0.5
          " />
        </Link>

      </td>

    </tr>

  );

}