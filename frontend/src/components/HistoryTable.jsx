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

    <div className="w-full overflow-hidden">

      <div className="overflow-x-auto">

        <table className="w-full text-left">

          {/* HEADER */}

          <thead>

            <tr className="border-b border-slate-100">

              {[
                'Analysis ID',
                'Capture File',
                'Analyzed',
                'Status',
                'Risk',
                'Sessions',
                'Findings',
                '',
              ].map((col, i) => (

                <th
                  key={i}
                  scope="col"
                  className={`
                    whitespace-nowrap
                    px-4 py-3
                    text-[10px]
                    font-bold
                    uppercase
                    tracking-[0.12em]
                    text-slate-400
                    ${i === 0 ? 'pl-5 sm:pl-6' : ''}
                    ${col === '' ? 'pr-5 text-right sm:pr-6' : ''}
                  `}
                >
                  {col}
                </th>

              ))}

            </tr>

          </thead>


          {/* BODY */}

          <tbody className="divide-y divide-slate-50">

            {items.map((item, rowIdx) => (

              <HistoryRow
                key={item.analysis_id}
                item={item}
                rowIdx={rowIdx}
              />

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