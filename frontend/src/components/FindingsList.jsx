import React, { useMemo, useState } from 'react';
import FindingCard from './FindingCard';
import EmptyState from './EmptyState';

import {
  Bug,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from 'lucide-react';

import { compareSeverity } from '../utils/severity';


const FILTERS = [
  { key: 'ALL', label: 'All' },
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH', label: 'High' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'LOW', label: 'Low' },
  { key: 'INFO', label: 'Info' },
];


export default function FindingsList({
  findings = [],
  onSelectSession = null,
}) {
  const [severityFilter, setSeverityFilter] =
    useState('ALL');


  const sortedFindings = useMemo(() => {
    return [...findings].sort((a, b) =>
      compareSeverity(
        a.severity,
        b.severity
      )
    );
  }, [findings]);


  const filteredFindings = useMemo(() => {
    if (severityFilter === 'ALL') {
      return sortedFindings;
    }

    return sortedFindings.filter(
      (finding) =>
        (
          finding?.severity || 'INFO'
        ).toUpperCase() ===
        severityFilter
    );
  }, [
    sortedFindings,
    severityFilter,
  ]);


  const counts = useMemo(() => {
    const result = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    findings.forEach((finding) => {
      const severity = (
        finding?.severity || 'INFO'
      ).toUpperCase();

      if (
        result[severity] !== undefined
      ) {
        result[severity]++;
      }
    });

    return result;
  }, [findings]);


  const hasFilter =
    severityFilter !== 'ALL';


  return (
    <section className="w-full">

      {/* =========================================================
          HEADER
      ========================================================== */}

      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">

        <div className="flex items-center gap-3">

          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40">
            <Bug className="h-4 w-4 text-amber-600 dark:text-amber-400" />
          </div>

          <div>

            <div className="flex items-center gap-2">

              <h2 className="text-sm font-semibold text-slate-900 dark:text-white sm:text-[15px]">
                Security findings
              </h2>

              {findings.length > 0 && (
                <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-600 dark:text-slate-300">
                  {findings.length}
                </span>
              )}

            </div>

            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Detected security weaknesses requiring attention.
            </p>

          </div>

        </div>


        {findings.length === 0 && (
          <span className="inline-flex items-center gap-2 rounded-lg border border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 px-3 py-2 text-xs font-medium text-yellow-700 dark:text-yellow-300">

            <ShieldCheck className="h-3.5 w-3.5" />

            No issues detected

          </span>
        )}

      </div>


      {/* =========================================================
          FILTERS
      ========================================================== */}

      {findings.length > 0 && (
        <div className="mb-5 flex flex-wrap items-center gap-1.5">

          {FILTERS.map((filter) => {

            const count =
              filter.key === 'ALL'
                ? findings.length
                : counts[filter.key];

            if (
              filter.key !== 'ALL' &&
              count === 0
            ) {
              return null;
            }

            const active =
              severityFilter ===
              filter.key;

            return (
              <button
                key={filter.key}
                type="button"
                onClick={() =>
                  setSeverityFilter(
                    filter.key
                  )
                }
                className={`
                  inline-flex items-center gap-1.5
                  rounded-lg border
                  px-2.5 py-1.5
                  text-[11px] font-medium
                  transition-all duration-150

                  ${
                    active
                      ? getFilterClasses(
                          filter.key
                        )
                      : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-200'
                  }
                `}
              >

                <span>
                  {filter.label}
                </span>

                <span
                  className={`
                    min-w-[18px]
                    rounded-md
                    px-1
                    text-center
                    font-mono
                    text-[10px]
                    ${
                      active
                        ? 'bg-white/70 dark:bg-white/20 text-current'
                        : 'text-slate-400 dark:text-slate-500'
                    }
                  `}
                >
                  {count}
                </span>

              </button>
            );
          })}


          {hasFilter && (
            <button
              type="button"
              onClick={() =>
                setSeverityFilter('ALL')
              }
              className="ml-1 inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] font-medium text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200"
            >
              <X className="h-3 w-3" />
              Clear
            </button>
          )}

        </div>
      )}


      {/* =========================================================
          FILTER RESULT
      ========================================================== */}

      {hasFilter &&
        filteredFindings.length > 0 && (
          <div className="mb-3 text-[11px] text-slate-500 dark:text-slate-400">
            Showing{' '}
            <span className="font-mono font-semibold text-slate-700 dark:text-slate-200">
              {filteredFindings.length}
            </span>{' '}
            {severityFilter.toLowerCase()}{' '}
            finding
            {filteredFindings.length !== 1
              ? 's'
              : ''}
          </div>
        )}


      {/* =========================================================
          FINDINGS
      ========================================================== */}

      {filteredFindings.length > 0 ? (

        <div className="space-y-3">

          {filteredFindings.map(
            (finding) => (
              <FindingCard
                key={
                  finding.finding_id ||
                  `${finding.session_id}-${finding.title}`
                }
                finding={finding}
                onSelectSession={onSelectSession}
              />
            )
          )}

        </div>

      ) : findings.length === 0 ? (

        <EmptyState
          title="No security findings detected"
          message="No protocol violations, cleartext credentials, or downgrade attacks were identified in this capture."
          icon="secure"
        />

      ) : (

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-14 text-center">

          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
            <SlidersHorizontal className="h-4 w-4 text-slate-500 dark:text-slate-400" />
          </div>

          <h3 className="mt-4 text-sm font-semibold text-slate-900 dark:text-white">
            No {severityFilter.toLowerCase()} findings
          </h3>

          <p className="mx-auto mt-1 max-w-md text-xs leading-5 text-slate-500 dark:text-slate-400">
            No findings match the selected severity.
          </p>

          <button
            type="button"
            onClick={() =>
              setSeverityFilter('ALL')
            }
            className="ui-button ui-button-secondary mt-4 px-3 py-1.5 text-xs"
          >
            Show all findings
          </button>

        </div>

      )}

    </section>
  );
}


/* ===============================================================
   FILTER COLORS
=============================================================== */

function getFilterClasses(severity) {
  switch (severity) {
    case 'CRITICAL':
      return 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/50 text-red-700 dark:text-red-300';

    case 'HIGH':
      return 'border-orange-200 dark:border-orange-900/60 bg-orange-50 dark:bg-orange-950/50 text-orange-700 dark:text-orange-300';

    case 'MEDIUM':
      return 'border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300';

    case 'LOW':
      return 'border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/50 text-yellow-700 dark:text-yellow-300';

    case 'INFO':
      return 'border-blue-200 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/50 text-blue-700 dark:text-blue-300';

    default:
      return 'border-brand-200 dark:border-brand-900/60 bg-brand-50 dark:bg-brand-950/50 text-brand-700 dark:text-brand-300';
  }
}