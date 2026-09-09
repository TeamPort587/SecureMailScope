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

          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-amber-200 bg-amber-50">
            <Bug className="h-4 w-4 text-amber-600" />
          </div>

          <div>

            <div className="flex items-center gap-2">

              <h2 className="text-sm font-semibold text-slate-900 sm:text-[15px]">
                Security findings
              </h2>

              {findings.length > 0 && (
                <span className="rounded-md bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-600">
                  {findings.length}
                </span>
              )}

            </div>

            <p className="mt-0.5 text-xs text-slate-500">
              Detected security weaknesses requiring attention.
            </p>

          </div>

        </div>


        {findings.length === 0 && (
          <span className="inline-flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-medium text-emerald-700">

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

          <div className="mr-1 flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-slate-400">

            <SlidersHorizontal className="h-3 w-3" />

            Severity

          </div>


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
                      : 'border-slate-200 bg-white text-slate-500 hover:bg-slate-50 hover:text-slate-800'
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
                        ? 'bg-white/70 text-current'
                        : 'text-slate-400'
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
              className="ml-1 inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] font-medium text-slate-400 hover:bg-slate-50 hover:text-slate-700"
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
          <div className="mb-3 text-[11px] text-slate-500">
            Showing{' '}
            <span className="font-mono font-semibold text-slate-700">
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

        <div className="rounded-xl border border-slate-200 bg-white px-6 py-14 text-center">

          <div className="mx-auto flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
            <SlidersHorizontal className="h-4 w-4 text-slate-500" />
          </div>

          <h3 className="mt-4 text-sm font-semibold text-slate-900">
            No {severityFilter.toLowerCase()} findings
          </h3>

          <p className="mx-auto mt-1 max-w-md text-xs leading-5 text-slate-500">
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
      return 'border-red-200 bg-red-50 text-red-700';

    case 'HIGH':
      return 'border-orange-200 bg-orange-50 text-orange-700';

    case 'MEDIUM':
      return 'border-amber-200 bg-amber-50 text-amber-700';

    case 'LOW':
      return 'border-emerald-200 bg-emerald-50 text-emerald-700';

    case 'INFO':
      return 'border-blue-200 bg-blue-50 text-blue-700';

    default:
      return 'border-brand-200 bg-brand-50 text-brand-700';
  }
}