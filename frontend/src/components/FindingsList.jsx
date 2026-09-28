import React, { useMemo, useState } from 'react';
import GroupedFindingCard from './GroupedFindingCard';
import EmptyState from './EmptyState';

import {
  Bug,
  ShieldCheck,
  SlidersHorizontal,
  X,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';

import { compareSeverity, getSeverityConfig } from '../utils/severity';

const FILTERS = [
  { key: 'ALL', label: 'All' },
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'HIGH', label: 'High' },
  { key: 'MEDIUM', label: 'Medium' },
  { key: 'LOW', label: 'Low' },
  { key: 'INFO', label: 'Info' },
];

const PAGE_SIZE = 15;

export default function FindingsList({
  findings = [],
  sessions = [],
  totalSessions = null,
  onSelectSession = null,
  onViewSessionsTab = null,
  onFilterSessionsInTable = null,
}) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);

  /* =========================================================
     GROUPED FINDINGS (By finding_type / title)
  ========================================================== */
  const allGroupedFindings = useMemo(() => {
    const groupsMap = new Map();

    findings.forEach((finding) => {
      // Grouping key: prefer finding_type, then title
      const key = finding?.finding_type || finding?.title || 'GENERAL';

      if (!groupsMap.has(key)) {
        groupsMap.set(key, {
          groupKey: key,
          finding_type: finding?.finding_type || key,
          title: finding?.title || 'Security finding detected',
          description: finding?.description || '',
          severity: (finding?.severity || 'INFO').toUpperCase(),
          confidence: finding?.confidence || 'OBSERVED',
          recommendation: finding?.recommendation || null,
          findings: [],
          affectedSessions: new Set(),
        });
      }

      const group = groupsMap.get(key);
      group.findings.push(finding);

      if (finding?.session_id) {
        group.affectedSessions.add(finding.session_id);
      }

      // If this finding has a higher severity rank than current group severity, upgrade it
      const currentRank = getSeverityConfig(group.severity).rank;
      const findingRank = getSeverityConfig(finding?.severity).rank;
      if (findingRank > currentRank) {
        group.severity = (finding?.severity || 'INFO').toUpperCase();
      }

      if (!group.description && finding?.description) {
        group.description = finding.description;
      }
      if (!group.recommendation && finding?.recommendation) {
        group.recommendation = finding.recommendation;
      }
    });

    const groups = Array.from(groupsMap.values()).map((g) => ({
      ...g,
      affectedSessions: Array.from(g.affectedSessions),
    }));

    // Sort by severity (Critical -> High -> Medium -> Low -> Info), then by affected sessions count descending
    return groups.sort((a, b) => {
      const sevDiff = compareSeverity(a.severity, b.severity);
      if (sevDiff !== 0) return sevDiff;
      return b.affectedSessions.length - a.affectedSessions.length;
    });
  }, [findings]);

  /* =========================================================
     FILTERING
  ========================================================== */
  const filteredGroupedFindings = useMemo(() => {
    if (severityFilter === 'ALL') {
      return allGroupedFindings;
    }
    return allGroupedFindings.filter(
      (group) => group.severity === severityFilter
    );
  }, [allGroupedFindings, severityFilter]);

  /* =========================================================
     FILTER COUNTS
  ========================================================== */
  const counts = useMemo(() => {
    const result = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    allGroupedFindings.forEach((g) => {
      if (result[g.severity] !== undefined) {
        result[g.severity]++;
      }
    });

    return result;
  }, [allGroupedFindings]);

  /* =========================================================
     PAGINATION
  ========================================================== */
  const totalPages = Math.ceil(filteredGroupedFindings.length / PAGE_SIZE) || 1;

  const paginatedItems = useMemo(() => {
    if (filteredGroupedFindings.length <= PAGE_SIZE) {
      return filteredGroupedFindings;
    }
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredGroupedFindings.slice(start, start + PAGE_SIZE);
  }, [filteredGroupedFindings, currentPage]);

  const hasFilter = severityFilter !== 'ALL';

  const handleFilterChange = (key) => {
    setSeverityFilter(key);
    setCurrentPage(1);
  };

  return (
    <section className="w-full">
      {/* =========================================================
          HEADER
      ========================================================== */}
      <div className="mb-5 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        
        {/* Left: Title & Count */}
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40">
            <Bug className="h-5 w-5 text-amber-600 dark:text-amber-400" />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white sm:text-[16px]">
                Security findings
              </h2>

              {findings.length > 0 && (
                <span className="rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-xs font-semibold text-slate-600 dark:text-slate-300">
                  {allGroupedFindings.length} {allGroupedFindings.length === 1 ? 'issue' : 'issues'}
                </span>
              )}
            </div>

            <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
              Deduplicated vulnerabilities aggregated across all inspected sessions.
            </p>
          </div>
        </div>

        {/* Right: Total Occurrences indicator or Empty state badge */}
        <div className="flex items-center gap-2.5 self-start sm:self-auto">
          {findings.length > 0 ? (
            <div className="inline-flex items-center gap-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 px-3 py-1.5 text-xs text-slate-600 dark:text-slate-300 shadow-sm">
              <span className="font-mono font-semibold text-slate-900 dark:text-white">
                {findings.length}
              </span>
              <span>raw {findings.length === 1 ? 'occurrence' : 'occurrences'} across capture</span>
            </div>
          ) : (
            <span className="inline-flex items-center gap-2 rounded-lg border border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 px-3 py-2 text-xs font-medium text-yellow-700 dark:text-yellow-300">
              <ShieldCheck className="h-3.5 w-3.5" />
              No issues detected
            </span>
          )}
        </div>

      </div>

      {/* =========================================================
          FILTERS
      ========================================================== */}
      {findings.length > 0 && (
        <div className="mb-5 flex flex-wrap items-center gap-1.5">
          {FILTERS.map((filter) => {
            const count =
              filter.key === 'ALL'
                ? allGroupedFindings.length
                : counts[filter.key];

            if (filter.key !== 'ALL' && count === 0) {
              return null;
            }

            const active = severityFilter === filter.key;

            return (
              <button
                key={filter.key}
                type="button"
                onClick={() => handleFilterChange(filter.key)}
                className={`
                  inline-flex items-center gap-1.5
                  rounded-lg border
                  px-2.5 py-1.5
                  text-[11px] font-medium
                  transition-all duration-150
                  ${
                    active
                      ? getFilterClasses(filter.key)
                      : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-800 dark:hover:text-slate-200'
                  }
                `}
              >
                <span>{filter.label}</span>
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
              onClick={() => handleFilterChange('ALL')}
              className="ml-1 inline-flex items-center gap-1 rounded-lg px-2 py-1.5 text-[11px] font-medium text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 hover:text-slate-700 dark:hover:text-slate-200"
            >
              <X className="h-3 w-3" />
              Clear
            </button>
          )}
        </div>
      )}

      {/* =========================================================
          FILTER SUMMARY
      ========================================================== */}
      {hasFilter && filteredGroupedFindings.length > 0 && (
        <div className="mb-3 text-[11px] text-slate-500 dark:text-slate-400">
          Showing{' '}
          <span className="font-mono font-semibold text-slate-700 dark:text-slate-200">
            {filteredGroupedFindings.length}
          </span>{' '}
          {severityFilter.toLowerCase()}{' '}
          vulnerability {filteredGroupedFindings.length !== 1 ? 'types' : 'type'}
        </div>
      )}

      {/* =========================================================
          FINDINGS LIST
      ========================================================== */}
      {filteredGroupedFindings.length > 0 ? (
        <div className="space-y-3.5">
          {paginatedItems.map((group) => (
            <GroupedFindingCard
              key={group.groupKey}
              group={group}
              sessions={sessions}
              totalCaptureSessions={totalSessions || sessions.length || 0}
              onSelectSession={onSelectSession}
              onViewSessionsTab={onViewSessionsTab}
              onFilterSessionsInTable={onFilterSessionsInTable}
            />
          ))}

          {/* =========================================================
              PAGINATION FOOTER (Rendered if totalPages > 1)
          ========================================================== */}
          {totalPages > 1 && (
            <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-4 py-3 shadow-sm">
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Showing{' '}
                <span className="font-semibold text-slate-700 dark:text-slate-200">
                  {(currentPage - 1) * PAGE_SIZE + 1}
                </span>{' '}
                to{' '}
                <span className="font-semibold text-slate-700 dark:text-slate-200">
                  {Math.min(currentPage * PAGE_SIZE, filteredGroupedFindings.length)}
                </span>{' '}
                of{' '}
                <span className="font-semibold text-slate-700 dark:text-slate-200">
                  {filteredGroupedFindings.length}
                </span>{' '}
                vulnerability types
              </div>

              {/* Prev / Next & Page buttons */}
              <div className="flex items-center gap-1.5 self-end sm:self-auto">
                <button
                  type="button"
                  disabled={currentPage <= 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Prev</span>
                </button>

                <div className="flex items-center gap-1">
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(
                    (pageNum) => {
                      if (
                        totalPages > 7 &&
                        pageNum !== 1 &&
                        pageNum !== totalPages &&
                        Math.abs(pageNum - currentPage) > 1
                      ) {
                        if (pageNum === 2 || pageNum === totalPages - 1) {
                          return (
                            <span
                              key={pageNum}
                              className="px-1 text-xs text-slate-400 dark:text-slate-500"
                            >
                              …
                            </span>
                          );
                        }
                        return null;
                      }

                      const isActive = pageNum === currentPage;
                      return (
                        <button
                          key={pageNum}
                          type="button"
                          onClick={() => setCurrentPage(pageNum)}
                          className={`h-7 min-w-[28px] rounded-lg px-2 text-xs font-semibold transition ${
                            isActive
                              ? 'border border-brand-600 bg-brand-600 text-white shadow-sm'
                              : 'border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                          }`}
                          aria-current={isActive ? 'page' : undefined}
                        >
                          {pageNum}
                        </button>
                      );
                    }
                  )}
                </div>

                <button
                  type="button"
                  disabled={currentPage >= totalPages}
                  onClick={() =>
                    setCurrentPage((p) => Math.min(totalPages, p + 1))
                  }
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none"
                  aria-label="Next page"
                >
                  <span className="hidden sm:inline">Next</span>
                  <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
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
            No findings match the selected severity filter.
          </p>

          <button
            type="button"
            onClick={() => handleFilterChange('ALL')}
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