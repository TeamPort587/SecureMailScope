import React, { useState, useMemo } from 'react';
import RiskBadge from './RiskBadge';
import EvidencePanel from './EvidencePanel';

import {
  ChevronDown,
  ChevronUp,
  ChevronLeft,
  ChevronRight,
  Terminal,
  ShieldAlert,
  Layers,
  ArrowUpRight,
  Search,
  Hash,
  Activity,
  Network,
  Lightbulb,
  Table,
} from 'lucide-react';

const CHIPS_PER_PAGE = 12;

export default function GroupedFindingCard({
  group,
  sessions = [],
  totalCaptureSessions = 0,
  onSelectSession = null,
  onViewSessionsTab = null,
  onFilterSessionsInTable = null,
}) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [sessionSearch, setSessionSearch] = useState('');
  const [sessionPage, setSessionPage] = useState(1);
  const [selectedSessionId, setSelectedSessionId] = useState(
    group?.affectedSessions?.[0] || null
  );

  const severity = (group?.severity || 'INFO').toUpperCase();

  const severityStyles = {
    CRITICAL: {
      accent: 'bg-red-500',
      icon: 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400',
      soft: 'bg-red-50/50 dark:bg-red-950/30',
      badge: 'border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300',
    },
    HIGH: {
      accent: 'bg-orange-500',
      icon: 'border-orange-200 dark:border-orange-900/60 bg-orange-50 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400',
      soft: 'bg-orange-50/50 dark:bg-orange-950/30',
      badge: 'border-orange-200 dark:border-orange-900/60 bg-orange-50 dark:bg-orange-950/40 text-orange-700 dark:text-orange-300',
    },
    MEDIUM: {
      accent: 'bg-amber-500',
      icon: 'border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400',
      soft: 'bg-amber-50/50 dark:bg-amber-950/30',
      badge: 'border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300',
    },
    LOW: {
      accent: 'bg-yellow-500',
      icon: 'border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 text-yellow-600 dark:text-yellow-400',
      soft: 'bg-yellow-50/50 dark:bg-yellow-950/30',
      badge: 'border-yellow-200 dark:border-yellow-900/60 bg-yellow-50 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-300',
    },
    INFO: {
      accent: 'bg-blue-500',
      icon: 'border-blue-200 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400',
      soft: 'bg-blue-50/50 dark:bg-blue-950/30',
      badge: 'border-blue-200 dark:border-blue-900/60 bg-blue-50 dark:bg-blue-950/40 text-blue-700 dark:text-blue-300',
    },
  };

  const style = severityStyles[severity] || severityStyles.INFO;
  const affectedSessions = group?.affectedSessions || [];
  const findings = group?.findings || [];

  // Percentage of total capture sessions
  const percentImpact = totalCaptureSessions > 0
    ? Math.round((affectedSessions.length / totalCaptureSessions) * 100)
    : null;

  const handleSearchChange = (e) => {
    setSessionSearch(e.target.value);
    setSessionPage(1);
  };

  // Filter affected sessions in search
  const filteredSessions = useMemo(() => {
    if (!sessionSearch.trim()) return affectedSessions;
    const q = sessionSearch.toLowerCase().trim();
    return affectedSessions.filter((sId) => sId.toLowerCase().includes(q));
  }, [affectedSessions, sessionSearch]);

  // Mini-paginated slice of sessions
  const totalSessionPages = Math.ceil(filteredSessions.length / CHIPS_PER_PAGE) || 1;
  const paginatedSessions = useMemo(() => {
    const start = (sessionPage - 1) * CHIPS_PER_PAGE;
    return filteredSessions.slice(start, start + CHIPS_PER_PAGE);
  }, [filteredSessions, sessionPage]);

  // Active finding corresponding to currently selected session
  const activeFinding = useMemo(() => {
    if (!selectedSessionId) return findings[0] || null;
    return (
      findings.find((f) => f.session_id === selectedSessionId) ||
      findings[0] ||
      null
    );
  }, [findings, selectedSessionId]);

  // Session metadata from sessions array
  const activeSessionMeta = useMemo(() => {
    if (!selectedSessionId || !sessions.length) return null;
    return sessions.find((s) => s.session_id === selectedSessionId) || null;
  }, [sessions, selectedSessionId]);

  const handleInspectSession = (sId) => {
    const targetId = sId || selectedSessionId;
    if (!targetId) return;

    if (onSelectSession) {
      onSelectSession(targetId);
      return;
    }

    if (typeof window !== 'undefined') {
      const match = window.location.pathname.match(/\/analysis\/([^/]+)/);
      if (match) {
        window.location.href = `/analysis/${match[1]}/session/${targetId}`;
      }
    }
  };

  const handleViewAllSessions = (e) => {
    if (e) e.stopPropagation();
    if (onFilterSessionsInTable) {
      onFilterSessionsInTable({
        title: group?.title || 'Security Finding',
        sessionIds: affectedSessions,
      });
      return;
    }
    if (onViewSessionsTab) {
      onViewSessionsTab();
      return;
    }
    if (typeof window !== 'undefined') {
      const match = window.location.pathname.match(/\/analysis\/([^/]+)/);
      if (match) {
        window.location.href = `/analysis/${match[1]}?tab=sessions`;
      }
    }
  };

  return (
    <article
      className="
        group relative overflow-hidden
        rounded-xl border border-slate-200 dark:border-slate-800
        bg-white dark:bg-slate-900
        shadow-[0_2px_10px_rgba(15,23,42,0.025)] dark:shadow-[0_2px_10px_rgba(0,0,0,0.3)]
        transition-all duration-200
        hover:border-slate-300 dark:hover:border-slate-700
        hover:shadow-[0_6px_24px_rgba(15,23,42,0.055)]
      "
    >
      {/* Severity accent strip */}
      <div className={`absolute inset-y-0 left-0 w-1.5 ${style.accent}`} />

      {/* Main card body */}
      <div className="p-5 pl-6 sm:p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          
          <div className="flex items-start gap-4">
            {/* Severity icon */}
            <div
              className={`
                flex h-11 w-11 shrink-0
                items-center justify-center
                rounded-xl border
                ${style.icon}
              `}
            >
              <ShieldAlert className="h-5 w-5" />
            </div>

            {/* Title & Badge */}
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <RiskBadge level={severity} size="sm" />

                {/* Affected sessions count badge */}
                <span className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-semibold ${style.badge}`}>
                  <Layers className="h-3.5 w-3.5" />
                  <span>
                    {affectedSessions.length} {affectedSessions.length === 1 ? 'session' : 'sessions'} affected
                  </span>
                </span>

                {/* Percentage of capture */}
                {percentImpact !== null && (
                  <span className="rounded-md border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 text-[10px] font-mono font-medium text-slate-600 dark:text-slate-300">
                    {percentImpact}% of capture
                  </span>
                )}

                {/* Occurrences count if multiple findings in single sessions */}
                {findings.length > affectedSessions.length && (
                  <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                    ({findings.length} occurrences)
                  </span>
                )}
              </div>

              <h3 className="mt-2.5 text-base font-semibold leading-6 text-slate-900 dark:text-white sm:text-[17px]">
                {group?.title || 'Security finding detected'}
              </h3>

              {group?.description && (
                <p className="mt-1.5 max-w-4xl text-xs sm:text-sm leading-6 text-slate-600 dark:text-slate-300">
                  {group.description}
                </p>
              )}
            </div>
          </div>

          {/* Toggle Explorer Button */}
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            aria-expanded={isExpanded}
            className={`
              inline-flex shrink-0 items-center justify-between sm:justify-start gap-2.5
              rounded-xl border px-3.5 py-2.5 text-xs font-semibold
              transition-all duration-200
              ${
                isExpanded
                  ? 'border-brand-200 dark:border-brand-800 bg-brand-50 dark:bg-brand-950/60 text-brand-700 dark:text-brand-300 shadow-sm'
                  : 'border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 text-slate-700 dark:text-slate-200 hover:border-brand-300 dark:hover:border-brand-700 hover:bg-brand-50/50 dark:hover:bg-brand-950/40 hover:text-brand-600 dark:hover:text-brand-300'
              }
            `}
          >
            <div
              className={`
                flex h-7 w-7 items-center justify-center rounded-lg
                ${
                  isExpanded
                    ? 'bg-brand-100 dark:bg-brand-900/60 text-brand-600 dark:text-brand-400'
                    : 'bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-700/60 text-slate-500 dark:text-slate-400'
                }
              `}
            >
              <Terminal className="h-3.5 w-3.5" />
            </div>

            <div className="text-left">
              <p className="leading-4">
                {isExpanded ? 'Hide sessions' : 'Explore sessions'}
              </p>
              <p className="mt-0.5 text-[10px] font-normal text-slate-500 dark:text-slate-400">
                {affectedSessions.length} session{affectedSessions.length !== 1 ? 's' : ''} & evidence
              </p>
            </div>

            {isExpanded ? (
              <ChevronUp className="ml-1 h-3.5 w-3.5 text-brand-500 dark:text-brand-400" />
            ) : (
              <ChevronDown className="ml-1 h-3.5 w-3.5 text-slate-400 dark:text-slate-500" />
            )}
          </button>

        </div>

        {/* Remediation Note if provided */}
        {group?.recommendation && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-brand-100 dark:border-brand-900/40 bg-brand-50/50 dark:bg-brand-950/30 p-3.5">
            <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-brand-600 dark:text-brand-400" />
            <div className="text-xs leading-relaxed text-slate-700 dark:text-slate-300">
              <span className="font-semibold text-brand-700 dark:text-brand-300">
                Remediation:
              </span>{' '}
              {typeof group.recommendation === 'string'
                ? group.recommendation
                : group.recommendation?.title || group.recommendation?.description}
            </div>
          </div>
        )}
      </div>

      {/* Metadata bar */}
      <div className="px-5 pb-5 pl-6 sm:px-6">
        <div className="grid grid-cols-1 gap-2 border-t border-slate-100 dark:border-slate-800 pt-4 sm:grid-cols-2 lg:grid-cols-3">
          {group?.finding_type && (
            <div className="flex items-center gap-2.5 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 px-3.5 py-2.5">
              <Hash className="h-4 w-4 text-slate-400 shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Finding type
                </p>
                <p className="truncate font-mono text-xs font-semibold text-slate-700 dark:text-slate-200">
                  {group.finding_type}
                </p>
              </div>
            </div>
          )}

          <div className="flex items-center gap-2.5 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 px-3.5 py-2.5">
            <Network className="h-4 w-4 text-slate-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Scope of impact
              </p>
              <p className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-200">
                {affectedSessions.length} session{affectedSessions.length !== 1 ? 's' : ''} affected
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 rounded-lg border border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-850 px-3.5 py-2.5">
            <Activity className="h-4 w-4 text-slate-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-[10px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                Confidence
              </p>
              <p className="font-mono text-xs font-semibold text-slate-700 dark:text-slate-200">
                {group?.confidence || 'OBSERVED'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Expandable Affected Sessions & Evidence Drawer */}
      {isExpanded && (
        <div className="border-t border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-850/40 p-5 pl-6 sm:p-6 animate-in fade-in slide-in-from-top-1 duration-200">
          
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex flex-wrap items-center gap-2.5">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                  Affected Sessions ({affectedSessions.length})
                </h4>

                {affectedSessions.length > 5 && (
                  <button
                    type="button"
                    onClick={handleViewAllSessions}
                    className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 text-[11px] font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 shadow-sm transition-all"
                    title="Open full interactive reconstructed sessions table"
                  >
                    <Table className="h-3 w-3" />
                    <span>Open in Sessions table</span>
                    <ArrowUpRight className="h-3 w-3" />
                  </button>
                )}
              </div>

              <p className="mt-0.5 text-[11px] text-slate-500 dark:text-slate-400">
                Select any session below to inspect its extracted packet evidence and connection metadata.
              </p>
            </div>

            {/* Search if more than 4 sessions */}
            {affectedSessions.length > 4 && (
              <div className="relative w-full sm:w-56">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  placeholder="Filter sessions..."
                  value={sessionSearch}
                  onChange={handleSearchChange}
                  className="h-8 w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 pl-8 pr-2.5 text-xs text-slate-700 dark:text-slate-200 placeholder:text-slate-400 focus:border-brand-500 focus:outline-none"
                />
              </div>
            )}
          </div>

          {/* Mini-paginated Session Chips */}
          <div className="mb-2.5 flex flex-wrap gap-1.5">
            {paginatedSessions.length > 0 ? (
              paginatedSessions.map((sId) => {
                const isSelected = sId === (selectedSessionId || affectedSessions[0]);
                return (
                  <button
                    key={sId}
                    type="button"
                    onClick={() => setSelectedSessionId(sId)}
                    className={`
                      inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-mono font-medium transition-all
                      ${
                        isSelected
                          ? 'border-brand-500 bg-brand-50 dark:bg-brand-950/70 text-brand-700 dark:text-brand-300 shadow-sm font-semibold'
                          : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-600'
                      }
                    `}
                  >
                    <span>{sId}</span>
                    {isSelected && (
                      <span className="h-1.5 w-1.5 rounded-full bg-brand-600 dark:bg-brand-400" />
                    )}
                  </button>
                );
              })
            ) : (
              <p className="text-xs text-slate-400 italic py-1">
                No sessions match "{sessionSearch}"
              </p>
            )}
          </div>

          {/* Mini Pagination Footer for Session Chips */}
          {filteredSessions.length > CHIPS_PER_PAGE && (
            <div className="mb-4 flex items-center justify-between border-t border-slate-200/80 dark:border-slate-800 pt-2 text-[11px] text-slate-500 dark:text-slate-400">
              <span>
                Showing <span className="font-semibold text-slate-700 dark:text-slate-200">{(sessionPage - 1) * CHIPS_PER_PAGE + 1}–{Math.min(sessionPage * CHIPS_PER_PAGE, filteredSessions.length)}</span> of <span className="font-semibold text-slate-700 dark:text-slate-200">{filteredSessions.length}</span>
              </span>

              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  disabled={sessionPage <= 1}
                  onClick={() => setSessionPage((p) => Math.max(1, p - 1))}
                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:pointer-events-none"
                  aria-label="Previous sessions page"
                >
                  <ChevronLeft className="h-3 w-3" />
                  <span>Prev</span>
                </button>

                <span className="font-mono text-[10px] text-slate-500 dark:text-slate-400 px-1">
                  {sessionPage} / {totalSessionPages}
                </span>

                <button
                  type="button"
                  disabled={sessionPage >= totalSessionPages}
                  onClick={() => setSessionPage((p) => Math.min(totalSessionPages, p + 1))}
                  className="inline-flex items-center gap-1 rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 px-2 py-0.5 font-medium text-slate-700 dark:text-slate-300 shadow-sm transition hover:bg-slate-50 dark:hover:bg-slate-800 disabled:opacity-40 disabled:pointer-events-none"
                  aria-label="Next sessions page"
                >
                  <span>Next</span>
                  <ChevronRight className="h-3 w-3" />
                </button>
              </div>
            </div>
          )}

          {/* Active Session Evidence & Inspection Bar */}
          {activeFinding && (
            <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 p-4 shadow-sm">
              <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center gap-2.5">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  <span className="font-mono text-xs font-bold text-slate-900 dark:text-white">
                    {activeFinding.session_id}
                  </span>
                  {activeSessionMeta?.tcp_stream !== undefined && (
                    <span className="rounded bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-500 dark:text-slate-400">
                      Stream #{activeSessionMeta.tcp_stream}
                    </span>
                  )}
                  {activeSessionMeta?.protocol && (
                    <span className="rounded bg-brand-50 dark:bg-brand-950/50 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-brand-600 dark:text-brand-400">
                      {activeSessionMeta.protocol}
                    </span>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => handleInspectSession(activeFinding.session_id)}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:text-brand-700 dark:hover:text-brand-300 transition-colors"
                >
                  <span>Inspect session</span>
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              </div>

              {/* Technical evidence for this selected session */}
              <EvidencePanel evidence={activeFinding.evidence} />
            </div>
          )}

        </div>
      )}
    </article>
  );
}
