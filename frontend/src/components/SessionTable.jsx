import React, { useMemo, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Layers,
  Search,
  Eye,
  ShieldCheck,
  ShieldAlert,
  X,
  ChevronLeft,
  ChevronRight,
  ArrowUp,
  ArrowDown,
  ArrowUpDown,
  Loader2,
  RotateCcw,
} from 'lucide-react';

import { formatEncryptionMode } from '../utils/formatters';
import { analysisApi } from '../api/analysisApi';
import SessionDetails from './SessionDetails';

const PAGE_SIZE = 15;

export default function SessionTable({
  sessions = [],
  findings = [],
  analysisId = null,
  onSelectSession = null,
}) {
  const navigate = useNavigate();
  const [selectedSession, setSelectedSession] = useState(null);

  // Filters & Search
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [encryptionFilter, setEncryptionFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  // Sorting
  const [sortBy, setSortBy] = useState('tcp_stream');
  const [sortOrder, setSortOrder] = useState('ASC');

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);

  // Server-side State
  const [serverData, setServerData] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  // Debounce search input
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedSearch(searchQuery.trim());
      setCurrentPage(1);
    }, 250);
    return () => clearTimeout(handler);
  }, [searchQuery]);

  // Vulnerable session map from findings
  const vulnerableSessionMap = useMemo(() => {
    const map = new Set();
    (findings || []).forEach((finding) => {
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        if (finding.session_id) {
          map.add(finding.session_id);
        }
      }
    });
    return map;
  }, [findings]);

  // Fetch paginated sessions from server when analysisId is provided
  useEffect(() => {
    if (!analysisId) return;

    let isMounted = true;
    setIsLoading(true);

    analysisApi
      .getSessions(analysisId, {
        page: currentPage,
        limit: PAGE_SIZE,
        search: debouncedSearch,
        protocol: protocolFilter,
        encryption: encryptionFilter,
        risk: riskFilter,
        sortBy,
        sortOrder,
      })
      .then((data) => {
        if (isMounted) {
          setServerData(data);
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [
    analysisId,
    currentPage,
    debouncedSearch,
    protocolFilter,
    encryptionFilter,
    riskFilter,
    sortBy,
    sortOrder,
  ]);

  // Client-side fallback filtering & sorting
  const clientFilteredSessions = useMemo(() => {
    const query = debouncedSearch.toLowerCase();

    const filtered = (sessions || []).filter((session) => {
      const protocol = (session.protocol || '').toUpperCase();
      const encryption = (session.security?.encryption_mode || '').toUpperCase();
      const sessionRisk = (
        session.risk?.level ||
        session.risk_label ||
        (vulnerableSessionMap.has(session.session_id) ? 'HIGH' : 'LOW')
      ).toUpperCase();

      const matchProtocol = protocolFilter === 'ALL' || protocol === protocolFilter;
      const matchEncryption = encryptionFilter === 'ALL' || encryption === encryptionFilter;
      const matchRisk = riskFilter === 'ALL' || sessionRisk === riskFilter;

      const matchSearch =
        !query ||
        (session.session_id || '').toLowerCase().includes(query) ||
        (session.client_ip || '').toLowerCase().includes(query) ||
        (session.server_ip || '').toLowerCase().includes(query) ||
        (session.protocol || '').toLowerCase().includes(query) ||
        (session.service || '').toLowerCase().includes(query);

      return matchProtocol && matchEncryption && matchRisk && matchSearch;
    });

    const multiplier = sortOrder === 'DESC' ? -1 : 1;
    return [...filtered].sort((a, b) => {
      if (sortBy === 'session_id') {
        return (a.session_id || '').localeCompare(b.session_id || '') * multiplier;
      }
      if (sortBy === 'protocol') {
        return (a.protocol || '').localeCompare(b.protocol || '') * multiplier;
      }
      if (sortBy === 'risk') {
        const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
        const rA = rank[(a.risk?.level || a.risk_label || 'LOW').toUpperCase()] || 0;
        const rB = rank[(b.risk?.level || b.risk_label || 'LOW').toUpperCase()] || 0;
        return (rA - rB) * multiplier;
      }
      if (sortBy === 'encryption') {
        return (
          (a.security?.encryption_mode || '').localeCompare(b.security?.encryption_mode || '') *
          multiplier
        );
      }
      return ((a.tcp_stream ?? 0) - (b.tcp_stream ?? 0)) * multiplier;
    });
  }, [
    sessions,
    debouncedSearch,
    protocolFilter,
    encryptionFilter,
    riskFilter,
    sortBy,
    sortOrder,
    vulnerableSessionMap,
  ]);

  const clientPaginatedSessions = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return clientFilteredSessions.slice(start, start + PAGE_SIZE);
  }, [clientFilteredSessions, currentPage]);

  // Determine whether server-side data is active
  const isServerSide = Boolean(analysisId && serverData);

  const displaySessions = isServerSide
    ? serverData.items || []
    : clientPaginatedSessions;

  const totalSessions = isServerSide
    ? serverData.pagination.total
    : clientFilteredSessions.length;

  const totalPages = isServerSide
    ? serverData.pagination.totalPages
    : Math.ceil(clientFilteredSessions.length / PAGE_SIZE) || 1;

  const grandTotal = sessions?.length || totalSessions;

  const hasCustomSort = sortBy !== 'tcp_stream' || sortOrder !== 'ASC';
  const hasActiveFilters =
    protocolFilter !== 'ALL' ||
    encryptionFilter !== 'ALL' ||
    riskFilter !== 'ALL' ||
    searchQuery.trim() !== '';

  const hasModifications = hasActiveFilters || hasCustomSort;

  const clearFilters = () => {
    setProtocolFilter('ALL');
    setEncryptionFilter('ALL');
    setRiskFilter('ALL');
    setSearchQuery('');
    setDebouncedSearch('');
    setCurrentPage(1);
  };

  const resetAll = () => {
    setProtocolFilter('ALL');
    setEncryptionFilter('ALL');
    setRiskFilter('ALL');
    setSearchQuery('');
    setDebouncedSearch('');
    setSortBy('tcp_stream');
    setSortOrder('ASC');
    setCurrentPage(1);
  };

  const handleSort = (key) => {
    if (sortBy !== key) {
      setSortBy(key);
      setSortOrder('ASC');
    } else if (sortOrder === 'ASC') {
      setSortOrder('DESC');
    } else {
      // 3rd click: Clear sort back to default natural stream order
      setSortBy('tcp_stream');
      setSortOrder('ASC');
    }
    setCurrentPage(1);
  };

  const handleInspect = (session) => {
    if (onSelectSession) {
      onSelectSession(session);
      return;
    }
    if (analysisId) {
      navigate(`/analysis/${analysisId}/session/${session.session_id}`, {
        state: { session, analysisId, findings },
      });
      return;
    }
    // Fallback if no analysisId is provided
    setSelectedSession(session);
  };

  return (
    <section className="w-full">
      {/* =========================================================
          HEADER
      ========================================================== */}
      <div className="mb-4 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="min-w-0 shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-brand-100 bg-brand-50">
              <Layers className="h-4 w-4 text-brand-600" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-900">
                  Reconstructed sessions
                </h3>
                {isLoading && (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-brand-600" />
                )}
              </div>
              <p className="mt-0.5 text-[11px] text-slate-500">
                Email connections reconstructed from the packet capture
              </p>
            </div>
          </div>
        </div>

        {/* =======================================================
            FILTERS
        ======================================================== */}
        <div className="flex flex-wrap items-center gap-2 sm:flex-nowrap">
          {/* SEARCH */}
          <div className="relative w-full sm:w-60 md:w-72 lg:w-80 shrink-0 min-w-[200px]">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search sessions..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-9 w-full rounded-xl border border-slate-200 bg-white pl-9 pr-3 text-xs text-slate-700 shadow-sm transition placeholder:text-slate-400 hover:border-slate-300 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10"
              aria-label="Search sessions"
            />
          </div>

          {/* PROTOCOL */}
          <select
            value={protocolFilter}
            onChange={(e) => {
              setProtocolFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 shadow-sm transition hover:border-slate-300 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10 cursor-pointer shrink-0"
            aria-label="Filter by protocol"
          >
            <option value="ALL">All protocols</option>
            <option value="SMTP">SMTP</option>
            <option value="IMAP">IMAP</option>
            <option value="POP3">POP3</option>
          </select>

          {/* ENCRYPTION */}
          <select
            value={encryptionFilter}
            onChange={(e) => {
              setEncryptionFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 shadow-sm transition hover:border-slate-300 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10 cursor-pointer shrink-0"
            aria-label="Filter by encryption"
          >
            <option value="ALL">All encryption</option>
            <option value="STARTTLS">STARTTLS</option>
            <option value="IMPLICIT_TLS">Implicit TLS</option>
            <option value="PLAINTEXT">Plaintext</option>
          </select>

          {/* RISK */}
          <select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-700 shadow-sm transition hover:border-slate-300 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/10 cursor-pointer shrink-0"
            aria-label="Filter by risk"
          >
            <option value="ALL">All risk levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {hasModifications && (
            <button
              type="button"
              onClick={resetAll}
              className="h-9 inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 text-xs font-medium text-slate-600 shadow-sm hover:bg-slate-50 hover:border-slate-300 transition shrink-0"
              title="Reset all filters and sorting"
              aria-label="Reset all filters and sorting"
            >
              <RotateCcw className="h-3.5 w-3.5 text-slate-400" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* =========================================================
          TABLE
      ========================================================== */}
      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/80">
                <TableHeader
                  sortKey="session_id"
                  currentSort={sortBy}
                  currentOrder={sortOrder}
                  onSort={handleSort}
                >
                  Session
                </TableHeader>

                <TableHeader
                  sortKey="risk"
                  currentSort={sortBy}
                  currentOrder={sortOrder}
                  onSort={handleSort}
                >
                  Risk
                </TableHeader>

                <TableHeader
                  sortKey="protocol"
                  currentSort={sortBy}
                  currentOrder={sortOrder}
                  onSort={handleSort}
                >
                  Protocol
                </TableHeader>

                <TableHeader>
                  Connection
                </TableHeader>

                <TableHeader
                  sortKey="encryption"
                  currentSort={sortBy}
                  currentOrder={sortOrder}
                  onSort={handleSort}
                >
                  Encryption
                </TableHeader>

                <TableHeader>TLS</TableHeader>
                <TableHeader>PFS</TableHeader>
                <TableHeader>Completeness</TableHeader>
                <TableHeader>Security posture</TableHeader>
                <TableHeader align="right">Action</TableHeader>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-100">
              {displaySessions.length > 0 ? (
                displaySessions.map((session) => {
                  const encryption = formatEncryptionMode(
                    session.security?.encryption_mode
                  );

                  const isVulnerable =
                    vulnerableSessionMap.has(session.session_id) ||
                    session.security?.authentication_before_tls === 'YES' ||
                    session.security?.encryption_mode === 'PLAINTEXT';

                  return (
                    <SessionRow
                      key={session.session_id}
                      session={session}
                      encryption={encryption}
                      isVulnerable={isVulnerable}
                      onInspect={() => handleInspect(session)}
                    />
                  );
                })
              ) : (
                <tr>
                  <td colSpan="10" className="px-6 py-14 text-center">
                    <div className="mx-auto flex max-w-xs flex-col items-center">
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-slate-50">
                        <Search className="h-4 w-4 text-slate-400" />
                      </div>

                      <p className="mt-3 text-xs font-semibold text-slate-800">
                        No matching sessions
                      </p>

                      <p className="mt-1 text-[11px] leading-5 text-slate-500">
                        Try changing the search term or clearing the active filters.
                      </p>

                      {hasActiveFilters && (
                        <button
                          type="button"
                          onClick={clearFilters}
                          className="mt-3 text-[11px] font-semibold text-brand-600 hover:text-brand-700"
                        >
                          Clear filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* =======================================================
            PAGINATION & TABLE FOOTER
        ======================================================== */}
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-t border-slate-100 bg-slate-50/50 px-4 py-3.5">
          <div className="flex items-center gap-2 text-xs text-slate-500">
            {totalSessions > 0 ? (
              <span>
                Showing{' '}
                <span className="font-semibold text-slate-700">
                  {(currentPage - 1) * PAGE_SIZE + 1}
                </span>{' '}
                to{' '}
                <span className="font-semibold text-slate-700">
                  {Math.min(currentPage * PAGE_SIZE, totalSessions)}
                </span>{' '}
                of{' '}
                <span className="font-semibold text-slate-700">
                  {totalSessions}
                </span>{' '}
                sessions
              </span>
            ) : (
              <span>0 sessions</span>
            )}
          </div>

          {/* PAGE BUTTONS */}
          {totalPages > 1 && (
            <div className="flex items-center gap-1.5 self-end sm:self-auto">
              <button
                type="button"
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-40 disabled:pointer-events-none"
                aria-label="Previous page"
              >
                <ChevronLeft className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Prev</span>
              </button>

              <div className="flex items-center gap-1">
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => {
                  if (
                    totalPages > 7 &&
                    pageNum !== 1 &&
                    pageNum !== totalPages &&
                    Math.abs(pageNum - currentPage) > 1
                  ) {
                    if (pageNum === 2 || pageNum === totalPages - 1) {
                      return (
                        <span key={pageNum} className="px-1 text-xs text-slate-400">
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
                          : 'border border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                      }`}
                      aria-current={isActive ? 'page' : undefined}
                    >
                      {pageNum}
                    </button>
                  );
                })}
              </div>

              <button
                type="button"
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-40 disabled:pointer-events-none"
                aria-label="Next page"
              >
                <span className="hidden sm:inline">Next</span>
                <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>

      {/* =========================================================
          SESSION DETAILS MODAL (FALLBACK ONLY)
      ========================================================== */}
      {selectedSession && (
        <SessionDetails
          session={selectedSession}
          analysisId={analysisId}
          findings={findings}
          onClose={() => setSelectedSession(null)}
        />
      )}
    </section>
  );
}

/* ===============================================================
   TABLE HEADER
=============================================================== */
function TableHeader({
  children,
  align = 'left',
  sortKey = null,
  currentSort = null,
  currentOrder = 'ASC',
  onSort = null,
}) {
  const isSortable = Boolean(sortKey && onSort);
  const isActive = isSortable && currentSort === sortKey;

  const getSortTooltip = () => {
    if (!isSortable) return undefined;
    if (!isActive) return `Sort by ${children} (ascending)`;
    if (currentOrder === 'ASC') return `Sort by ${children} (descending)`;
    return 'Click to remove sort';
  };

  return (
    <th
      scope="col"
      className={`px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.08em] select-none ${
        align === 'right' ? 'text-right' : 'text-left'
      } ${
        isSortable
          ? 'cursor-pointer transition-colors hover:text-slate-900'
          : 'text-slate-500'
      } ${isActive ? 'text-brand-900 bg-brand-50/50' : ''}`}
      onClick={isSortable ? () => onSort(sortKey) : undefined}
      title={getSortTooltip()}
      aria-sort={
        isActive
          ? currentOrder === 'ASC'
            ? 'ascending'
            : 'descending'
          : undefined
      }
    >
      <div className={`inline-flex items-center gap-1.5 ${align === 'right' ? 'justify-end' : ''}`}>
        <span>{children}</span>
        {isSortable && (
          <span
            className={`shrink-0 transition-colors ${
              isActive ? 'text-brand-600' : 'text-slate-400 opacity-40 hover:opacity-100'
            }`}
          >
            {isActive ? (
              currentOrder === 'DESC' ? (
                <ArrowDown className="h-3 w-3 stroke-[2.5]" />
              ) : (
                <ArrowUp className="h-3 w-3 stroke-[2.5]" />
              )
            ) : (
              <ArrowUpDown className="h-3 w-3" />
            )}
          </span>
        )}
      </div>
    </th>
  );
}

/* ===============================================================
   SESSION ROW
=============================================================== */
function SessionRow({
  session,
  encryption,
  isVulnerable,
  onInspect,
}) {
  const riskLevel =
    session.risk?.level ||
    session.risk_label ||
    (isVulnerable ? 'HIGH' : 'LOW');

  const completeness =
    session.security?.capture_completeness || 'COMPLETE';

  return (
    <tr
      onClick={onInspect}
      className="group cursor-pointer transition-colors hover:bg-slate-50"
    >
      {/* SESSION */}
      <td className="px-4 py-4">
        <div className="flex items-center gap-3">
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || isVulnerable
                ? 'bg-red-500'
                : 'bg-emerald-500'
            }`}
          />

          <div className="min-w-0">
            <p
              className="max-w-[180px] truncate font-mono text-xs font-semibold text-slate-800"
              title={session.session_id}
            >
              {session.session_id || '—'}
            </p>

            <p className="mt-0.5 text-[10px] text-slate-400 font-mono">
              {session.tcp_stream !== null && session.tcp_stream !== undefined
                ? `Stream #${session.tcp_stream}`
                : 'Click to open session page'}
            </p>
          </div>
        </div>
      </td>

      {/* RISK */}
      <td className="px-4 py-4">
        <span
          className={`inline-flex rounded-md border px-2 py-0.5 font-mono text-[10px] font-bold ${
            riskLevel === 'CRITICAL'
              ? 'border-red-200 bg-red-50 text-red-700'
              : riskLevel === 'HIGH'
              ? 'border-orange-200 bg-orange-50 text-orange-700'
              : riskLevel === 'MEDIUM'
              ? 'border-amber-200 bg-amber-50 text-amber-700'
              : 'border-emerald-200 bg-emerald-50 text-emerald-700'
          }`}
        >
          {riskLevel}
        </span>
      </td>

      {/* PROTOCOL */}
      <td className="px-4 py-4">
        <div>
          <span className="inline-flex rounded-md border border-slate-200 bg-slate-50 px-2 py-1 font-mono text-[10px] font-semibold text-slate-700">
            {session.protocol || '—'}
          </span>

          {session.service && (
            <p className="mt-1.5 text-[10px] text-slate-400">
              {session.service}
            </p>
          )}
        </div>
      </td>

      {/* CONNECTION */}
      <td className="px-4 py-4">
        <div className="space-y-1.5">
          <Endpoint
            label="C"
            ip={session.client_ip}
            port={session.client_port}
          />

          <Endpoint
            label="S"
            ip={session.server_ip}
            port={session.server_port}
          />
        </div>
      </td>

      {/* ENCRYPTION */}
      <td className="px-4 py-4">
        <EncryptionBadge encryption={encryption} />
      </td>

      {/* TLS */}
      <td className="px-4 py-4">
        {session.tls?.version ? (
          <span className="font-mono text-[11px] font-semibold text-slate-700">
            {session.tls.version}
          </span>
        ) : (
          <span className="text-xs text-slate-300">—</span>
        )}
      </td>

      {/* PFS */}
      <td className="px-4 py-4">
        {session.tls?.pfs === 'YES' ? (
          <span className="inline-flex items-center gap-1.5 text-[10px] font-semibold text-yellow-700">
            <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
            Yes
          </span>
        ) : session.tls?.pfs ? (
          <span className="text-[10px] font-medium text-slate-500">
            {session.tls.pfs}
          </span>
        ) : (
          <span className="text-xs text-slate-300">—</span>
        )}
      </td>

      {/* COMPLETENESS */}
      <td className="px-4 py-4">
        <span
          className={`inline-flex rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold ${
            completeness === 'PARTIAL'
              ? 'border-amber-200 bg-amber-50 text-amber-700'
              : completeness === 'COMPLETE'
              ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
              : 'border-slate-200 bg-slate-50 text-slate-600'
          }`}
        >
          {completeness}
        </span>
      </td>

      {/* POSTURE */}
      <td className="px-4 py-4">
        {isVulnerable ? (
          <span className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-2.5 py-1.5">
            <ShieldAlert className="h-3.5 w-3.5 text-red-600" />
            <span className="text-[10px] font-semibold text-red-700">
              Vulnerable
            </span>
          </span>
        ) : (
          <span className="inline-flex items-center gap-2 rounded-lg border border-yellow-200 bg-yellow-50 px-2.5 py-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-yellow-600" />
            <span className="text-[10px] font-semibold text-yellow-700">
              Protected
            </span>
          </span>
        )}
      </td>

      {/* ACTION */}
      <td className="px-4 py-4 text-right">
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            onInspect();
          }}
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-[10px] font-semibold text-slate-600 shadow-sm transition-all hover:border-brand-200 hover:bg-brand-50 hover:text-brand-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/20"
          aria-label={`Inspect session ${session.session_id}`}
        >
          <Eye className="h-3.5 w-3.5 text-brand-600" />
          Inspect
        </button>
      </td>
    </tr>
  );
}

/* ===============================================================
   ENCRYPTION BADGE
=============================================================== */
function EncryptionBadge({ encryption }) {
  const label = encryption?.label || 'Unknown';
  const normalized = label.toUpperCase().replace(/\s+/g, '_');

  let classes = 'border-slate-200 bg-slate-50 text-slate-600';

  if (normalized.includes('PLAINTEXT')) {
    classes = 'border-red-200 bg-red-50 text-red-700';
  } else if (normalized.includes('STARTTLS')) {
    classes = 'border-sky-200 bg-sky-50 text-sky-700';
  } else if (normalized.includes('TLS')) {
    classes = 'border-yellow-200 bg-yellow-50 text-yellow-700';
  }

  return (
    <span
      className={`inline-flex rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold ${classes}`}
    >
      {label}
    </span>
  );
}

/* ===============================================================
   ENDPOINT
=============================================================== */
function Endpoint({ label, ip, port }) {
  return (
    <div className="flex items-center gap-2">
      <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded bg-slate-100 font-mono text-[8px] font-semibold text-slate-500">
        {label}
      </span>

      <span className="font-mono text-[10px] text-slate-600" title={ip}>
        {ip || '—'}
      </span>

      {port && (
        <span className="font-mono text-[10px] text-slate-400">
          :{port}
        </span>
      )}
    </div>
  );
}