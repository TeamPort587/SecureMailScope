import React, { useEffect, useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  FileSearch,
  ArrowRight,
  Activity,
  ShieldAlert,
  Database,
  Plus,
  Clock,
  Server,
  AlertTriangle,
  CheckCircle2,
  Search,
  Calendar,
  X,
  ChevronLeft,
  ChevronRight,
  Loader2,
} from 'lucide-react';

import { analysisApi } from '../api/analysisApi';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export default function AnalysisOverview() {
  const navigate = useNavigate();

  const [analyses, setAnalyses] = useState([]);
  const [pagination, setPagination] = useState({ page: 1, limit: 10, total: 0, totalPages: 1 });
  const [stats, setStats] = useState({ totalAnalyses: 0, highRiskCount: 0, totalSessions: 0, totalFindings: 0 });
  const [loading, setLoading] = useState(true);
  const [isFetching, setIsFetching] = useState(false);
  const [error, setError] = useState(null);

  // Search, Date Filter & Pagination state
  const [searchTerm, setSearchTerm] = useState('');
  const [searchDate, setSearchDate] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 10;

  const isFirstRender = useRef(true);

  const loadAnalyses = async (page = 1, search = '', date = '', isInitial = false) => {
    if (isInitial) {
      setLoading(true);
    } else {
      setIsFetching(true);
    }

    setError(null);

    try {
      const data = await analysisApi.getAnalyses(page, ITEMS_PER_PAGE, search, date);

      setAnalyses(data?.items || []);
      setPagination(data?.pagination || { page, limit: ITEMS_PER_PAGE, total: 0, totalPages: 1 });

      if (data?.stats) {
        setStats(data.stats);
      } else {
        setStats((prev) => ({
          ...prev,
          totalAnalyses: data?.pagination?.total || data?.items?.length || 0,
        }));
      }
    } catch (err) {
      setError(
        err.message ||
        'Failed to load available analyses.'
      );
    } finally {
      setLoading(false);
      setIsFetching(false);
    }
  };

  // Initial load
  useEffect(() => {
    loadAnalyses(1, '', '', true);
  }, []);

  // Debounced server search / date / page change
  useEffect(() => {
    if (isFirstRender.current) {
      isFirstRender.current = false;
      return;
    }

    const timer = setTimeout(() => {
      loadAnalyses(currentPage, searchTerm, searchDate, false);
    }, 280);

    return () => clearTimeout(timer);
  }, [currentPage, searchTerm, searchDate]);

  const handleSearchChange = (val) => {
    setSearchTerm(val);
    setCurrentPage(1);
  };

  const handleDateChange = (val) => {
    setSearchDate(val);
    setCurrentPage(1);
  };

  const handleClearFilters = () => {
    setSearchTerm('');
    setSearchDate('');
    setCurrentPage(1);
  };

  const totalPages = pagination.totalPages || 1;

  const getRiskClass = (level) => {
    const risk = String(level || '').toLowerCase();

    if (risk === 'critical') {
      return 'border-rose-200 bg-rose-50 text-rose-700';
    }

    if (risk === 'high') {
      return 'border-orange-200 bg-orange-50 text-orange-700';
    }

    if (risk === 'medium') {
      return 'border-amber-200 bg-amber-50 text-amber-700';
    }

    if (risk === 'low') {
      return 'border-yellow-200 bg-yellow-50 text-yellow-700';
    }

    return 'border-brand-200 bg-brand-50 text-brand-700';
  };

  if (loading) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <LoadingState
          message="Loading Analysis Workspace..."
          subtext="Retrieving available security analysis records."
        />
      </div>
    );
  }

  if (error) {
    return (
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        <ErrorState
          title="Unable to Load Analyses"
          message={error}
          onRetry={loadAnalyses}
        />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-7 sm:px-6 lg:px-8">

      {/* PAGE HEADER HERO */}
      <div className="mb-8">
        <div className="
          relative overflow-hidden
          rounded-2xl border border-slate-100 dark:border-slate-800/80
          bg-gradient-to-br from-white via-slate-50/80 to-brand-50/40
          dark:from-slate-900/90 dark:via-slate-900/80 dark:to-slate-950/90
          px-6 py-2 sm:px-8 sm:py-3
          shadow-sm dark:shadow-soft-dark
          border-l-2 border-t-2 border-brand-200/60 dark:border-l-brand-500/40 dark:border-t-brand-500/40
        ">
          {/* orb glows */}
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute -left-16 -top-16 h-72 w-72 rounded-full bg-brand-400/[0.07] blur-[100px]" />
            <div className="absolute right-0 -top-8 h-72 w-72 rounded-full bg-sky-200/[0.12] blur-[90px]" />
            <div className="absolute -bottom-12 left-1/3 h-52 w-52 rounded-full bg-brand-300/[0.06] blur-[80px]" />
            <div className="absolute bottom-0 right-0 h-52 w-52 rounded-full bg-blue-100/[0.18] blur-[70px]" />
          </div>

          {/* dot grid */}
          <div
            className="pointer-events-none absolute inset-0 opacity-[0.018]"
            style={{
              backgroundImage: 'radial-gradient(circle, #334155 1px, transparent 1px)',
              backgroundSize: '26px 26px',
            }}
          />

          {/* top hairline */}
          <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-brand-400/30 to-transparent" />


          {/* content */}
          <div className="relative flex items-center justify-between gap-8">

            {/* LEFT — text & CTA */}
            <div className="max-w-xl py-2">

              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-100 dark:border-brand-800/60 bg-brand-50/80 dark:bg-brand-950/60 px-3 py-1 backdrop-blur-sm">
                <FileSearch className="h-3 w-3 text-brand-500 dark:text-brand-400" />
                <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-brand-600 dark:text-brand-300">
                  Security Workspace
                </span>
              </div>

              <h1 className="text-3xl font-bold leading-tight tracking-tight text-slate-900 dark:text-white sm:text-4xl">
                Analysis{' '}
                <span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent">
                  Center
                </span>
              </h1>

              <p className="mt-3 max-w-md text-sm leading-6 text-slate-500 dark:text-slate-400">
                Review completed email security analyses, inspect captured
                sessions, investigate findings, and track the overall
                security posture of your network traffic.
              </p>

              <div className="mt-5">
                <Link
                  to="/"
                  className="inline-flex items-center gap-2 rounded-xl bg-brand-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm transition-all hover:bg-brand-700 hover:shadow-md active:scale-[0.98]"
                >
                  <Plus className="h-3.5 w-3.5" />
                  New Analysis
                </Link>
              </div>

            </div>

            {/* RIGHT — SVG illustration */}
            <div className="pointer-events-none hidden shrink-0 lg:block">
              <svg
                width="220" height="180"
                viewBox="0 0 220 180"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                className="opacity-[0.55]"
              >
                <circle cx="110" cy="90" r="82" stroke="#3b82f6" strokeWidth="0.6" strokeDasharray="4 6" opacity="0.25" />
                <circle cx="110" cy="90" r="66" stroke="#3b82f6" strokeWidth="0.5" strokeDasharray="2 8" opacity="0.15" />

                {/* shield */}
                <path d="M110 42 L148 58 L148 96 C148 118 110 138 110 138 C110 138 72 118 72 96 L72 58 Z"
                  fill="#eff6ff" stroke="#bfdbfe" strokeWidth="1.4" strokeLinejoin="round" className="hero-shield-body" />

                {/* shield checkmark */}
                <path d="M94 90 L105 101 L126 78"
                  stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" fill="none" />

                {/* scan lines left */}
                <line x1="46" y1="80" x2="66" y2="80" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                <line x1="46" y1="90" x2="62" y2="90" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                <line x1="46" y1="100" x2="66" y2="100" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />

                {/* scan lines right */}
                <line x1="154" y1="80" x2="174" y2="80" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                <line x1="158" y1="90" x2="174" y2="90" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                <line x1="154" y1="100" x2="174" y2="100" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />

                {/* stat badge top-right */}
                <rect x="138" y="38" width="46" height="18" rx="5" fill="#dbeafe" stroke="#93c5fd" strokeWidth="1" className="hero-badge-bg" />
                <text x="161" y="51" textAnchor="middle" fontSize="7" fontWeight="700" fill="#2563eb" fontFamily="monospace" className="hero-badge-text">ANALYSIS</text>

                {/* floating dots */}
                <circle cx="34" cy="54" r="3" fill="#bfdbfe" opacity="0.5" />
                <circle cx="186" cy="126" r="2.5" fill="#93c5fd" opacity="0.4" />
                <circle cx="172" cy="48" r="2" fill="#60a5fa" opacity="0.35" />
                <circle cx="44" cy="138" r="2" fill="#bfdbfe" opacity="0.4" />

                {/* signal arcs */}
                <path d="M26 80 a18 18 0 0 1 0-20" stroke="#93c5fd" strokeWidth="1.2" strokeLinecap="round" fill="none" opacity="0.4" />
                <path d="M20 84 a26 26 0 0 1 0-28" stroke="#bfdbfe" strokeWidth="0.9" strokeLinecap="round" fill="none" opacity="0.3" />
              </svg>
            </div>

          </div>
        </div>
      </div>


      {/* STATS */}
      <div className="mb-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={<Database className="h-5 w-5" />}
          label="Total Analyses"
          value={stats.totalAnalyses}
          description="Available security reports"
          iconBg="bg-brand-100 dark:bg-brand-950/70"
          iconText="text-brand-600 dark:text-brand-400"
          glow="shadow-[0_0_18px_4px_rgba(14,165,233,0.13)]"
          topBar="from-brand-300 via-brand-400 to-brand-300"
        />
        <StatCard
          icon={<ShieldAlert className="h-5 w-5" />}
          label="High / Critical Risk"
          value={stats.highRiskCount}
          description="Elevated risk posture"
          iconBg="bg-rose-100 dark:bg-rose-950/70"
          iconText="text-rose-600 dark:text-rose-400"
          glow="shadow-[0_0_18px_4px_rgba(239,68,68,0.13)]"
          topBar="from-rose-300 via-rose-400 to-rose-300"
        />
        <StatCard
          icon={<Activity className="h-5 w-5" />}
          label="Captured Sessions"
          value={stats.totalSessions}
          description="Across all analyses"
          iconBg="bg-sky-100 dark:bg-sky-950/70"
          iconText="text-sky-600 dark:text-sky-400"
          glow="shadow-[0_0_18px_4px_rgba(14,165,233,0.13)]"
          topBar="from-sky-300 via-sky-400 to-sky-300"
        />
        <StatCard
          icon={<AlertTriangle className="h-5 w-5" />}
          label="Security Findings"
          value={stats.totalFindings}
          description="Issues requiring review"
          iconBg="bg-amber-100 dark:bg-amber-950/70"
          iconText="text-amber-600 dark:text-amber-400"
          glow="shadow-[0_0_18px_4px_rgba(245,158,11,0.13)]"
          topBar="from-amber-300 via-amber-400 to-amber-300"
        />
      </div>


      {/* ANALYSIS RECORDS */}
      <div className="overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">

        {/* SECTION HEADER & TOOLBAR */}
        <div className="flex flex-col gap-4 border-b border-slate-100 dark:border-slate-800 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">

          <div>
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-brand-600 dark:text-brand-400" />

              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Available Analyses
              </h2>
            </div>

            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              Select a capture to view its complete security report.
            </p>
          </div>

          {isFetching && (
            <div className="flex items-center gap-1.5 text-xs text-brand-600 dark:text-brand-400 animate-pulse self-start sm:self-auto">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span className="text-[11px] font-medium">Updating...</span>
            </div>
          )}

        </div>

        {/* SEARCH & DATE FILTER BAR */}
        <div className="border-b border-slate-100 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-850/60 px-5 py-3 sm:px-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            
            {/* Search by filename or ID */}
            <div className="relative flex-1 max-w-md">
              <Search className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => handleSearchChange(e.target.value)}
                placeholder="Search by capture name or ID..."
                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 pl-9 pr-8 py-1.5 text-xs text-slate-800 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 shadow-sm"
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={() => handleSearchChange('')}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 p-0.5"
                  title="Clear search"
                >
                  <X className="h-3 w-3" />
                </button>
              )}
            </div>

            {/* Date Picker & Reset */}
            <div className="flex items-center gap-2">
              <div className="relative">
                <Calendar className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                <input
                  type="date"
                  value={searchDate}
                  onChange={(e) => handleDateChange(e.target.value)}
                  className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 pl-9 pr-3 py-1.5 text-xs text-slate-700 dark:text-slate-200 focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 shadow-sm"
                  title="Filter by capture date"
                />
              </div>

              {(searchTerm || searchDate) && (
                <button
                  type="button"
                  onClick={handleClearFilters}
                  className="inline-flex items-center gap-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-2.5 py-1.5 text-xs font-semibold text-slate-600 dark:text-slate-300 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors"
                  title="Reset all filters"
                >
                  <X className="h-3 w-3" />
                  Clear
                </button>
              )}
            </div>

          </div>
        </div>

        {stats.totalAnalyses === 0 && !searchTerm && !searchDate ? (

          <div className="flex flex-col items-center justify-center px-6 py-20 text-center">

            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-brand-100 bg-brand-50">
              <FileSearch className="h-6 w-6 text-brand-600" />
            </div>

            <h3 className="mt-5 text-base font-semibold text-slate-900">
              No analysis records yet
            </h3>

            <p className="mt-2 max-w-sm text-sm leading-6 text-slate-500">
              Upload a PCAP or PCAPNG file from the dashboard
              to begin analyzing your email traffic.
            </p>

            <Link
              to="/"
              className="mt-6 inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-brand-700"
            >
              <Plus className="h-4 w-4" />
              Start New Analysis
            </Link>

          </div>

        ) : pagination.total === 0 ? (

          <div className="flex flex-col items-center justify-center px-6 py-16 text-center">

            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-400">
              <Search className="h-5 w-5" />
            </div>

            <h3 className="mt-4 text-sm font-semibold text-slate-900">
              No matching captures found
            </h3>

            <p className="mt-1 max-w-sm text-xs text-slate-500">
              No analysis records match your search query or selected date.
            </p>

            <button
              type="button"
              onClick={handleClearFilters}
              className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <X className="h-3.5 w-3.5" />
              Clear Filters
            </button>

          </div>

        ) : (

          <div>
            <div className="divide-y divide-slate-100 dark:divide-slate-800">

              {analyses.map((item) => {

                const risk =
                  String(item.risk_label || 'UNKNOWN');

                return (
                  <button
                    key={item.analysis_id}
                    type="button"
                    onClick={() =>
                      navigate(`/analysis/${item.analysis_id}`)
                    }
                    className="group w-full px-5 py-5 text-left transition-all hover:bg-slate-50 dark:hover:bg-slate-800/60"
                  >

                    <div className="flex flex-col gap-5 lg:flex-row lg:items-center">

                      {/* FILE */}
                      <div className="flex min-w-0 flex-1 items-center gap-4">

                        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-brand-100 dark:border-brand-800/60 bg-brand-50 dark:bg-brand-950/60 transition-transform group-hover:scale-[1.03]">
                          <FileSearch className="h-4.5 w-4.5 text-brand-600 dark:text-brand-400" />
                        </div>

                        <div className="min-w-0">

                          <p className="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">
                            {item.filename || 'Untitled Capture'}
                          </p>

                          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500 dark:text-slate-400">

                            <span className="font-mono text-slate-400 dark:text-slate-500">
                              {item.analysis_id}
                            </span>

                            <span className="hidden text-slate-300 dark:text-slate-700 sm:inline">
                              •
                            </span>

                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />

                              {item.created_at
                                ? new Date(
                                  item.created_at
                                ).toLocaleString()
                                : 'Unknown time'}
                            </span>

                          </div>

                        </div>

                      </div>


                      {/* METADATA */}
                      <div className="grid grid-cols-3 gap-5 lg:flex lg:items-center lg:gap-8">

                        {/* RISK */}
                        <div className="min-w-[95px]">

                          <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                            Risk Level
                          </p>

                          <span
                            className={`mt-2 inline-flex rounded-md border px-2 py-1 text-[9px] font-bold uppercase tracking-wide ${getRiskClass(
                              risk
                            )}`}
                          >
                            {risk}
                          </span>

                        </div>


                        {/* SESSIONS */}
                        <div className="min-w-[75px]">

                          <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                            Sessions
                          </p>

                          <p className="mt-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                            {item.session_count || 0}
                          </p>

                        </div>


                        {/* FINDINGS */}
                        <div className="min-w-[75px]">

                          <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                            Findings
                          </p>

                          <p className="mt-2 text-sm font-semibold text-slate-800 dark:text-slate-200">
                            {item.finding_count || 0}
                          </p>

                        </div>


                        {/* OPEN */}
                        <div className="flex items-center justify-end">

                          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-400 dark:text-slate-300 transition-all group-hover:border-brand-100 dark:group-hover:border-brand-800 group-hover:bg-brand-50 dark:group-hover:bg-brand-950/60 group-hover:text-brand-600 dark:group-hover:text-brand-400">
                            <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                          </div>

                        </div>

                      </div>

                    </div>

                  </button>
                );
              })}

            </div>

            {/* PAGINATION FOOTER */}
            {pagination.total > 0 && (
              <div className="flex flex-col gap-3 border-t border-slate-100 dark:border-slate-800 px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between sm:px-6 bg-slate-50/40 dark:bg-slate-850/40">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Showing <span className="font-semibold text-slate-700 dark:text-slate-200">{(currentPage - 1) * ITEMS_PER_PAGE + 1}</span> to{' '}
                  <span className="font-semibold text-slate-700 dark:text-slate-200">{Math.min(currentPage * ITEMS_PER_PAGE, pagination.total)}</span> of{' '}
                  <span className="font-semibold text-slate-700 dark:text-slate-200">{pagination.total}</span> captures
                </p>

                {totalPages > 1 && (
                  <div className="flex items-center gap-1 self-center sm:self-auto">
                    <button
                      type="button"
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      disabled={currentPage === 1 || isFetching}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 shadow-sm transition-colors hover:bg-slate-50 dark:hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
                      aria-label="Previous Page"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </button>

                    {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => {
                      const isCurrent = pageNum === currentPage;
                      return (
                        <button
                          key={pageNum}
                          type="button"
                          onClick={() => setCurrentPage(pageNum)}
                          disabled={isFetching}
                          className={`inline-flex h-8 min-w-[32px] px-2 items-center justify-center rounded-lg text-xs font-semibold shadow-sm transition-colors ${
                            isCurrent
                              ? 'bg-brand-600 text-white border border-brand-600'
                              : 'border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700'
                          }`}
                        >
                          {pageNum}
                        </button>
                      );
                    })}

                    <button
                      type="button"
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                      disabled={currentPage === totalPages || isFetching}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 shadow-sm transition-colors hover:bg-slate-50 dark:hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
                      aria-label="Next Page"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

        )}

      </div>

    </div>
  );
}


function StatCard({ icon, label, value, description, iconBg, iconText, glow, topBar }) {
  return (
    <div className="group relative overflow-hidden rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-5 py-4 transition-all duration-200 hover:-translate-y-0.5 hover:border-slate-300 dark:hover:border-slate-700 hover:shadow-soft-hover dark:shadow-soft-dark">

      {/* coloured top bar */}
      <div className={`absolute inset-x-0 top-0 h-[3px] rounded-t-xl bg-gradient-to-r opacity-60 transition-opacity duration-200 group-hover:opacity-100 ${topBar}`} />

      {/* header row */}
      <div className="flex items-start justify-between">

        {/* icon with glow */}
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${iconBg} ${iconText} ${glow} transition-transform duration-200 group-hover:scale-110`}>
          {icon}
        </div>

      </div>

      {/* value + label inline */}
      <div className="mt-4 flex items-end justify-between">
        <div>
          <p className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">{value}</p>
          <p className="mt-0.5 text-xs font-semibold text-slate-700 dark:text-slate-300">{label}</p>
          <p className="mt-0.5 text-[10px] text-slate-400 dark:text-slate-500">{description}</p>
        </div>
      </div>

    </div>
  );
}