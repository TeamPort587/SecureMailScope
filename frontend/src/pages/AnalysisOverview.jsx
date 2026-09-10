import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  FileSearch,
  ArrowRight,
  Activity,
  ShieldAlert,
  Database,
  RefreshCw,
  Plus,
  Clock,
  Server,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';

import { analysisApi } from '../api/analysisApi';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export default function AnalysisOverview() {
  const navigate = useNavigate();

  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  const loadAnalyses = async (isRefresh = false) => {
    if (isRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    setError(null);

    try {
      const data = await analysisApi.getAnalyses(1, 50);

      setAnalyses(data?.items || []);
    } catch (err) {
      setError(
        err.message ||
        'Failed to load available analyses.'
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadAnalyses();
  }, []);

  const highRiskCount = analyses.filter((item) => {
    const level = String(item.risk_label || '').toLowerCase();

    return (
      level === 'high' ||
      level === 'critical'
    );
  }).length;

  const totalSessions = analyses.reduce(
    (total, item) =>
      total + (item.session_count || 0),
    0
  );

  const totalFindings = analyses.reduce(
    (total, item) =>
      total + (item.finding_count || 0),
    0
  );

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
    rounded-2xl border border-slate-100
        bg-gradient-to-br from-white via-slate-50/80 to-brand-50/40
    px-6 py-2 sm:px-8 sm:py-3
    shadow-sm
    border-l-2 border-t-2 border-brand-200/60
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


          {/* top-right buttons */}
          <div className="absolute right-7 bottom-10 z-10 flex items-center gap-2 sm:right-10 sm:bottom-12">
            <button
              type="button"
              onClick={() => loadAnalyses(true)}
              disabled={refreshing}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white/80 backdrop-blur-sm px-3.5 py-2 text-xs font-semibold text-slate-700 shadow-sm transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-70"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin' : ''}`} />
              {refreshing ? 'Refreshing...' : 'Refresh'}
            </button>

            <Link
              to="/"
              className="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-xs font-semibold text-white shadow-sm transition-colors hover:bg-brand-700"
            >
              <Plus className="h-3.5 w-3.5" />
              New Analysis
            </Link>
          </div>

          {/* content */}
          <div className="relative flex items-center justify-between gap-8">

            {/* LEFT — text */}
            <div className="max-w-xl">

              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-100 bg-brand-50/80 px-3 py-1 backdrop-blur-sm">
                <FileSearch className="h-3 w-3 text-brand-500" />
                <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-brand-600">
                  Security Workspace
                </span>
              </div>

              <h1 className="text-3xl font-bold leading-tight tracking-tight text-slate-900 sm:text-4xl">
                Analysis{' '}
                <span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent">
                  Center
                </span>
              </h1>

              <p className="mt-3 max-w-md text-sm leading-6 text-slate-500">
                Review completed email security analyses, inspect captured
                sessions, investigate findings, and track the overall
                security posture of your network traffic.
              </p>


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
                  fill="#eff6ff" stroke="#bfdbfe" strokeWidth="1.4" strokeLinejoin="round" />

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
                <rect x="138" y="38" width="46" height="18" rx="5" fill="#dbeafe" stroke="#93c5fd" strokeWidth="1" />
                <text x="161" y="51" textAnchor="middle" fontSize="7" fontWeight="700" fill="#2563eb" fontFamily="monospace">ANALYSIS</text>

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
          value={analyses.length}
          description="Available security reports"
          iconBg="bg-brand-100"
          iconText="text-brand-600"
          glow="shadow-[0_0_18px_4px_rgba(14,165,233,0.13)]"
          topBar="from-brand-300 via-brand-400 to-brand-300"
        />
        <StatCard
          icon={<ShieldAlert className="h-5 w-5" />}
          label="High / Critical Risk"
          value={highRiskCount}
          description="Elevated risk posture"
          iconBg="bg-rose-100"
          iconText="text-rose-600"
          glow="shadow-[0_0_18px_4px_rgba(239,68,68,0.13)]"
          topBar="from-rose-300 via-rose-400 to-rose-300"
          alert={highRiskCount > 0}
        />
        <StatCard
          icon={<Activity className="h-5 w-5" />}
          label="Captured Sessions"
          value={totalSessions}
          description="Across all analyses"
          iconBg="bg-sky-100"
          iconText="text-sky-600"
          glow="shadow-[0_0_18px_4px_rgba(14,165,233,0.13)]"
          topBar="from-sky-300 via-sky-400 to-sky-300"
        />
        <StatCard
          icon={<AlertTriangle className="h-5 w-5" />}
          label="Security Findings"
          value={totalFindings}
          description="Issues requiring review"
          iconBg="bg-amber-100"
          iconText="text-amber-600"
          glow="shadow-[0_0_18px_4px_rgba(245,158,11,0.13)]"
          topBar="from-amber-300 via-amber-400 to-amber-300"
        />
      </div>


      {/* ANALYSIS RECORDS */}
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">

        {/* SECTION HEADER */}
        <div className="flex flex-col gap-4 border-b border-slate-100 px-5 py-5 sm:flex-row sm:items-center sm:justify-between">

          <div>
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-brand-600" />

              <h2 className="text-sm font-semibold text-slate-900">
                Available Analyses
              </h2>
            </div>

            <p className="mt-1 text-xs text-slate-500">
              Select a capture to view its complete security report.
            </p>
          </div>

          <div className="inline-flex items-center gap-2 self-start rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 sm:self-auto">
            <span className="h-1.5 w-1.5 rounded-full bg-brand-500" />

            <span className="text-[11px] font-semibold text-slate-600">
              {analyses.length} Records
            </span>
          </div>

        </div>


        {analyses.length === 0 ? (

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

        ) : (

          <div className="divide-y divide-slate-100">

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
                  className="group w-full px-5 py-5 text-left transition-all hover:bg-slate-50"
                >

                  <div className="flex flex-col gap-5 lg:flex-row lg:items-center">

                    {/* FILE */}
                    <div className="flex min-w-0 flex-1 items-center gap-4">

                      <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-brand-100 bg-brand-50 transition-transform group-hover:scale-[1.03]">
                        <FileSearch className="h-4.5 w-4.5 text-brand-600" />
                      </div>

                      <div className="min-w-0">

                        <p className="truncate text-sm font-semibold text-slate-800">
                          {item.filename || 'Untitled Capture'}
                        </p>

                        <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-slate-500">

                          <span className="font-mono text-slate-400">
                            {item.analysis_id}
                          </span>

                          <span className="hidden text-slate-300 sm:inline">
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

                        <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">
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

                        <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">
                          Sessions
                        </p>

                        <p className="mt-2 text-sm font-semibold text-slate-800">
                          {item.session_count || 0}
                        </p>

                      </div>


                      {/* FINDINGS */}
                      <div className="min-w-[75px]">

                        <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">
                          Findings
                        </p>

                        <p className="mt-2 text-sm font-semibold text-slate-800">
                          {item.finding_count || 0}
                        </p>

                      </div>


                      {/* OPEN */}
                      <div className="flex items-center justify-end">

                        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 bg-white text-slate-400 transition-all group-hover:border-brand-100 group-hover:bg-brand-50 group-hover:text-brand-600">
                          <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                        </div>

                      </div>

                    </div>

                  </div>

                </button>
              );
            })}

          </div>

        )}

      </div>

    </div>
  );
}


function StatCard({ icon, label, value, description, iconBg, iconText, glow, topBar, alert }) {
  return (
    <div className="group relative overflow-hidden rounded-xl border border-slate-200 bg-white px-5 py-4 transition-all duration-200 hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-soft-hover">

      {/* coloured top bar */}
      <div className={`absolute inset-x-0 top-0 h-[3px] rounded-t-xl bg-gradient-to-r opacity-60 transition-opacity duration-200 group-hover:opacity-100 ${topBar}`} />

      {/* header row */}
      <div className="flex items-start justify-between">

        {/* icon with glow */}
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${iconBg} ${iconText} ${glow} transition-transform duration-200 group-hover:scale-110`}>
          {icon}
        </div>

        {alert && (
          <span className="flex items-center gap-1.5 rounded-full border border-rose-100 bg-rose-50 px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider text-rose-600">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-rose-500" />
            Alert
          </span>
        )}

      </div>

            {/* value + label inline */}
      <div className="mt-4 flex items-end justify-between">
        <div>
          <p className="text-2xl font-bold tracking-tight text-slate-900">{value}</p>
          <p className="mt-0.5 text-xs font-semibold text-slate-700">{label}</p>
          <p className="mt-0.5 text-[10px] text-slate-400">{description}</p>
        </div>
      </div>

    </div>
  );
}