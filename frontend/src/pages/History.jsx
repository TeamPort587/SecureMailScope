import React from 'react';

import { useHistory } from '../hooks/useHistory';
import HistoryTable from '../components/HistoryTable';
import ErrorState from '../components/ErrorState';
import { History as HistoryIcon, RefreshCw, Layers, Lock, LogIn } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function History() {
  const { isAuthenticated, openAuthModal } = useAuth();
  const { items, pagination, loading, error, refresh } = useHistory(1, 20);

  if (!isAuthenticated) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 flex flex-col items-center text-center">
        <div className="w-14 h-14 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 mb-4">
          <Lock className="w-7 h-7" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">Authentication Required</h2>
        <p className="text-sm text-slate-400 max-w-md mb-6">
          You must be signed in with an authorized analyst account to view stored PCAP forensic audit logs.
        </p>
        <button
          onClick={openAuthModal}
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-brand-600 hover:bg-brand-500 text-white text-xs font-semibold rounded-xl shadow-lg shadow-brand-500/25 transition-all"
        >
          <LogIn className="w-4 h-4" />
          <span>Sign In to Access History</span>
        </button>
      </div>
    );
  }

  return (

    <div className="mx-auto max-w-7xl space-y-6 px-4 py-8 sm:px-6 lg:px-8">


      {/* =====================================================
          PAGE HEADER
      ====================================================== */}

      <div className="mb-6">
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

    {/* bottom-right button */}
    <div className="absolute right-7 bottom-10 z-10 sm:right-10 sm:bottom-12">
      <button
        onClick={() => refresh()}
        disabled={loading}
        className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white/80 backdrop-blur-sm px-3.5 py-2 text-xs font-semibold text-slate-700 shadow-sm transition-colors hover:bg-white disabled:cursor-not-allowed disabled:opacity-50"
      >
        <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
        Refresh
      </button>
    </div>

    {/* content */}
    <div className="relative flex items-center justify-between gap-8">

      {/* LEFT — text */}
      <div className="max-w-xl">

        <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-100 bg-brand-50/80 px-3 py-1 backdrop-blur-sm">
          <HistoryIcon className="h-3 w-3 text-brand-500" />
          <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-brand-600">
            Analysis Records
          </span>
        </div>

        <h1 className="text-3xl font-bold leading-tight tracking-tight text-slate-900 sm:text-4xl">
          Analysis{' '}
          <span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent">
            History
          </span>
        </h1>

        <p className="mt-3 max-w-md text-sm leading-6 text-slate-500">
          Review previously analyzed email captures and their
          detected security posture.
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

          {/* clipboard/history icon */}
          <rect x="72" y="48" width="76" height="90" rx="8" fill="#eff6ff" stroke="#bfdbfe" strokeWidth="1.4" />
          <rect x="88" y="42" width="44" height="16" rx="5" fill="#dbeafe" stroke="#93c5fd" strokeWidth="1.2" />

          {/* lines on clipboard */}
          <line x1="88" y1="78" x2="132" y2="78" stroke="#93c5fd" strokeWidth="1.2" strokeLinecap="round" />
          <line x1="88" y1="92" x2="124" y2="92" stroke="#bfdbfe" strokeWidth="1.2" strokeLinecap="round" />
          <line x1="88" y1="106" x2="128" y2="106" stroke="#bfdbfe" strokeWidth="1.2" strokeLinecap="round" />
          <line x1="88" y1="120" x2="116" y2="120" stroke="#bfdbfe" strokeWidth="1.2" strokeLinecap="round" />

          {/* small check dots */}
          <circle cx="82" cy="78" r="3" fill="#3b82f6" opacity="0.5" />
          <circle cx="82" cy="92" r="3" fill="#bfdbfe" opacity="0.6" />
          <circle cx="82" cy="106" r="3" fill="#bfdbfe" opacity="0.6" />
          <circle cx="82" cy="120" r="3" fill="#bfdbfe" opacity="0.6" />

          {/* HISTORY badge */}
          <rect x="136" y="42" width="46" height="18" rx="5" fill="#dbeafe" stroke="#93c5fd" strokeWidth="1" />
          <text x="159" y="55" textAnchor="middle" fontSize="6.5" fontWeight="700" fill="#2563eb" fontFamily="monospace">HISTORY</text>

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


      {/* =====================================================
          ERROR STATE
      ====================================================== */}

      {error && (

        <ErrorState
          title="Could Not Load Analysis History"
          message={error}
          onRetry={() => refresh()}
        />

      )}


      {/* =====================================================
          HISTORY CONTENT
      ====================================================== */}

      <section
        className="
          overflow-hidden
          rounded-2xl
          border border-slate-200
          bg-white
          shadow-sm
        "
      >


        {/* Table Header */}

        <div
          className="
            flex flex-col
            justify-between
            gap-4
            border-b border-slate-100
            px-5 py-4
            sm:flex-row
            sm:items-center
            sm:px-6
          "
        >

          <div className="flex items-center gap-3">

            <div
              className="
                flex h-9 w-9
                items-center justify-center
                rounded-lg
                border border-brand-100
                bg-brand-50
              "
            >

              <ClipboardList className="h-4 w-4 text-brand-600" />

            </div>


            <div>

              <h2
                className="
                  text-sm
                  font-semibold
                  text-slate-900
                "
              >
                Completed Analyses
              </h2>


              <p
                className="
                  mt-0.5
                  text-[11px]
                  text-slate-500
                "
              >
                Previously processed PCAP captures
              </p>

            </div>

          </div>


          {/* Total */}

          {pagination && (

            <div
              className="
                flex items-center
                gap-2
                self-start
                rounded-lg
                border border-slate-100
                bg-slate-50
                px-3 py-2
                sm:self-auto
              "
            >

              <Database className="h-3.5 w-3.5 text-slate-400" />

              <span
                className="
                  text-xs
                  font-medium
                  text-slate-500
                "
              >
                Total
              </span>

              <span
                className="
                  font-mono
                  text-sm
                  font-semibold
                  text-slate-900
                "
              >
                {pagination.total ?? 0}
              </span>

            </div>

          )}

        </div>


        {/* Table */}

        <HistoryTable
          items={items}
          loading={loading}
        />


        {/* =====================================================
            PAGINATION FOOTER
        ====================================================== */}

        {pagination && pagination.total > 0 && (

          <div
            className="
              flex flex-col
              justify-between
              gap-2
              border-t border-slate-100
              bg-slate-50/50
              px-5 py-3
              text-xs
              sm:flex-row
              sm:items-center
              sm:px-6
            "
          >

            <span className="text-slate-500">

              Showing{' '}

              <span className="font-semibold text-slate-700">
                {items.length}
              </span>

              {' '}of{' '}

              <span className="font-semibold text-slate-700">
                {pagination.total}
              </span>

              {' '}stored analyses

            </span>


            <span
              className="
                font-mono
                text-[11px]
                text-slate-400
              "
            >
              Page {pagination.page}
            </span>

          </div>

        )}

      </section>


    </div>

  );

}