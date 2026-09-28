import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import UploadForm from '../components/UploadForm';
import UploadProgress from '../components/UploadProgress';
import ErrorState from '../components/ErrorState';

import {
  Sparkles,
  ArrowUpRight,
  ShieldCheck,
  FileSearch,
  Upload,
} from 'lucide-react';

import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Dashboard({ analysisHook }) {
  const {
    analysis,
    uploading,
    error,
    uploadPcap,
    loadPreset,
    setAnalysis,
    setError,
  } = analysisHook;

  const navigate = useNavigate();

  // When visiting Dashboard (e.g. clicking "New Analysis" or navigating to upload),
  // clear any previous completed analysis so the upload PCAP form is always presented.
  useEffect(() => {
    if (setAnalysis) {
      setAnalysis(null);
    }
  }, [setAnalysis]);

  const handleUpload = async (file) => {
    try {
      const result = await uploadPcap(file);
      if (result?.analysis_id) {
        navigate(`/analysis/${result.analysis_id}`, { state: { analysis: result } });
      }
    } catch (err) {
      // Error handled by analysisHook
    }
  };

  return (
    <main className="min-h-screen w-full bg-slate-50 dark:bg-slate-950 transition-colors">
      <div className="mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">

        {/* =====================================================
            UPLOAD / EMPTY STATE
        ====================================================== */}
            <section className="mb-6">

              <div className="
                relative overflow-hidden
                rounded-2xl border border-slate-100 dark:border-slate-800/80
                bg-gradient-to-br from-white via-slate-50/80 to-brand-50/40
                dark:from-slate-900/90 dark:via-slate-900/80 dark:to-slate-950/90
                px-6 py-2 sm:px-8 sm:py-3
                shadow-sm dark:shadow-soft-dark
                border-l-2 border-t-2 border-brand-200/60 dark:border-l-brand-500/40 dark:border-t-brand-500/40
              ">

                {/* ── orb glows ── */}
                <div className="pointer-events-none absolute inset-0">
                  <div className="absolute -left-16 -top-16 h-72 w-72 rounded-full bg-brand-400/[0.07] blur-[100px]" />
                  <div className="absolute right-0 -top-8 h-72 w-72 rounded-full bg-sky-200/[0.12] blur-[90px]" />
                  <div className="absolute -bottom-12 left-1/3 h-52 w-52 rounded-full bg-brand-300/[0.06] blur-[80px]" />
                  <div className="absolute bottom-0 right-0 h-52 w-52 rounded-full bg-blue-100/[0.18] blur-[70px]" />
                </div>

                {/* ── dot grid ── */}
                <div
                  className="pointer-events-none absolute inset-0 opacity-[0.018]"
                  style={{
                    backgroundImage: 'radial-gradient(circle, #334155 1px, transparent 1px)',
                    backgroundSize: '26px 26px',
                  }}
                />

                {/* ── top hairline ── */}
                <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-brand-400/30 to-transparent" />

                {/* ── content + illustration ── */}
                <div className="relative flex items-center justify-between gap-8">

                  {/* LEFT — text */}
                  <div className="max-w-xl">

                    <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-brand-100 dark:border-brand-800/60 bg-brand-50/80 dark:bg-brand-950/60 px-3 py-1 backdrop-blur-sm">
                      <ShieldCheck className="h-3 w-3 text-brand-500 dark:text-brand-400" />
                      <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-brand-600 dark:text-brand-300">
                        Email Security Analysis
                      </span>
                    </div>

                    <h1 className="text-3xl font-bold leading-tight tracking-tight text-slate-900 dark:text-white sm:text-4xl">
                      Email Protocol{' '}
                      <span className="bg-gradient-to-r from-brand-600 to-brand-400 bg-clip-text text-transparent">
                        Security Inspector
                      </span>
                    </h1>

                    <p className="mt-3 max-w-md text-sm leading-6 text-slate-500 dark:text-slate-400">
                      Upload a PCAP capture to reconstruct email sessions,
                      evaluate TLS protection, detect exposed credentials,
                      and score protocol-level security risk.
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
                      {/* ── outer glow ring ── */}
                      <circle cx="110" cy="90" r="82" stroke="#3b82f6" strokeWidth="0.6" strokeDasharray="4 6" opacity="0.25" />
                      <circle cx="110" cy="90" r="66" stroke="#3b82f6" strokeWidth="0.5" strokeDasharray="2 8" opacity="0.15" />

                      {/* ── envelope body ── */}
                      <rect x="42" y="62" width="96" height="68" rx="7" fill="#eff6ff" stroke="#bfdbfe" strokeWidth="1.2" className="hero-envelope-body" />

                      {/* ── envelope flap ── */}
                      <path d="M42 69l48 36 48-36" stroke="#93c5fd" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" fill="none" />

                      {/* ── lock body ── */}
                      <rect x="62" y="92" width="44" height="32" rx="6" fill="#dbeafe" stroke="#3b82f6" strokeWidth="1.4" className="hero-lock-body" />

                      {/* ── lock shackle ── */}
                      <path d="M71 92v-10a13 13 0 0 1 26 0v10" stroke="#3b82f6" strokeWidth="1.8" strokeLinecap="round" fill="none" />

                      {/* ── lock keyhole ── */}
                      <circle cx="84" cy="106" r="4" fill="#3b82f6" opacity="0.6" />
                      <rect x="82.5" y="109" width="3" height="6" rx="1.5" fill="#3b82f6" opacity="0.6" />

                      {/* ── TLS badge top-right ── */}
                      <rect x="138" y="48" width="36" height="18" rx="5" fill="#dbeafe" stroke="#93c5fd" strokeWidth="1" className="hero-badge-bg" />
                      <text x="156" y="61" textAnchor="middle" fontSize="7.5" fontWeight="700" fill="#2563eb" fontFamily="monospace" className="hero-badge-text">TLS</text>

                      {/* ── scan lines ── */}
                      <line x1="56" y1="115" x2="86" y2="115" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                      <line x1="56" y1="121" x2="78" y2="121" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />
                      <line x1="124" y1="115" x2="138" y2="115" stroke="#bfdbfe" strokeWidth="1" strokeLinecap="round" />

                      {/* ── floating dots ── */}
                      <circle cx="34" cy="54" r="3" fill="#bfdbfe" opacity="0.5" />
                      <circle cx="186" cy="126" r="2.5" fill="#93c5fd" opacity="0.4" />
                      <circle cx="172" cy="58" r="2" fill="#60a5fa" opacity="0.35" />
                      <circle cx="44" cy="138" r="2" fill="#bfdbfe" opacity="0.4" />

                      {/* ── signal arcs top-left ── */}
                      <path d="M26 80 a18 18 0 0 1 0-20" stroke="#93c5fd" strokeWidth="1.2" strokeLinecap="round" fill="none" opacity="0.4" />
                      <path d="M20 84 a26 26 0 0 1 0-28" stroke="#bfdbfe" strokeWidth="0.9" strokeLinecap="round" fill="none" opacity="0.3" />
                    </svg>
                  </div>

                </div>

              </div>

            </section>


            {/* UPLOAD CARD */}

            <section className="ui-card overflow-hidden dark:bg-slate-900 dark:border-slate-800">

              <div className="border-b border-slate-100 dark:border-slate-800 px-5 py-4 sm:px-6">

                <div className="flex items-center gap-3">

                  <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-brand-100 dark:border-brand-800/60 bg-brand-50 dark:bg-brand-950/60">
                    <Upload className="h-4 w-4 text-brand-600 dark:text-brand-400" />
                  </div>

                  <div>

                    <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      Upload packet capture
                    </h2>

                    <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                      Start an inspection from an SMTP, IMAP, or POP3 PCAP.
                    </p>

                  </div>

                </div>

              </div>

              <div className="p-5 sm:p-6">

                {uploading ? (
                  <UploadProgress />
                ) : (
                  <UploadForm
                    onUpload={handleUpload}
                    loading={uploading}
                  />
                )}

              </div>

            </section>


            {/* SAMPLE CAPTURES */}

            {!uploading && (
              <section className="mt-7">

                <div className="mb-4 flex items-end justify-between gap-4">

                  <div>

                    <div className="flex items-center gap-2">

                      <Sparkles className="h-4 w-4 text-brand-600 dark:text-brand-400" />

                      <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                        Sample captures
                      </h2>

                    </div>

                    <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                      Quickly demonstrate different security outcomes.
                    </p>

                  </div>

                  <span className="hidden text-[10px] font-medium uppercase tracking-wider text-slate-400 sm:block">
                    Demo presets
                  </span>

                </div>


                <div className="grid grid-cols-1 gap-3 md:grid-cols-3">

                  {DEMO_PRESETS.map((demo) => {

                    const demoName =
                      demo.name.split(':')[1]?.trim() ||
                      demo.name;

                    const badge =
                      (demo.badge || '').toUpperCase();

                    const isCritical =
                      badge.includes('CRITICAL');

                    const isHigh =
                      badge.includes('HIGH');

                    const isLow =
                      badge.includes('LOW');

                    const cardClass =
                      isCritical
                        ? 'sample-card-critical'
                        : isHigh
                          ? 'sample-card-high'
                          : isLow
                            ? 'sample-card-low'
                            : '';

                    const badgeClass =
                      isCritical
                        ? 'severity-critical'
                        : isHigh
                          ? 'severity-high'
                          : isLow
                            ? 'severity-low'
                            : 'severity-info';

                    const config = isCritical
                      ? {
                          iconBox:
                            'border-rose-200 dark:border-rose-800/60 bg-rose-50 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400 group-hover:bg-rose-100 dark:group-hover:bg-rose-900/60',
                          hoverTitle:
                            'group-hover:text-rose-600 dark:group-hover:text-rose-300',
                          hoverAction:
                            'group-hover:text-rose-600 dark:group-hover:text-rose-400',
                        }
                      : isHigh
                        ? {
                            iconBox:
                              'border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 group-hover:bg-amber-100 dark:group-hover:bg-amber-900/60',
                            hoverTitle:
                              'group-hover:text-amber-600 dark:group-hover:text-amber-300',
                            hoverAction:
                              'group-hover:text-amber-600 dark:group-hover:text-amber-400',
                          }
                        : {
                            iconBox:
                              'border-emerald-200 dark:border-emerald-800/60 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400 group-hover:bg-emerald-100 dark:group-hover:bg-emerald-900/60',
                            hoverTitle:
                              'group-hover:text-emerald-600 dark:group-hover:text-emerald-300',
                            hoverAction:
                              'group-hover:text-emerald-600 dark:group-hover:text-emerald-400',
                          };

                    return (
                      <button
                        key={demo.id}
                        type="button"
                        onClick={() => {
                          loadPreset(demo.data);
                          if (demo.data?.analysis_id) {
                            navigate(`/analysis/${demo.data.analysis_id}`, {
                              state: { analysis: demo.data },
                            });
                          }
                        }}
                        className={`sample-card ${cardClass} group rounded-xl p-4 text-left transition-all duration-200`}
                      >
                        <div className="flex items-start gap-3.5">
                          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border transition-colors ${config.iconBox}`}>
                            <FileSearch className="h-5 w-5 transition-colors" />
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0">
                                <h3 className={`truncate text-xs font-semibold text-slate-800 dark:text-slate-100 transition-colors ${config.hoverTitle}`}>
                                  {demoName}
                                </h3>

                                <p className="mt-1.5 line-clamp-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">
                                  {demo.description}
                                </p>
                              </div>

                              <ArrowUpRight className={`h-4 w-4 shrink-0 text-slate-300 dark:text-slate-600 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 ${config.hoverAction}`} />
                            </div>

                            <div className="mt-3.5 flex items-center justify-between border-t border-slate-200/80 dark:border-slate-800/80 pt-3">
                              <span
                                className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold leading-none uppercase tracking-wide transition-colors ${badgeClass}`}
                              >
                                {demo.badge}
                              </span>

                              <span className={`text-[10px] font-semibold text-slate-400 dark:text-slate-500 transition-colors ${config.hoverAction}`}>
                                Load sample →
                              </span>
                            </div>
                          </div>
                        </div>
                      </button>
                    );
                  })}

                </div>

              </section>
            )}

        {/* =====================================================
            ERROR
        ====================================================== */}

        {error && (
          <div className="mt-6">

            <ErrorState
              title="Analysis Request Failed"
              message={error}
              onRetry={() => setError(null)}
            />

          </div>
        )}

      </div>

    </main>
  );
}
