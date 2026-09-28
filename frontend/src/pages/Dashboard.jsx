import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';

import UploadForm from '../components/UploadForm';
import UploadProgress from '../components/UploadProgress';
import ErrorState from '../components/ErrorState';

import HeroSection from '../components/landing/HeroSection';
import PipelineSection from '../components/landing/PipelineSection';
import FaqSection from '../components/landing/FaqSection';

import { useAuth } from '../context/AuthContext';

import {
  Sparkles,
  ArrowUpRight,
  ShieldCheck,
  FileSearch,
  Upload,
  Lock,
  LogIn,
  AlertCircle,
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
  const location = useLocation();
  const { user } = useAuth();

  // Clear any previous completed analysis when landing so the upload PCAP form is always presented
  useEffect(() => {
    if (setAnalysis) {
      setAnalysis(null);
    }
  }, [setAnalysis]);

  // Handle smooth scroll when navigating with hash (e.g. /#upload-section)
  useEffect(() => {
    if (location.hash) {
      const id = location.hash.replace('#', '');
      const el = document.getElementById(id);
      if (el) {
        const timer = setTimeout(() => {
          el.scrollIntoView({ behavior: 'smooth' });
        }, 80);
        return () => clearTimeout(timer);
      }
    }
  }, [location.hash]);

  const handleScrollToUpload = () => {
    const el = document.getElementById('upload-section');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleUpload = async (file) => {
    if (!user) {
      navigate('/login', {
        state: { from: { pathname: '/', hash: '#upload-section' } },
      });
      return;
    }

    try {
      const result = await uploadPcap(file);
      if (result?.analysis_id) {
        navigate(`/analysis/${result.analysis_id}`, { state: { analysis: result } });
      }
    } catch (err) {
      // Error handled by analysisHook
    }
  };

  const handleSelectPreset = (demo) => {
    loadPreset(demo.data);
    if (demo.data?.analysis_id) {
      navigate(`/analysis/${demo.data.analysis_id}`, {
        state: { analysis: demo.data },
      });
    }
  };

  return (
    <main className="min-h-screen w-full bg-slate-50 dark:bg-slate-950 transition-colors">
      {/* =====================================================
          1. HERO SECTION
      ====================================================== */}
      <HeroSection user={user} onScrollToUpload={handleScrollToUpload} />

      {/* =====================================================
          2. HOW IT WORKS / PIPELINE SECTION
      ====================================================== */}
      <PipelineSection />

      {/* =====================================================
          3. UPLOAD SECTION (#upload-section)
      ====================================================== */}
      <section id="upload-section" className="py-12 sm:py-16 border-t border-slate-200/80 dark:border-slate-800/80">
        <div className="mx-auto w-full max-w-5xl px-4 sm:px-6 lg:px-8">
          
          <div className="mb-6 flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-brand-200 dark:border-brand-800/60 bg-brand-50/70 dark:bg-brand-950/50 px-3 py-1 text-xs font-semibold text-brand-600 dark:text-brand-400">
                <Upload className="h-3.5 w-3.5" />
                <span>PCAP Ingestion</span>
              </div>
              <h2 className="mt-2 text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
                Upload & Inspect Packet Capture
              </h2>
              <p className="mt-1 text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                Start deep protocol inspection from an SMTP, IMAP, or POP3 network capture file.
              </p>
            </div>

            {!user && (
              <span className="inline-flex items-center gap-1.5 rounded-lg border border-amber-200 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/40 px-2.5 py-1 text-[11px] font-semibold text-amber-800 dark:text-amber-300">
                <Lock className="h-3 w-3" />
                <span>Login required to analyze</span>
              </span>
            )}
          </div>

          {/* UPLOAD CARD */}
          <div className="ui-card overflow-hidden rounded-2xl border border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-md">
            
            <div className="border-b border-slate-100 dark:border-slate-800 px-5 py-4 sm:px-6 bg-slate-50/50 dark:bg-slate-850/50">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-brand-100 dark:border-brand-800/60 bg-brand-50 dark:bg-brand-950/60">
                    <Upload className="h-4 w-4 text-brand-600 dark:text-brand-400" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      Network Packet File (.pcap, .pcapng, .cap)
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400">
                      Standard tcpdump or Wireshark format, maximum 100MB
                    </p>
                  </div>
                </div>

                <span className="hidden sm:inline-flex items-center rounded-md bg-slate-100 dark:bg-slate-800 px-2 py-0.5 font-mono text-[10px] font-bold text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                  Max 100MB
                </span>
              </div>
            </div>

            <div className="p-5 sm:p-7">
              {user ? (
                uploading ? (
                  <UploadProgress />
                ) : (
                  <UploadForm onUpload={handleUpload} loading={uploading} />
                )
              ) : (
                /* Unauthenticated Guest Lock Banner */
                <div className="rounded-xl border border-dashed border-slate-300 dark:border-slate-700 bg-slate-50/60 dark:bg-slate-850/40 p-8 sm:p-10 text-center">
                  <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-brand-200 dark:border-brand-800 bg-brand-50 dark:bg-brand-950/80 text-brand-600 dark:text-brand-400 shadow-sm">
                    <Lock className="h-6 w-6" />
                  </div>

                  <h4 className="mt-4 text-base font-bold text-slate-900 dark:text-white">
                    Sign in to Inspect Packet Captures
                  </h4>

                  <p className="mx-auto mt-1.5 max-w-md text-xs sm:text-sm text-slate-500 dark:text-slate-400 leading-relaxed font-normal">
                    SecureMailScope requires an authenticated analyst session to reconstruct TCP streams,
                    detect credentials, and persist your forensic reports.
                  </p>

                  <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-3">
                    <Link
                      to="/login"
                      state={{ from: { pathname: '/', hash: '#upload-section' } }}
                      className="inline-flex items-center gap-2 rounded-xl bg-brand-600 dark:bg-brand-500 px-5 py-2.5 text-xs font-semibold text-white shadow-sm hover:bg-brand-700 dark:hover:bg-brand-400 transition cursor-pointer"
                    >
                      <LogIn className="h-3.5 w-3.5" />
                      <span>Sign In to Upload</span>
                    </Link>

                    <Link
                      to="/login"
                      state={{ from: { pathname: '/', hash: '#upload-section' } }}
                      className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-4 py-2.5 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition"
                    >
                      <span>Create Account</span>
                    </Link>
                  </div>
                </div>
              )}
            </div>

          </div>

          {/* SAMPLE CAPTURES / DEMO PRESETS */}
          {!uploading && (
            <div className="mt-8">
              <div className="mb-4 flex items-end justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2">
                    <Sparkles className="h-4 w-4 text-brand-600 dark:text-brand-400" />
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      Sample Demonstrations
                    </h3>
                  </div>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                    Pre-captured network traces demonstrating different security postures.
                  </p>
                </div>

                <span className="hidden text-[10px] font-medium uppercase tracking-wider text-slate-400 sm:block">
                  Demo presets
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                {DEMO_PRESETS.map((demo) => {
                  const demoName =
                    demo.name.split(':')[1]?.trim() || demo.name;
                  const badge = (demo.badge || '').toUpperCase();
                  const isCritical = badge.includes('CRITICAL');
                  const isHigh = badge.includes('HIGH');
                  const isLow = badge.includes('LOW');

                  const cardClass = isCritical
                    ? 'sample-card-critical'
                    : isHigh
                    ? 'sample-card-high'
                    : isLow
                    ? 'sample-card-low'
                    : '';

                  const badgeClass = isCritical
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
                      onClick={() => handleSelectPreset(demo)}
                      className={`sample-card ${cardClass} group rounded-xl p-4 text-left transition-all duration-200 cursor-pointer`}
                    >
                      <div className="flex items-start gap-3.5">
                        <div
                          className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border transition-colors ${config.iconBox}`}
                        >
                          <FileSearch className="h-5 w-5 transition-colors" />
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <h4
                                className={`truncate text-xs font-semibold text-slate-800 dark:text-slate-100 transition-colors ${config.hoverTitle}`}
                              >
                                {demoName}
                              </h4>
                              <p className="mt-1.5 line-clamp-2 text-[11px] leading-5 text-slate-500 dark:text-slate-400">
                                {demo.description}
                              </p>
                            </div>

                            <ArrowUpRight
                              className={`h-4 w-4 shrink-0 text-slate-300 dark:text-slate-600 transition-all duration-200 group-hover:-translate-y-0.5 group-hover:translate-x-0.5 ${config.hoverAction}`}
                            />
                          </div>

                          <div className="mt-3.5 flex items-center justify-between border-t border-slate-200/80 dark:border-slate-800/80 pt-3">
                            <span
                              className={`rounded-md px-2 py-0.5 font-mono text-[10px] font-bold leading-none uppercase tracking-wide transition-colors ${badgeClass}`}
                            >
                              {demo.badge}
                            </span>

                            <span
                              className={`text-[10px] font-semibold text-slate-400 dark:text-slate-500 transition-colors ${config.hoverAction}`}
                            >
                              Inspect sample →
                            </span>
                          </div>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* ERROR ALERT */}
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
      </section>

      {/* =====================================================
          4. FAQ SECTION (#faq-section)
      ====================================================== */}
      <FaqSection />

    </main>
  );
}
