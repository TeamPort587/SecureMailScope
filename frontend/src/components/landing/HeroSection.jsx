import React from 'react';
import { ArrowRight, ShieldCheck, Lock, FileUp } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function HeroSection({ user, onScrollToUpload }) {
  const handleScrollToPipeline = (e) => {
    e.preventDefault();
    document.getElementById('pipeline-section')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section className="relative overflow-hidden pt-6 pb-12 sm:pt-10 sm:pb-16 lg:pt-14 lg:pb-20">
      <div className="relative mx-auto max-w-5xl px-4 text-center sm:px-6 lg:px-8">
        {/* Top security tag pill */}
        <div className="inline-flex items-center gap-2 rounded-full border border-brand-200/80 dark:border-brand-800/70 bg-white/90 dark:bg-slate-900/90 px-3.5 py-1.5 shadow-sm backdrop-blur-md transition hover:border-brand-300 dark:hover:border-brand-700">
          <ShieldCheck className="h-4 w-4 text-brand-600 dark:text-brand-400 animate-pulse" />
          <span className="text-xs font-semibold tracking-wide text-slate-800 dark:text-slate-200">
            Email Network Traffic Security Inspector
          </span>
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
          <span className="font-mono text-[10px] font-bold uppercase text-brand-600 dark:text-brand-400">
            RFC 3207 · 8314
          </span>
        </div>

        {/* High-impact Bold Headline */}
        <h1 className="mt-8 text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight leading-[1.08] text-slate-950 dark:text-white uppercase select-none">
          DECODE TRAFFIC,{' '}
          <span className="block mt-1 bg-gradient-to-r from-brand-600 via-sky-500 to-emerald-600 dark:from-brand-400 dark:via-sky-400 dark:to-emerald-400 bg-clip-text text-transparent drop-shadow-sm">
            ISOLATE THREATS
          </span>
        </h1>

        {/* Subtitle */}
        <p className="mx-auto mt-6 max-w-2xl text-base sm:text-lg text-slate-600 dark:text-slate-300 leading-relaxed font-normal">
          Deep packet inspection for email protocols. Detect plaintext credential leakage,
          evaluate TLS handshakes, and isolate anomalous outliers across SMTP, IMAP, and POP3 streams.
        </p>

        {/* Dual Call-to-Action Buttons */}
        <div className="mt-9 flex flex-col sm:flex-row items-center justify-center gap-3.5 sm:gap-4">
          <button
            type="button"
            onClick={onScrollToUpload}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 rounded-xl bg-brand-600 dark:bg-brand-500 hover:bg-brand-700 dark:hover:bg-brand-400 text-white font-semibold px-6 py-3.5 text-sm shadow-md shadow-brand-500/25 dark:shadow-brand-500/15 transition-all duration-200 hover:-translate-y-0.5 active:translate-y-0 cursor-pointer"
          >
            <FileUp className="h-4 w-4" />
            <span>Analyze PCAP</span>
            <ArrowRight className="h-4 w-4" />
          </button>

          {user ? (
            <Link
              to="/analysis"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-850 hover:border-slate-300 dark:hover:border-slate-700 font-semibold px-6 py-3.5 text-sm shadow-sm transition-all duration-200 hover:-translate-y-0.5 active:translate-y-0"
            >
              <span>Analysis Center</span>
              <ArrowRight className="h-4 w-4 text-slate-400 dark:text-slate-500" />
            </Link>
          ) : (
            <Link
              to="/login"
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-slate-900/90 text-slate-700 dark:text-slate-200 hover:text-slate-900 dark:hover:text-white hover:bg-slate-50 dark:hover:bg-slate-850 hover:border-slate-300 dark:hover:border-slate-700 font-semibold px-6 py-3.5 text-sm shadow-sm transition-all duration-200 hover:-translate-y-0.5 active:translate-y-0"
            >
              <Lock className="h-4 w-4 text-slate-400 dark:text-slate-500" />
              <span>Sign In</span>
            </Link>
          )}

          <button
            type="button"
            onClick={handleScrollToPipeline}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 rounded-xl px-4 py-3.5 text-xs font-semibold text-slate-500 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors cursor-pointer"
          >
            <span>How it works</span>
            <span className="text-slate-400 dark:text-slate-600">↓</span>
          </button>
        </div>
      </div>
    </section>
  );
}
