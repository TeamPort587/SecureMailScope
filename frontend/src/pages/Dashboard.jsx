import React, { useState } from 'react';

import UploadForm from '../components/UploadForm';
import UploadProgress from '../components/UploadProgress';
import RiskSummary from '../components/RiskSummary';
import SessionTable from '../components/SessionTable';
import FindingsList from '../components/FindingsList';
import Recommendations from '../components/Recommendations';
import ErrorState from '../components/ErrorState';

import {
  Download,
  Layers,
  Bug,
  Lightbulb,
  Sparkles,
  ArrowUpRight,
  ShieldCheck,
  FileSearch,
  Activity,
  Upload,
  CheckCircle2,
} from 'lucide-react';

import { DEMO_PRESETS } from '../mock/demoCaptures';

export default function Dashboard({ analysisHook }) {
  const {
    analysis,
    uploading,
    error,
    uploadPcap,
    exportJson,
    loadPreset,
    setError,
  } = analysisHook;

  const [activeTab, setActiveTab] = useState('overview');

  const sessionCount =
    analysis?.sessions?.length || 0;

  const findingCount =
    analysis?.findings?.length || 0;

  const recommendationCount =
    analysis?.recommendations?.length || 0;

  return (
    <main className="min-h-screen w-full bg-slate-50 md:ml-[248px] md:w-[calc(100%-248px)]">
      <div className="mx-auto w-full max-w-[1440px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">

        {/* =====================================================
            UPLOAD / EMPTY STATE
        ====================================================== */}

        {!analysis && (
          <>
            <section className="mb-6">

              <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">

                <div className="max-w-3xl">

                  <div className="mb-3 flex items-center gap-2">

                    <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-brand-200 bg-brand-50">
                      <ShieldCheck className="h-3.5 w-3.5 text-brand-600" />
                    </span>

                    <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-brand-700">
                      Security Analysis
                    </span>

                  </div>

                  <h1 className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
                    Email Protocol Security Inspector
                  </h1>

                  <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
                    Analyze PCAP files to reconstruct email sessions,
                    evaluate TLS protection, detect exposed credentials,
                    and identify protocol-level security weaknesses.
                  </p>

                </div>

                <div className="hidden items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 lg:flex">

                  <Activity className="h-3.5 w-3.5 text-emerald-600" />

                  <span className="text-[11px] font-medium text-slate-600">
                    Analysis engine ready
                  </span>

                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />

                </div>

              </div>

            </section>


            {/* UPLOAD CARD */}

            <section className="ui-card overflow-hidden">

              <div className="border-b border-slate-100 px-5 py-4 sm:px-6">

                <div className="flex items-center gap-3">

                  <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-brand-100 bg-brand-50">
                    <Upload className="h-4 w-4 text-brand-600" />
                  </div>

                  <div>

                    <h2 className="text-sm font-semibold text-slate-900">
                      Upload packet capture
                    </h2>

                    <p className="mt-0.5 text-xs text-slate-500">
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
                    onUpload={uploadPcap}
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

                      <Sparkles className="h-4 w-4 text-brand-600" />

                      <h2 className="text-sm font-semibold text-slate-900">
                        Sample captures
                      </h2>

                    </div>

                    <p className="mt-1 text-xs text-slate-500">
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

                    return (
                      <button
                        key={demo.id}
                        type="button"
                        onClick={() =>
                          loadPreset(demo.data)
                        }
                        className={`sample-card ${cardClass} group rounded-xl p-4 text-left`}
                      >

                        <div className="flex items-start gap-3">

                          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-white">
                            <FileSearch className="h-4 w-4 text-slate-400 transition-colors group-hover:text-brand-600" />
                          </div>

                          <div className="min-w-0 flex-1">

                            <div className="flex items-start justify-between gap-3">

                              <div className="min-w-0">

                                <h3 className="truncate text-xs font-semibold text-slate-800 transition-colors group-hover:text-slate-950">
                                  {demoName}
                                </h3>

                                <p className="mt-1.5 line-clamp-2 text-[11px] leading-5 text-slate-500">
                                  {demo.description}
                                </p>

                              </div>

                              <ArrowUpRight className="h-3.5 w-3.5 shrink-0 text-slate-300 transition-all group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-brand-600" />

                            </div>

                            <div className="mt-3 flex items-center justify-between border-t border-slate-200/80 pt-3">

                              <span
                                className={`rounded-md px-2 py-1 text-[10px] font-semibold leading-none ${badgeClass}`}
                              >
                                {demo.badge}
                              </span>

                              <span className="text-[10px] font-medium text-slate-400 group-hover:text-brand-600">
                                Load sample
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

          </>
        )}


        {/* =====================================================
            ERROR
        ====================================================== */}

        {error && (
          <div className={analysis ? 'mb-6' : 'mt-6'}>

            <ErrorState
              title="Analysis Request Failed"
              message={error}
              onRetry={() => setError(null)}
            />

          </div>
        )}


        {/* =====================================================
            ANALYSIS
        ====================================================== */}

        {analysis && (
          <div className="animate-in fade-in duration-300">

            {/* =================================================
                ANALYSIS HEADER + NAVIGATION
            ================================================== */}

            <section className="mb-7 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">

              {/* INSPECTION HEADER */}

              <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">

                <div className="flex min-w-0 items-center gap-3">

                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-brand-200 bg-brand-50">
                    <FileSearch className="h-4 w-4 text-brand-600" />
                  </div>

                  <div className="min-w-0">

                    <div className="flex flex-wrap items-center gap-2">

                      <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-400">
                        Active inspection
                      </span>

                      <span className="h-1 w-1 rounded-full bg-slate-300" />

                      <span className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-600">

                        <CheckCircle2 className="h-3 w-3" />

                        Analysis complete

                      </span>

                    </div>

                    <div className="mt-1.5 flex min-w-0 items-center gap-2">

                      <span className="truncate font-mono text-xs font-semibold text-slate-800 sm:text-sm">
                        {analysis.filename ||
                          'packet_capture.pcap'}
                      </span>

                      {analysis.analysis_id && (
                        <>
                          <span className="text-slate-300">
                            ·
                          </span>

                          <span className="hidden shrink-0 font-mono text-[10px] text-slate-400 sm:inline">
                            {analysis.analysis_id}
                          </span>
                        </>
                      )}

                    </div>

                  </div>

                </div>


                <button
                  type="button"
                  onClick={() =>
                    exportJson(analysis.analysis_id)
                  }
                  className="ui-button ui-button-primary w-full sm:w-auto"
                  title="Download authoritative analysis report JSON"
                >

                  <Download className="h-3.5 w-3.5" />

                  Export report

                </button>

              </div>


              {/* =================================================
                  SECTION NAVIGATION
              ================================================== */}

              <div className="border-t border-slate-100 bg-slate-50/50 px-2 sm:px-3">

                <div className="flex overflow-x-auto">

                  <AnalysisTab
                    active={
                      activeTab === 'overview'
                    }
                    onClick={() =>
                      setActiveTab('overview')
                    }
                    icon={ShieldCheck}
                    label="Overview"
                  />

                  <AnalysisTab
                    active={
                      activeTab === 'sessions'
                    }
                    onClick={() =>
                      setActiveTab('sessions')
                    }
                    icon={Layers}
                    label="Sessions"
                    count={sessionCount}
                  />

                  <AnalysisTab
                    active={
                      activeTab === 'findings'
                    }
                    onClick={() =>
                      setActiveTab('findings')
                    }
                    icon={Bug}
                    label="Findings"
                    count={findingCount}
                    countClass="text-amber-700 bg-amber-50 border-amber-200"
                  />

                  <AnalysisTab
                    active={
                      activeTab === 'recommendations'
                    }
                    onClick={() =>
                      setActiveTab('recommendations')
                    }
                    icon={Lightbulb}
                    label="Recommendations"
                    count={recommendationCount}
                    countClass="text-emerald-700 bg-emerald-50 border-emerald-200"
                  />

                </div>

              </div>

            </section>


            {/* =================================================
                OVERVIEW
            ================================================== */}

            {activeTab === 'overview' && (
              <section>

                <div className="mb-5">

                  <div className="flex items-center gap-2">

                    <ShieldCheck className="h-4 w-4 text-brand-600" />

                    <h2 className="text-sm font-semibold text-slate-900">
                      Security overview
                    </h2>

                  </div>

                  <p className="mt-1 text-xs text-slate-500">
                    Overall risk posture and key observations from this capture.
                  </p>

                </div>


                <RiskSummary
                  risk={analysis.risk}
                  summary={analysis.summary}
                  filename={analysis.filename}
                  uploadedAt={analysis.uploaded_at}
                />

              </section>
            )}


            {/* =================================================
                SESSIONS

                IMPORTANT:
                No duplicate SectionIntro here.
                SessionTable owns its own heading.
            ================================================== */}

            {activeTab === 'sessions' && (
              <section>

                <SessionTable
                  sessions={analysis.sessions}
                  findings={analysis.findings}
                />

              </section>
            )}


            {/* =================================================
                FINDINGS

                FindingsList owns its own heading.
            ================================================== */}

            {activeTab === 'findings' && (
              <section>

                <FindingsList
                  findings={analysis.findings}
                />

              </section>
            )}


            {/* =================================================
                RECOMMENDATIONS

                Recommendations owns its own heading.
            ================================================== */}

            {activeTab === 'recommendations' && (
              <section>

                <Recommendations
                  recommendations={
                    analysis.recommendations
                  }
                />

              </section>
            )}

          </div>
        )}

      </div>

    </main>
  );
}


/* ===============================================================
   ANALYSIS TAB
=============================================================== */

function AnalysisTab({
  active,
  onClick,
  icon: Icon,
  label,
  count,
  countClass = 'text-slate-600 bg-white border-slate-200',
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`relative flex shrink-0 items-center gap-2.5 px-5 py-3.5 text-xs font-semibold transition-all duration-200 ${
        active
          ? 'text-slate-900'
          : 'text-slate-500 hover:text-slate-800'
      }`}
    >

      {/* Active indicator */}

      {active && (
        <span className="absolute inset-x-3 bottom-0 h-0.5 rounded-full bg-brand-500" />
      )}

      <Icon
        className={`h-4 w-4 ${
          active
            ? 'text-brand-600'
            : 'text-slate-400'
        }`}
      />

      <span>
        {label}
      </span>

      {typeof count === 'number' && (
        <span
          className={`min-w-[22px] rounded-md border px-1.5 py-0.5 text-center text-[10px] font-semibold leading-none ${countClass}`}
        >
          {count}
        </span>
      )}

    </button>
  );
}